"""Exercise a disposable PostgreSQL service, a restricted runtime and pg_restore."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit, urlunsplit


def main():
    executable = str(Path(sys.argv[1]).resolve())
    root = Path(__file__).resolve().parents[1]
    container = os.environ["CHEZHI_TEST_POSTGRES_CONTAINER"]
    base = urlsplit(os.environ["CHEZHI_TEST_DATABASE_URL"])
    admin = base.username
    original = base.path.lstrip("/")
    runtime_password = "ephemeral_runtime_test"
    runtime_role = "chezhi_runtime"

    def pg(command, *args, stdin=None, output=False):
        result = subprocess.run(
            ["docker", "exec", "-i", container, command, "-U", admin, *args],
            input=stdin, text=True, check=True, timeout=60,
            stdout=subprocess.PIPE if output else None,
        )
        return result.stdout

    def sql(database, statement=None, stdin=None, output=False):
        options = ["-d", database, "-v", "ON_ERROR_STOP=1", "-qAt"]
        if statement is not None:
            options += ["-c", statement]
        return pg("psql", *options, stdin=stdin, output=output)

    def environment(database, role=None):
        netloc = base.netloc
        if role:
            host = netloc.rsplit("@", 1)[-1]
            netloc = f"{role}:{runtime_password}@{host}"
        dsn = urlunsplit(base._replace(netloc=netloc, path="/" + database))
        return dict(os.environ, CHEZHI_STORAGE="postgres", CHEZHI_DATABASE_URL=dsn)

    def cli(database, *args, ok=True, env=None):
        result = subprocess.run(
            [executable, *args], env=env or environment(database),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30,
        )
        if (result.returncode == 0) != ok:
            raise RuntimeError(f"Unexpected exit {result.returncode} from {args[0]}")
        return result.stdout

    sql(original, f"CREATE ROLE {runtime_role} LOGIN PASSWORD '{runtime_password}'")
    created = []
    try:
        for database in ("chezhi_accept_import", "chezhi_accept_http", "chezhi_accept_restore"):
            pg("createdb", database)
            created.append(database)
        source, live, restored = created
        cli(source, "db-check", ok=False)
        cli(source, "db-init")
        cli(source, "db-init")
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            payload = json.dumps({"QQ": "123456789", "Cards": [], "Audit": []}).encode()
            state.write_bytes(payload)
            cli(source, "db-import", "--dry-run", directory)
            assert sql(source, "SELECT count(*) FROM chezhi_import", output=True).strip() == "0"
            cli(source, "db-import", "--apply", directory)
            cli(source, "db-import", "--apply", directory, ok=False)
            assert state.read_bytes() == payload
            assert sql(source, "SELECT qq FROM chezhi_config", output=True).strip() == "123456789"
        print("PASS CLI init, dry run, import, reconciliation and duplicate protection", flush=True)

        cli(live, "db-init")
        sql(live, stdin=(root / "migration/postgres_runtime_grants.sql").read_text(encoding="utf-8"))
        runtime = environment(live, runtime_role)
        assert "completed" in cli(live, "db-check", env=runtime)
        assert sql(live, f"SELECT has_table_privilege('{runtime_role}', 'chezhi_audit','DELETE')",
                   output=True).strip() == "f"
        subprocess.run(
            [sys.executable, str(root / "http_smoke.py"), executable],
            check=True, timeout=120, env=runtime,
        )
        print("PASS restricted runtime live HTTP end to end", flush=True)

        pg("pg_dump", "-d", live, "-Fc", "-f", "/tmp/chezhi-accept.dump", "--no-owner", "--no-acl")
        pg("pg_restore", "-d", restored, "--exit-on-error", "--single-transaction",
           "--no-owner", "--no-acl", "/tmp/chezhi-accept.dump")
        cli(restored, "db-check")
        tables = ("schema", "config", "orders", "cards", "audit", "plans", "members", "owner", "import")
        for table in tables:
            statement = f"SELECT to_jsonb(t)::text FROM chezhi_{table} AS t ORDER BY to_jsonb(t)::text"
            assert sql(live, statement, output=True) == sql(restored, statement, output=True), table
        assert sql(restored, "SELECT count(*) FROM chezhi_cards", output=True).strip() == "26"
        print("PASS pg_dump/pg_restore and row-by-row reconciliation across nine tables", flush=True)
    finally:
        subprocess.run(["docker", "exec", container, "rm", "-f", "/tmp/chezhi-accept.dump"], check=True)
        for database in reversed(created):
            pg("dropdb", "--force", database)
        sql(original, f"DROP ROLE {runtime_role}")


if __name__ == "__main__":
    main()
