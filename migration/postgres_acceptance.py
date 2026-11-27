"""Exercise a disposable PostgreSQL service, a restricted runtime and pg_restore."""
from contextlib import contextmanager
import html
import http.cookiejar
import json
import os
import re
import secrets
from pathlib import Path
import subprocess
import sys
import tempfile
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import Request, HTTPCookieProcessor, build_opener, urlopen

HTTP_SMOKES = (
    "http_smoke.py", "client_http_smoke.py", "session_http_smoke.py",
    "members_http_smoke.py", "owner_http_smoke.py",
)


@contextmanager
def service(executable, env):
    with subprocess.Popen([executable], stdout=subprocess.PIPE, text=True, env=env) as process:
        try:
            boot = [process.stdout.readline() for _ in range(5)]
            yield boot[1].split("URL: ", 1)[1].strip(), boot[3].split("Password: ", 1)[1].strip()
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                    raise


class Admin:
    def __init__(self, url):
        self.url = url
        self.opener = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(self, path="", fields=None):
        headers = {"Accept": "text/html"}
        if fields is not None:
            headers["Origin"] = self.url.rstrip("/")
        req = Request(self.url + path, headers=headers,
                      data=None if fields is None else urlencode(fields).encode())
        try:
            with self.opener.open(req, timeout=10) as response:
                return response.status, response.geturl(), response.read().decode()
        except HTTPError as err:
            return err.code, err.geturl(), err.read().decode()

    def token(self, path, name="csrf"):
        status, _, body = self.request(path)
        assert status == 200
        return re.search(rf'name="{name}" value="([^"]+)"', body)[1]

    def login(self, name, password):
        values = dict(username=name, password=password, login_csrf=self.token("login", "login_csrf"))
        status, url, _ = self.request("login", values)
        assert status == 200 and url == self.url

    def issue(self, ref):
        fields = dict(csrf=self.token("?view=issue"), action="issue", preset="30",
                      quantity=1, amount_yuan="9.90", channel="test", sale_ref=ref, confirmed="yes")
        status, _, body = self.request("?view=issue", fields)
        assert status == 200
        match = re.search(r'<textarea readonly aria-label="生成卡密">(.*?)</textarea>', body, re.S)
        assert match is not None, "issuance failed"
        return html.unescape(match[1]).strip()

    def member(self, action, role="operator"):
        return self.request("members", dict(csrf=self.token("?view=members"), action=action,
                                            name="recovery_user", role=role))


def activate(url, key, device):
    request = Request(url + "api/demo/activate", headers={"Content-Type": "application/json"},
                      data=json.dumps(dict(key=key, device=device)).encode())
    with urlopen(request, timeout=10) as response:
        return json.load(response)


def build_recovery_baseline(executable, env):
    permanent = "recovery-" + secrets.token_hex(16)
    with service(executable, env) as (url, bootstrap):
        owner = Admin(url)
        owner.login("admin", bootstrap)
        activated = owner.issue("restore-bound")
        revoked = owner.issue("restore-revoked")
        owner.issue("restore-unused")
        assert activate(url, activated, "recovery-device")["valid"]
        assert activate(url, revoked, "revoked-device")["valid"]
        _, _, body = owner.request("?view=cards&q=restore-revoked")
        card_id = re.search(r'name="id" value="([0-9a-f]{24})"', body)[1]
        status, _, body = owner.request("?view=cards", dict(csrf=owner.token("?view=plans"),
                                         action="revoke", id=card_id))
        assert status == 200 and "操作完成" in body
        plans = dict(csrf=owner.token("?view=plans"), action="plans")
        for days in (0, 1, 7, 30, 90, 365):
            plans[f"price_{days}"] = "9.90"
            plans[f"visible_{days}"] = "yes"
        assert "套餐设置已保存" in owner.request("?view=plans", plans)[2]
        assert owner.member("member-create")[0] == 200
        assert owner.member("member-disable")[0] == 200
        assert owner.member("member-enable")[0] == 200
        status, _, body = owner.member("member-reset")
        assert status == 200
        member_secret = re.search(r'rows="2">([0-9a-f]{64})</textarea>', body)[1]
        Admin(url).login("recovery_user", member_secret)
        status, location, _ = owner.request("account/password", dict(
            csrf=owner.token("?view=account"), current_password=bootstrap,
            new_password=permanent, confirm_password=permanent))
        assert status == 200 and location.endswith("/login")
    return permanent, member_secret, activated, revoked


def verify_recovered_service(executable, env, baseline):
    permanent, member_secret, activated, revoked = baseline
    with service(executable, env) as (url, display):
        assert display.startswith("(configured")
        Admin(url).login("admin", permanent)
        member = Admin(url)
        member.login("recovery_user", member_secret)
        assert activate(url, activated, "recovery-device")["valid"]
        assert activate(url, activated, "wrong-device")["reason"] == "device_mismatch"
        assert activate(url, revoked, "revoked-device")["reason"] == "revoked"
        new_key = member.issue("restore-new-write")
        assert activate(url, new_key, "new-device")["valid"]



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
            raise RuntimeError(f"Unexpected exit {result.returncode} from {args[0]}: {result.stderr.strip()}")
        return result.stdout

    sql(original, f"CREATE ROLE {runtime_role} LOGIN PASSWORD '{runtime_password}'")
    created = []
    dump_path = "/tmp/chezhi-accept-" + secrets.token_hex(8) + ".dump"
    try:
        database_names = ("chezhi_accept_import", "chezhi_accept_restore", "chezhi_accept_incomplete") + tuple(
            f"chezhi_accept_http_{i}" for i in range(len(HTTP_SMOKES)))
        for database in database_names:
            pg("createdb", database)
            created.append(database)
        source, restored, incomplete, *smoke_databases = created
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
            assert state.read_bytes() == payload and not (state.parent / "instance.lock").exists()
            assert sql(source, "SELECT qq FROM chezhi_config", output=True).strip() == "123456789"
        print("PASS CLI init, dry run, import, reconciliation and duplicate protection", flush=True)

        grants = (root / "migration/postgres_runtime_grants.sql").read_text(encoding="utf-8")
        for database, script in zip(smoke_databases, HTTP_SMOKES, strict=True):
            cli(database, "db-init")
            sql(database, stdin=grants)
            runtime = environment(database, runtime_role)
            cli(database, "db-check", "--runtime", env=runtime)
            subprocess.run([sys.executable, str(root / script), executable], check=True, timeout=120, env=runtime)
            print(f"PASS restricted PostgreSQL runtime {script}", flush=True)

        sql(source, stdin=grants)
        runtime = environment(source, runtime_role)
        cli(source, "db-check", "--migrator")
        cli(source, "db-check", "--runtime", ok=False)
        cli(source, "db-check", "--migrator", ok=False, env=runtime)
        cli(source, "db-init", ok=False, env=runtime)
        sql(source, f"GRANT DELETE ON chezhi_audit TO {runtime_role}")
        cli(source, "db-check", "--runtime", ok=False, env=runtime)
        sql(source, f"REVOKE DELETE ON chezhi_audit FROM {runtime_role}")
        sql(source, f"REVOKE UPDATE (activated) ON chezhi_cards FROM {runtime_role}")
        cli(source, "db-check", "--runtime", ok=False, env=runtime)
        sql(source, stdin=grants)
        cli(source, "db-check", "--runtime", env=runtime)
        print("PASS runtime and migrator permission boundaries, excessive and missing grants", flush=True)

        baseline = build_recovery_baseline(executable, runtime)
        cli(source, "db-check", "--migrator")
        counts = sql(source, """SELECT
            (SELECT count(*) FROM chezhi_orders)=3,
            (SELECT count(*) FROM chezhi_cards WHERE device <> '' AND NOT revoked)=1,
            (SELECT count(*) FROM chezhi_cards WHERE revoked)=1,
            (SELECT count(*) FROM chezhi_cards WHERE activated IS NULL)=1,
            (SELECT count(*) FROM chezhi_plans WHERE cents=990)=6,
            (SELECT count(*) FROM chezhi_members)=1,
            (SELECT count(*) FROM chezhi_owner)=1,
            (SELECT count(*) FROM chezhi_audit)>0,
            (SELECT count(*) FROM chezhi_import)=1""", output=True)
        assert counts.strip() == "|".join(["t"] * 9)
        pg("pg_dump", "-d", source, "-Fc", "-f", dump_path, "--no-owner", "--no-acl")
        pg("pg_restore", "-d", restored, "--exit-on-error", "--single-transaction",
           "--no-owner", "--no-acl", dump_path)
        cli(restored, "db-check", "--migrator")
        pg("pg_restore", "-d", incomplete, "--exit-on-error", "--schema-only", "--no-owner", "--no-acl", dump_path)
        cli(incomplete, "db-check", "--migrator", ok=False)
        print("PASS schema-only native restore rejected by db-check", flush=True)
        tables = ("schema", "config", "orders", "cards", "audit", "plans", "members", "owner", "import")
        for table in tables:
            statement = f"SELECT to_jsonb(t)::text FROM chezhi_{table} AS t ORDER BY to_jsonb(t)::text"
            assert sql(source, statement, output=True) == sql(restored, statement, output=True), table
        print("PASS pg_dump/pg_restore and row-by-row reconciliation across nine populated tables", flush=True)
        sql(restored, stdin=grants)
        restored_env = environment(restored, runtime_role)
        cli(restored, "db-check", "--runtime", ok=False, env=restored_env)
        cli(restored, "db-recover-security", restored)
        cli(restored, "db-check", "--runtime", env=restored_env)
        verify_recovered_service(executable, restored_env, baseline)
        cli(restored, "db-check", "--migrator")
        assert sql(restored, "SELECT count(*) FROM chezhi_orders WHERE ref='restore-new-write'", output=True).strip() == "1"
        print("PASS independent restored service supports inherited login, activation, and new writes", flush=True)
    finally:
        subprocess.run(["docker", "exec", container, "rm", "-f", dump_path], check=True)
        for database in reversed(created):
            pg("dropdb", "--force", database)
        sql(original, f"DROP ROLE {runtime_role}")


if __name__ == "__main__":
    main()
