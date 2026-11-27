"""Standalone integration against disposable PostgreSQL and two real processes."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from hashlib import sha256
from http.client import HTTPConnection, HTTPSConnection
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import html
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
from threading import Thread
import time
from urllib.parse import urlencode, urlsplit, urlunsplit


def run(args, **kwargs):
    return subprocess.run(args, text=True, check=True, timeout=kwargs.pop("timeout", 60), **kwargs)


def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def eventually(check, timeout=12):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except (OSError, TimeoutError):
            pass
        time.sleep(0.12)
    raise AssertionError("timed out waiting for server state")


class Client:
    def __init__(self, service_port, host_header, tls=None, source=None):
        self.port = service_port
        self.host = host_header
        self.tls = tls
        self.source = source

    def request(self, path, method="GET", data=None, headers=None):
        h = {"Host": self.host, "Accept": "text/html", **(headers or {})}
        options = {"timeout": 12}
        if self.source:
            options["source_address"] = (self.source, 0)
        if self.tls:
            conn = HTTPSConnection("127.0.0.1", self.port, context=self.tls, **options)
        else:
            conn = HTTPConnection("127.0.0.1", self.port, **options)
        try:
            conn.request(method, path, body=data, headers=h)
            response = conn.getresponse()
            return response.status, {k.lower(): v for k, v in response.getheaders()}, response.read().decode("utf-8")
        finally:
            conn.close()

    def form(self, path, fields, cookie=None, origin=None):
        h = {"Content-Type": "application/x-www-form-urlencoded"}
        if cookie:
            h["Cookie"] = cookie
        if origin is not False:
            h["Origin"] = origin or ("https://" if self.tls else "http://") + self.host
        return self.request(path, "POST", urlencode(fields), h)

    def page(self, path, cookie):
        return self.request(path, headers={"Cookie": cookie} if cookie else {})

    def csrf(self, path, cookie=None, field="csrf"):
        status, _, body = self.page(path, cookie)
        assert status == 200, (path, status)
        return re.search(rf'name="{field}" value="([^"]+)"', body)[1]

    def login(self, username, password, peer=None, status=303):
        csrf = (peer or self).csrf("/login", field="login_csrf")
        result, headers, _ = self.form("/login", dict(username=username, password=password, login_csrf=csrf))
        assert result == status, ("login", result, status)
        if result == 303:
            value = SimpleCookie(headers["set-cookie"])
            assert len(value) == 1
            name, cookie = next(iter(value.items()))
            assert cookie["httponly"] and cookie["path"] == "/" and cookie["samesite"] == "Strict"
            if self.tls:
                assert cookie["secure"] and name.startswith("__Host-") and not cookie["domain"]
            return f"{name}={cookie.value}"
        return ""

    def issue(self, cookie, ref):
        values = dict(csrf=self.csrf("/?view=issue", cookie), action="issue", preset="30", quantity=1,
                      amount_yuan="5.00", confirmed="yes", channel="test", sale_ref=ref)
        status, _, body = self.form("/?view=issue", values, cookie)
        assert status == 200, ("issue", status)
        key = re.search(r'<textarea readonly aria-label="生成卡密">(.*?)</textarea>', body, re.S)
        if key:
            return html.unescape(key[1]).strip()
        assert "该订单已生成卡密" in body
        return ""

    def license(self, action, key, device, status=200, extra=None):
        headers = {"Content-Type": "application/json", **(extra or {})}
        code, response, body = self.request("/api/v1/licenses/" + action, "POST",
                                            json.dumps(dict(key=key, device=device)), headers)
        assert code == status, (action, code, status)
        envelope = json.loads(body)
        assert envelope["version"] == "v1" and envelope["request_id"] == response["x-request-id"]
        return envelope


@contextmanager
def instance(binary, env, diagnostic):
    with tempfile.TemporaryFile(mode="w+b") as logs:
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        p = subprocess.Popen([binary], env=env, stdout=logs, stderr=logs, creationflags=flags)
        try:
            def ready():
                if p.poll() is not None:
                    logs.seek(0)
                    raise RuntimeError(f"instance exited: {logs.read().decode(errors='replace')}")
                return diagnostic.request("/readyz")[0] == 200
            eventually(ready)
            yield
        finally:
            if p.poll() is None:
                p.send_signal(signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGTERM)
                try:
                    p.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=5)
                    raise
                assert p.returncode == 0
                logs.seek(0)
                assert b'"msg":"server_stopped"' in logs.read()


@contextmanager
def https_proxy(tls, backend, host, front_port):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            conn = HTTPConnection("127.0.0.1", backend, timeout=5)
            try:
                conn.request("GET", self.path, headers={"Host": host, "X-Forwarded-Proto": "https",
                                                        "X-Forwarded-For": self.client_address[0]})
                response = conn.getresponse()
                self.send_response(response.status)
                body = response.read()
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            finally:
                conn.close()

        def log_message(self, *args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", front_port), Handler) as proxy:
        proxy.socket = tls.wrap_socket(proxy.socket, server_side=True)
        thread = Thread(target=proxy.serve_forever, daemon=True)
        thread.start()
        try:
            yield
        finally:
            proxy.shutdown()
            thread.join(timeout=4)


def test_cluster(a, b, da, sql, password, restart):
    assert a.request("/healthz")[0] == 200
    assert a.request("/readyz", headers={"Host": "evil.invalid"})[0] == 400
    assert a.request("/metrics")[0] in (401, 404)
    fake = a.request("/?view=issue", headers={"Authorization": "Basic YWRtaW46dGVzdA=="})
    assert fake[0] == 303 and fake[1]["location"] == "/login"
    assert a.request("/api/v1/admin/issue", "POST", "{}")[0] == 404
    assert a.request("/api/demo/activate", "POST", "{}")[0] == 404
    assert a.request("/api/v1/licenses/activate")[0] == 405
    assert a.license("activate", "synthetic", "device", 403, {"Origin": "https://evil.invalid"})["error"]["code"] == "browser_origin_forbidden"
    status, _, _ = a.request("/api/v1/licenses/activate", "POST", '{"key":"x","key":"y","device":"z"}',
                             {"Content-Type": "application/json"})
    assert status == 400
    status, _, _ = b.request("/api/v1/licenses/activate", "POST", "x" * 5000,
                             {"Content-Type": "application/json"})
    assert status == 413
    for origin in (False, "https://evil.invalid"):
        status, _, _ = a.form("/login", dict(username="admin", password=password,
                                             login_csrf=a.csrf("/login", field="login_csrf")), origin=origin)
        assert status == 403
    print("PASS HTTPS, Host and Origin policy, Basic Auth disabled, API isolation, malformed and oversized input", flush=True)

    ca = a.login("admin", password, peer=b)
    cb = b.login("admin", password, peer=a)
    token = ca.split("=", 1)[1]
    hashed = sha256(token.encode()).hexdigest()
    assert sql(f"SELECT count(*) FROM chezhi_sessions WHERE token_digest='{hashed}'") == "1"
    assert sql(f"SELECT count(*) FROM chezhi_sessions WHERE token_digest='{token}'") == "0"
    assert b.page("/?view=overview", ca)[0] == 200
    restart()
    assert b.page("/?view=overview", ca)[0] == 200
    with ThreadPoolExecutor(2) as pool:
        results = [pool.submit(a.issue, ca, "shared-order"), pool.submit(b.issue, cb, "shared-order")]
        keys = [f.result() for f in results if f.result()]
    assert len(keys) == 1 and sql("SELECT count(*) FROM chezhi_orders WHERE ref='shared-order'") == "1"
    key = keys[0]
    assert a.license("validate", key, "first")["data"]["status"] == "activation_required"
    with ThreadPoolExecutor(2) as pool:
        one = pool.submit(a.license, "activate", key, "first")
        two = pool.submit(b.license, "activate", key, "second")
        outcomes = [one.result()["data"], two.result()["data"]]
    assert sorted(x["status"] for x in outcomes) == ["device_mismatch", "valid"]
    device = "first" if outcomes[0]["valid"] else "second"
    assert a.license("validate", key, device)["data"]["valid"]
    assert sql("SELECT count(*) FROM chezhi_audit WHERE action='bind'") == "1"
    for section in ("cards", "orders", "devices", "audit", "overview", "plans"):
        assert b.page("/?view=" + section, ca)[0] == 200
    assert b.form("/logout", {"logout_csrf": a.csrf("/?view=account", ca, "logout_csrf")}, ca)[0] == 303
    assert a.page("/", ca)[0] == b.page("/", ca)[0] == 303
    assert a.page("/", cb)[0] == 200
    print("PASS two server processes, hashed persistent cookies, restart, concurrent issuance and binding, cross-instance logout", flush=True)

    member_form = dict(csrf=a.csrf("/?view=members", cb), action="member-create", name="server_test", role="operator")
    status, _, body = a.form("/members", member_form, cb)
    assert status == 200
    member_secret = re.search(r'rows="2">([0-9a-f]{64})</textarea>', body)[1]
    mc = a.login("server_test", member_secret)
    assert b.page("/?view=issue", mc)[0] == 200
    assert a.form("/members", {**member_form, "action": "member-role", "role": "viewer"}, cb)[0] == 200
    assert b.page("/", mc)[0] == 303
    mc = b.login("server_test", member_secret)
    assert a.page("/?view=issue", mc)[0] == 403
    mt = a.csrf("/?view=account", mc, "logout_csrf")
    for path in ("/backup", "/export", "/members", "/account/password"):
        assert b.form(path, {"csrf": mt}, mc)[0] == 403
    assert a.form("/members", {**member_form, "action": "member-reset"}, cb)[0] == 200
    assert b.page("/", mc)[0] == 303
    ca = b.login("admin", password)
    assert a.form("/logout-all", {"logout_csrf": b.csrf("/?view=account", cb, "logout_csrf")}, cb)[0] == 303
    assert a.page("/", ca)[0] == b.page("/", cb)[0] == 303
    ca, cb = a.login("admin", password), b.login("admin", password)
    replacement = "rotated-" + secrets.token_hex(16)
    fields = dict(csrf=b.csrf("/?view=account", ca), current_password=password,
                  new_password=replacement, confirm_password=replacement)
    assert b.form("/account/password", fields, ca)[0] == 303
    assert a.page("/", ca)[0] == b.page("/", cb)[0] == 303
    password = replacement
    ca = a.login("admin", password)
    old = b.login("admin", password)
    expired_hash = sha256(old.split("=", 1)[1].encode()).hexdigest()
    sql(f"UPDATE chezhi_sessions SET expires=clock_timestamp()-interval '1 second' WHERE token_digest='{expired_hash}'")
    assert a.page("/", old)[0] == 303
    print("PASS global logout, shared invalidation on role and credential changes, privilege denial and expiry", flush=True)

    # Avoid exercising across a fixed window boundary, where the limit resets.
    if int(sql("SELECT extract(second FROM clock_timestamp())::int")) >= 53:
        eventually(lambda: int(sql("SELECT extract(second FROM clock_timestamp())::int")) < 12, timeout=10)
    sql("DELETE FROM chezhi_rate_limits")
    for i in range(8):
        (a if i % 2 else b).license("validate", key, device)
    assert a.license("validate", key, device, 429, {"X-Forwarded-For": "198.51.100.2"})["error"]["code"] == "rate_limited"
    alternate=Client(b.port,b.host,b.tls,source="127.0.0.2")
    for _ in range(4):
        alternate.license("validate", key, device)
    assert alternate.license("validate", key, device, 429)["error"]["code"] == "rate_limited"
    for i in range(15):
        (a if i % 2 else b).login("does_not_exist", "synthetic", status=401)
    b.login("does_not_exist", "synthetic", status=429)
    assert int(sql("SELECT count(*) FROM chezhi_rate_limits WHERE scope='license' AND source<>'*'")) == 2
    print("PASS shared per-source and global license limits, shared login limits, forged direct source ignored", flush=True)

    assert da.request("/metrics")[0] == 200 and "chezhi_db_connections_open" in da.request("/metrics")[2]
    assert a.page("/", ca)[0] == 200
    return ca, key, device


def measure_dashboard_http(a,b,cookie,sql):
    paths = dict(overview="/?view=overview", cards="/?view=cards&page=5", orders="/?view=orders&op=5",
                 devices="/?view=devices&op=5", audit="/?view=audit&ap=5")
    previous = 0
    for amount in (10_000,100_000):
        sql(f"""BEGIN;
            INSERT INTO chezhi_orders(ref,channel,cents,days,created)
            SELECT 'http-scale-'||i,CASE WHEN i%3=0 THEN 'test' ELSE 'wechat' END,110,30,
                   62135596800+floor(extract(epoch FROM transaction_timestamp()))
            FROM generate_series({previous//10+1},{amount//10}) i;
            INSERT INTO chezhi_cards(id,hash,prefix,ref,created,days,activated,expires,device,revoked)
            SELECT left(f.hash,24),f.hash,'ABCDE',o.ref,o.created,30,
                CASE WHEN i%3=0 THEN o.created END,CASE WHEN i%3=0 THEN o.created+2592000 END,
                CASE WHEN i%3=0 THEN repeat('a',64) ELSE '' END,i%11=0
            FROM generate_series({previous+1},{amount}) i
            CROSS JOIN LATERAL (SELECT md5('http:'||i)||md5('http-extra:'||i) AS hash) f
            JOIN chezhi_orders o ON o.ref='http-scale-'||((i-1)/10+1);
            INSERT INTO chezhi_audit(occurred,action,card_id,actor,target)
            SELECT c.created,'issue',c.id,'admin','' FROM chezhi_cards c
            JOIN chezhi_orders o USING(ref)
            WHERE o.ref IN (SELECT 'http-scale-'||i FROM generate_series({previous//10+1},{amount//10}) i);
            COMMIT; ANALYZE;""")
        assert int(sql("SELECT count(*) FROM chezhi_cards")) == amount+1
        previous=amount

        def reader(i):
            client = a if i<8 else b
            elapsed={}
            # Stagger page types across workers while keeping 8 workers per instance.
            items=list(paths.items())
            for name,path in items[i%5:]+items[:i%5]:
                start = time.perf_counter()
                status,_,body=client.page(path,cookie)
                elapsed[name]=(time.perf_counter()-start)*1000
                assert status==200 and "业务数据暂不可用" not in body, (name,status)
            return elapsed

        with ThreadPoolExecutor(16) as pool:
            samples=list(pool.map(reader,range(16)))
        for name in paths:
            times=sorted(x[name] for x in samples)
            p95=times[(95*len(times)+99)//100-1]
            print(f"HTTP dashboard synthetic_cards={amount} readers=16 section={name} "
                  f"samples={len(times)} p95_ms={p95:.1f} slow_over_500ms={sum(x>500 for x in times)}",flush=True)
    print("PASS HTTPS dashboard under both synthetic data sizes and 16 concurrent readers",flush=True)


def main():
    binary = str(Path(sys.argv[1]).resolve())
    root = Path(__file__).resolve().parent.parent
    container = os.environ["CHEZHI_TEST_POSTGRES_CONTAINER"]
    base = urlsplit(os.environ["CHEZHI_TEST_DATABASE_URL"])
    original = base.path.lstrip("/")
    suffix = secrets.token_hex(5)
    database, role = "chezhi_server_" + suffix, "chezhi_runtime_" + suffix
    runtime_password = secrets.token_hex(16)

    def pg(command, *args, **kw):
        return run(["docker", "exec", "-i", container, command, "-U", base.username, *args], **kw)

    def sql(statement, db=database, stdin=None):
        cmd = ["-d", db, "-qAt", "-v", "ON_ERROR_STOP=1"]
        if statement:
            cmd.extend(("-c", statement))
        result = pg("psql", *cmd, input=stdin, capture_output=True)
        return result.stdout.strip()

    def dsn(db_user=None):
        netloc = base.netloc
        if db_user:
            netloc = f"{role}:{runtime_password}@{base.netloc.rsplit('@', 1)[1]}"
        return urlunsplit(base._replace(netloc=netloc, path="/" + database))

    def cli(env, *args, success=True):
        output = subprocess.run([binary, *args], env=env, capture_output=True, text=True, timeout=20)
        assert (output.returncode == 0) == success, (args, output.stderr)
        return output

    pg("createdb", database)
    try:
        sql(f"CREATE ROLE {role} LOGIN PASSWORD '{runtime_password}'", db=original)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            cert, key = path / "tls-cert.pem", path / "tls-key.pem"
            run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                 "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
                 "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=dict(os.environ, MSYS2_ARG_CONV_EXCL="*"))
            secret, owner_file = path / "csrf-key", path / "owner-password"
            secret.write_text(secrets.token_hex(32))
            password = "owner-" + secrets.token_hex(16)
            owner_file.write_text(password)
            migration_env = dict(os.environ, CHEZHI_DATABASE_URL=dsn(), CHEZHI_OWNER_PASSWORD_FILE=str(owner_file))
            cli(migration_env, "db-init")
            grants = (root / "migration/postgres_runtime_grants.sql").read_text().replace("chezhi_runtime", role)
            sql(None, stdin=grants)
            runtime_env = dict(os.environ, CHEZHI_DATABASE_URL=dsn(role), CHEZHI_OWNER_PASSWORD_FILE=str(owner_file))
            cli(runtime_env, "db-owner-init", success=False)
            cli(migration_env, "db-owner-init")
            cli(migration_env, "db-owner-init", success=False)
            cli(migration_env, "db-check", "--migrator")
            cli(runtime_env, "db-check", "--runtime")
            owner_file.unlink()
            runtime_env.pop("CHEZHI_OWNER_PASSWORD_FILE")
            other_port, first_port, da_port, db_port = [port() for _ in range(4)]
            host = f"localhost:{first_port}"
            common = dict(runtime_env, CHEZHI_MODE="server", CHEZHI_PUBLIC_ORIGIN="https://" + host,
                          CHEZHI_CSRF_KEY_FILE=str(secret), CHEZHI_TLS_CERT=str(cert), CHEZHI_TLS_KEY=str(key),
                          CHEZHI_LOGIN_PER_MINUTE="15", CHEZHI_LICENSE_PER_MINUTE="8",
                          CHEZHI_LICENSE_GLOBAL_PER_MINUTE="12")
            cert_ctx = ssl.create_default_context(cafile=str(cert))
            a, b = Client(first_port, host, cert_ctx), Client(other_port, host, cert_ctx)
            da, db = Client(da_port, f"127.0.0.1:{da_port}"), Client(db_port, f"127.0.0.1:{db_port}")
            env_a = dict(common, CHEZHI_LISTEN=f"127.0.0.1:{first_port}", CHEZHI_DIAGNOSTICS=f"127.0.0.1:{da_port}")
            env_b = dict(common, CHEZHI_LISTEN=f"127.0.0.1:{other_port}", CHEZHI_DIAGNOSTICS=f"127.0.0.1:{db_port}")
            for invalid in ({"CHEZHI_STORAGE": "json"}, {"CHEZHI_TLS_KEY": ""}, {"CHEZHI_PUBLIC_ORIGIN": "http://" + host},
                            {"CHEZHI_CSRF_KEY_FILE": ""}, {"CHEZHI_DIAGNOSTICS": "0.0.0.0:9090"},
                            {"CHEZHI_MODE": "test", "CHEZHI_LISTEN": "0.0.0.0:8443"}):
                failure = cli(dict(env_a, **invalid), success=False)
                assert password not in failure.stdout + failure.stderr and runtime_password not in failure.stdout + failure.stderr
            print("PASS invalid configuration rejected; explicit offline owner initialization and role preflight", flush=True)

            with instance(binary, env_a, da), ExitStack() as peer:
                peer.enter_context(instance(binary, env_b, db))
                def restart():
                    peer.close()
                    peer.enter_context(instance(binary, env_b, db))
                cookie, valid_key, device = test_cluster(a, b, da, sql, password, restart)
                try:
                    sql(f"ALTER DATABASE {database} ALLOW_CONNECTIONS false", db=original)
                    sql(f"SELECT pg_terminate_backend(pid,3000) FROM pg_stat_activity WHERE datname='{database}'", db=original)
                    eventually(lambda: da.request("/readyz")[0] == 503)
                    assert a.request("/healthz")[0] == 200
                    assert a.page("/", cookie)[0] == 503
                    assert b.license("validate", valid_key, device, 503)["error"]["code"] == "unavailable"
                finally:
                    sql(f"ALTER DATABASE {database} ALLOW_CONNECTIONS true", db=original)
                eventually(lambda: da.request("/readyz")[0] == 200)
                assert b.page("/", cookie)[0] == 200
                sql("DELETE FROM chezhi_rate_limits")
                assert b.license("validate", valid_key, device)["data"]["valid"]
                measure_dashboard_http(a,b,cookie,sql)
            print("PASS database outage, fail-closed shared state, readiness recovery and graceful process shutdown", flush=True)

            proxy_port, backend, diagnostic_port = [port() for _ in range(3)]
            proxy_host = f"localhost:{proxy_port}"
            proxy_env = dict(common, CHEZHI_LISTEN=f"127.0.0.1:{backend}", CHEZHI_PUBLIC_ORIGIN="https://" + proxy_host,
                             CHEZHI_DIAGNOSTICS=f"127.0.0.1:{diagnostic_port}", CHEZHI_TRUSTED_PROXIES="127.0.0.1/32",
                             CHEZHI_TLS_CERT="", CHEZHI_TLS_KEY="")
            server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_tls.load_cert_chain(cert, key)
            proxied = Client(proxy_port, proxy_host, cert_ctx)
            local_diag = Client(diagnostic_port, f"127.0.0.1:{diagnostic_port}")
            with instance(binary, proxy_env, local_diag), https_proxy(server_tls, backend, proxy_host, proxy_port):
                assert proxied.request("/healthz", headers={"X-Forwarded-For": "evil.invalid"})[0] == 200
                direct = Client(backend, proxy_host, source="127.0.0.2")
                assert direct.request("/healthz", headers={"X-Forwarded-For": "127.0.0.1", "X-Forwarded-Proto": "https"})[0] == 403
                assert Client(backend, proxy_host).request("/healthz", headers={"X-Forwarded-For": "127.0.0.1, 1.2.3.4",
                                                                               "X-Forwarded-Proto": "https"})[0] == 403
            print("PASS real HTTPS reverse proxy and rejection of untrusted or ambiguous forwarded transport", flush=True)

            test_port, test_diag = port(), port()
            test_host = f"127.0.0.1:{test_port}"
            test_env = dict(common, CHEZHI_MODE="test", CHEZHI_LISTEN=test_host,
                            CHEZHI_PUBLIC_ORIGIN="http://" + test_host, CHEZHI_TLS_CERT="", CHEZHI_TLS_KEY="",
                            CHEZHI_DIAGNOSTICS=f"127.0.0.1:{test_diag}")
            test_client = Client(test_port,test_host)
            with instance(binary,test_env,Client(test_diag,f"127.0.0.1:{test_diag}")):
                status,_,body = test_client.request("/api/demo/activate","POST",
                    json.dumps(dict(key=valid_key,device=device)),{"Content-Type":"application/json"})
                assert status==200 and json.loads(body)["valid"]
            print("PASS loopback-only test mode and legacy activation compatibility", flush=True)

            image = os.getenv("CHEZHI_TEST_CONTAINER_IMAGE")
            if image:
                test_container(image, suffix, path, env_a, a, da)
    finally:
        pg("dropdb", "--force", database)
        sql(f"DROP ROLE IF EXISTS {role}", db=original)


def test_container(image, suffix, path, env, client, diagnostic):
    # The fixture contains disposable synthetic credentials only. Mounted
    # inputs must be readable by the image's unprivileged UID on Linux.
    path.chmod(0o755)
    for entry in path.iterdir():
        entry.chmod(0o444)
    name = "chezhi-server-test-" + suffix
    settings = {k: env[k] for k in ("CHEZHI_MODE", "CHEZHI_DATABASE_URL", "CHEZHI_LISTEN",
                                    "CHEZHI_DIAGNOSTICS", "CHEZHI_PUBLIC_ORIGIN")}
    dsn_file = path / "runtime-url"
    dsn_file.write_text(settings.pop("CHEZHI_DATABASE_URL"))
    dsn_file.chmod(0o444)
    settings.update(CHEZHI_DATABASE_URL_FILE="/inputs/runtime-url", CHEZHI_CSRF_KEY_FILE="/inputs/csrf-key",
                    CHEZHI_TLS_CERT="/inputs/tls-cert.pem", CHEZHI_TLS_KEY="/inputs/tls-key.pem")
    args = ["docker", "run", "-d", "--name", name, "--network", "host", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true", "-v", f"{path}:/inputs:ro"]
    for k, v in settings.items():
        args.extend(("-e", f"{k}={v}"))
    run([*args, image], stdout=subprocess.DEVNULL)
    try:
        eventually(lambda: diagnostic.request("/readyz")[0] == 200, timeout=20)
        assert client.request("/healthz")[0] == 200
        assert run(["docker", "inspect", "-f", "{{.Config.User}}", name], capture_output=True).stdout.strip() == "65532:65532"
        eventually(lambda: run(["docker", "inspect", "-f", "{{.State.Health.Status}}", name],
                               capture_output=True).stdout.strip() == "healthy", timeout=20)
        run(["docker", "stop", "--time", "10", name], stdout=subprocess.DEVNULL)
        assert run(["docker", "inspect", "-f", "{{.State.ExitCode}}", name], capture_output=True).stdout.strip() == "0"
        assert '"msg":"server_stopped"' in run(["docker", "logs", name], capture_output=True).stderr
        print("PASS non-root read-only container, HTTPS, healthcheck and graceful stop", flush=True)
    finally:
        run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
