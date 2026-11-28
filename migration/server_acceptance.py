"""Standalone integration against disposable PostgreSQL and two real processes."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from hashlib import sha256
from http.client import HTTPConnection, HTTPSConnection
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import html
from collections import Counter
from statistics import median
from dashboard_plans import capture_plans
from caddy_acceptance import run_caddy_suite
from v2_acceptance import run_v2_suite
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
from threading import Event, Thread
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
def instance(binary, env, diagnostic, ready_path="/readyz", structured=True):
    with tempfile.TemporaryFile(mode="w+b") as logs:
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        p = subprocess.Popen([binary], env=env, stdout=logs, stderr=logs, creationflags=flags)
        try:
            def ready():
                if p.poll() is not None:
                    logs.seek(0)
                    raise RuntimeError(f"instance exited: {logs.read().decode(errors='replace')}")
                return diagnostic.request(ready_path)[0] == 200
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
                if structured:
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
    return ca, key, device, password


def check_sensitive_limit(a,b,sql,password,restart):
    sql("DELETE FROM chezhi_rate_limits WHERE scope IN ('account','login')")
    first, second = a.login("admin",password), b.login("admin",password)
    replacements="next-"+secrets.token_hex(16)
    old="wrong-"+secrets.token_hex(16)
    csrf_a=a.csrf("/?view=account",first)
    csrf_b=b.csrf("/?view=account",second)
    # Keep this burst in one database-defined minute; the boundary resets counters.
    if int(sql("SELECT extract(second FROM clock_timestamp())::int"))>=50:
        eventually(lambda: int(sql("SELECT extract(second FROM clock_timestamp())::int"))<10,timeout=13)
    before=int(sql("SELECT count(*) FROM chezhi_audit WHERE action='password_failed'"))

    def change(client,cookie,csrf,current):
        return client.form("/account/password",dict(csrf=csrf,current_password=current,
            new_password=replacements,confirm_password=replacements),cookie)[0]

    for i in range(2):
        assert change(a,first,csrf_a,old)==200
    assert change(b,second,csrf_b,old)==200
    restart()
    source_variant=Client(b.port,b.host,b.tls,source="127.0.0.2")
    participants=[(a,first,csrf_a),(b,second,csrf_b),(source_variant,second,csrf_b),
                  (a,first,csrf_a),(b,second,csrf_b),(source_variant,second,csrf_b)]
    with ThreadPoolExecutor(6) as pool:
        results=list(pool.map(lambda args:change(*args,old),participants))
    assert Counter(results)=={200:2,429:4},results
    assert change(b,second,csrf_b,password)==429
    assert int(sql("SELECT count(*) FROM chezhi_audit WHERE action='password_failed'"))==before+5
    assert sql("SELECT max(used) FROM chezhi_rate_limits WHERE scope='account' AND source<>'*'")=="5"

    # Simulate window age with the database clock as the authority. The
    # old bucket is retained and the new window must be independently usable.
    sql("UPDATE chezhi_rate_limits SET window_start=window_start-120 WHERE scope='account'")
    sql("ALTER TABLE chezhi_rate_limits RENAME TO chezhi_test_rate_unavailable")
    try:
        assert change(a,first,csrf_a,password)==503
    finally:
        sql("ALTER TABLE chezhi_test_rate_unavailable RENAME TO chezhi_rate_limits")
    assert a.page("/",first)[0]==200
    assert change(b,second,csrf_b,password)==303
    assert a.page("/",first)[0]==303 and b.page("/",second)[0]==303
    assert sql("SELECT count(*) FROM chezhi_audit WHERE action='password_changed' AND actor='admin'")!="0"
    print("PASS account-wide password budget across sessions, sources, nodes and restart; concurrent limit, aged window, unavailable storage and audit",flush=True)
    sql("DELETE FROM chezhi_rate_limits WHERE scope='login'")
    return b.login("admin",replacements),replacements


def verify_secure_restore(binary,a,b,pg,sql,cli,migration_env,runtime_env,grants,env_a,password,key,device):
    sql("DELETE FROM chezhi_rate_limits WHERE scope='login'")
    owner=a.login("admin",password)
    fields=dict(csrf=a.csrf("/?view=members",owner),name="restore231",role="viewer",action="member-create")
    status,_,body=a.form("/members",fields,owner)
    assert status==200
    secret=re.search(r'rows="2">([0-9a-f]{64})</textarea>',body)[1]
    member=b.login("restore231",secret)
    assert b.page("/?view=overview",owner)[0]==200 and a.page("/?view=cards",member)[0]==200
    assert sql("SELECT count(*) FROM chezhi_sessions")!="0"
    restored="chezhi_recovered_"+secrets.token_hex(6)
    dump="/tmp/"+restored+".dump"
    live=urlsplit(migration_env["CHEZHI_DATABASE_URL"]).path.lstrip("/")
    def target(env):
        address=urlsplit(env["CHEZHI_DATABASE_URL"])
        return dict(env,CHEZHI_DATABASE_URL=urlunsplit(address._replace(path="/"+restored)))
    pg("createdb",restored)
    try:
        pg("pg_dump","-d",live,"-Fc","--no-owner","--no-acl","-f",dump)
        assert b.form("/logout",{"logout_csrf":a.csrf("/?view=account",owner,"logout_csrf")},owner)[0]==303
        editor=a.login("admin",password)
        assert a.form("/members",{**fields,"csrf":a.csrf("/?view=members",editor),"action":"member-role","role":"operator"},editor)[0]==200
        assert b.page("/",owner)[0]==303 and b.page("/",member)[0]==303

        pg("pg_restore","-d",restored,"--exit-on-error","--single-transaction","--no-owner","--no-acl",dump)
        sql(None,db=restored,stdin=grants)
        assert int(sql("SELECT count(*) FROM chezhi_sessions",db=restored))>=2
        assert int(sql("SELECT count(*) FROM chezhi_rate_limits",db=restored))>0
        client_port,diagnostic_port=port(),port()
        restored_env=dict(target(env_a),CHEZHI_LISTEN=f"127.0.0.1:{client_port}",
                          CHEZHI_DIAGNOSTICS=f"127.0.0.1:{diagnostic_port}")
        assert "requires recovery" in cli(restored_env,success=False).stderr
        cli(target(runtime_env),"db-recover-security",restored,success=False)
        cli(target(migration_env),"db-recover-security",live,success=False)
        cli(target(migration_env),"db-check","--migrator")
        def business():
            return {table:sql(f"SELECT to_jsonb(t)::text FROM chezhi_{table} t ORDER BY to_jsonb(t)::text",db=restored)
                    for table in ("orders","cards","members","owner","plans","config")}
        business_before=business()
        prior_audit=sql("SELECT to_jsonb(a)::text FROM chezhi_audit a ORDER BY position",db=restored)
        reset=cli(target(migration_env),"db-recover-security",restored)
        assert "sessions=" in reset.stdout and "rate_buckets=" in reset.stdout
        assert business()==business_before
        assert sql("SELECT to_jsonb(a)::text FROM chezhi_audit a WHERE action<>'security_recovered' ORDER BY position",db=restored)==prior_audit
        assert sql("SELECT count(*) FROM chezhi_audit WHERE action='security_recovered'",db=restored)=="1"
        assert sql("SELECT (SELECT count(*) FROM chezhi_sessions),(SELECT count(*) FROM chezhi_rate_limits)",db=restored)=="0|0"
        cli(target(migration_env),"db-recover-security",restored,success=False)
        cli(target(runtime_env),"db-check","--runtime")
        restored_client=Client(client_port,a.host,a.tls)
        diag=Client(diagnostic_port,f"127.0.0.1:{diagnostic_port}")
        with instance(binary,restored_env,diag):
            assert restored_client.page("/",owner)[0]==303 and restored_client.page("/",member)[0]==303
            new_owner=restored_client.login("admin",password)
            new_member=restored_client.login("restore231",secret)
            assert restored_client.page("/?view=cards",new_member)[0]==200
            assert restored_client.license("validate",key,device)["data"]["valid"]
            new_key=restored_client.issue(new_owner,"restored-new")
            assert restored_client.license("activate",new_key,"restored-new-device")["data"]["valid"]
        print("PASS native restore with live snapshot sessions, later logout and role change, offline audited reset, invalid old cookies and new login",flush=True)
        return editor
    finally:
        pg("dropdb","--force",restored)
        run(["docker","exec",os.environ["CHEZHI_TEST_POSTGRES_CONTAINER"],"rm","-f",dump])


def measure_dashboard_http(a,b,cookie,sql,diagnostics):
    paths = dict(overview="/?view=overview", cards="/?view=cards&page=5", orders="/?view=orders&op=5",
                 devices="/?view=devices&op=5", audit="/?view=audit&ap=5")
    previous = 0
    benchmark=os.getenv("CHEZHI_PERF_PROFILE")=="benchmark"
    audited=os.getenv("CHEZHI_AUDITED_BASELINE")=="1"
    trials=3 if benchmark else 1
    iterations=4 if benchmark else 1
    warmups=2 if benchmark else 0
    slo_pass=True
    strict=os.getenv("CHEZHI_REQUIRE_CAPACITY")=="1"
    assert not strict or (benchmark and not audited), "capacity gate requires candidate benchmark"
    capacity_failures=[]
    def stats(client):
        code,_,body=client.request("/metrics")
        assert code==200
        values={key:int(value) for key,value in re.findall(r"^(chezhi_db_[a-z_]+) (\d+)$",body,re.M)}
        for group,value in re.findall(r'^chezhi_admission_rejected_total\{group="([a-z_]+)"\} (\d+)$',body,re.M):
            values["admission_"+group]=int(value)
        return values
    def perc(values,percent):
        values=sorted(values)
        return values[(percent*len(values)+99)//100-1]

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
        assert int(sql("SELECT count(*) FROM chezhi_cards WHERE ref LIKE 'http-scale-%'")) == amount
        previous=amount
        baseline_metrics=[stats(diag) for diag in diagnostics]

        def reader(i, repeats):
            client = a if i<8 else b
            events=[]
            items=list(paths.items())
            for _ in range(repeats):
                for name,path in items[i%5:]+items[:i%5]:
                    start=time.perf_counter()
                    code,_,body=client.page(path,cookie)
                    elapsed=(time.perf_counter()-start)*1000
                    if code==200 and "业务数据暂不可用" in body:
                        code=503
                    events.append((name,code,elapsed))
            return events

        def load(rounds):
            with ThreadPoolExecutor(16) as pool:
                return [event for record in pool.map(lambda i:reader(i,rounds),range(16)) for event in record]

        if benchmark:
            cold=os.getenv("CHEZHI_PERF_COLD_DB")=="1"
            if cold:
                # This option is for the dedicated benchmark service only.
                run(["docker","restart",os.environ["CHEZHI_TEST_POSTGRES_CONTAINER"]],
                    stdout=subprocess.DEVNULL)
                eventually(lambda:all(diag.request("/readyz")[0]==200 for diag in diagnostics),timeout=25)
            first=load(1)
            print(f"FIRST_ACCESS cards={amount} cold_pg_buffers={cold} p95_ms={perc([x[2] for x in first],95):.1f} "
                  f"statuses={dict(Counter(x[1] for x in first))}",flush=True)
            assert all(event[1]==200 for event in first)
            warmed=load(warmups)
            assert all(event[1]==200 for event in warmed)

        trial_p95={name:[] for name in paths}
        combined={name:[] for name in paths}
        for trial in range(trials):
            events=load(iterations)
            for name in paths:
                selected=[x for x in events if x[0]==name]
                statuses=Counter(x[1] for x in selected)
                samples=[x[2] for x in selected if x[1]==200]
                if len(samples)!=len(selected):
                    print(f"HTTP dashboard failed cards={amount} trial={trial+1} section={name} "
                          f"statuses={dict(statuses)} error_rate={(len(selected)-len(samples))/len(selected):.4f}",flush=True)
                assert len(samples)==len(selected), (name,dict(statuses))
                trial_p95[name].append(perc(samples,95))
                combined[name].extend(samples)
                print(f"HTTP dashboard cards={amount} readers=16 trial={trial+1} section={name} "
                      f"samples={len(samples)} p50_ms={perc(samples,50):.1f} p95_ms={perc(samples,95):.1f} "
                      f"p99_ms={perc(samples,99):.1f} max_ms={max(samples):.1f} error_rate=0 "
                      f"http_503={statuses[503]} http_429={statuses[429]}",flush=True)
        for name,samples in combined.items():
            p95=median(trial_p95[name])
            slo_pass &= p95<=500
            print(f"SLO cards={amount} section={name} samples={len(samples)} median_trial_p95_ms={p95:.1f} "
                  f"slow_over_500ms={sum(x>500 for x in samples)} passed={p95<=500}",flush=True)

        if benchmark:
            csrf=a.csrf("/?view=issue",cookie)
            mixed_before=[stats(diag) for diag in diagnostics]
            started,sampled,finished=Event(),Event(),Event()
            lock_samples=[]
            def observe():
                while not finished.wait(0.10):
                    lock_samples.append(int(sql("""SELECT count(*) FROM pg_stat_activity
                        WHERE datname=current_database() AND wait_event_type='Lock' AND pid<>pg_backend_pid()""")))
            def writer():
                started.wait(timeout=15)
                assert started.is_set()
                form=dict(csrf=csrf,action="issue",preset="30",quantity=1,
                          amount_yuan="5.00",confirmed="yes",channel="test",sale_ref=f"perf-mixed-{amount}")
                outcomes=Counter()
                for _ in range(40):
                    status,_,body=a.form("/?view=issue",form,cookie)
                    outcomes[status]+=1
                    key=re.search(r'<textarea readonly aria-label="生成卡密">(.*?)</textarea>',body,re.S)
                    if status==200 and key:
                        sampled.set()
                        reply=b.license("activate",html.unescape(key[1]).strip(),"perf-device")
                        assert reply["data"]["valid"]
                        return outcomes
                    assert status in (429,503),status
                    time.sleep(0.025)
                print(f"MIXED_ISSUE_EXHAUSTED cards={amount} issue_responses={dict(outcomes)}",flush=True)
                raise AssertionError("mixed benchmark could not issue a card")

            with ThreadPoolExecutor(18) as pool:
                observed=pool.submit(observe)
                work=pool.submit(writer)
                readers=[pool.submit(reader,i,iterations) for i in range(16)]
                started.set()
                try:
                    mixed=[x for f in readers for x in f.result()]
                    writes=work.result()
                finally:
                    finished.set()
                    observed.result()
                    mixed_after=[stats(diag) for diag in diagnostics]
                    for index,(old,new) in enumerate(zip(mixed_before,mixed_after)):
                        delta={key:new[key]-old[key] for key in new if key.startswith("admission_") and key in old}
                        print(f"MIXED_ADMISSION cards={amount} instance={index+1} counters={delta or 'not available in historical baseline'}",flush=True)
            assert sampled.is_set()
            status=Counter(event[1] for event in mixed)
            print(f"MIXED cards={amount} reads={len(mixed)} responses={dict(status)} "
                  f"error_rate={(len(mixed)-status[200])/len(mixed):.4f} http_503={status[503]} http_429={status[429]} "
                  f"issue_responses={dict(writes)} activations=1 lock_samples={len(lock_samples)} "
                  f"lock_waiters_peak={max(lock_samples,default=0)}",flush=True)
            if strict:
                before_failures=len(capacity_failures)
                if len(mixed)!=320 or status!=Counter({200:320}) or writes!=Counter({200:1}):
                    capacity_failures.append(f"mixed cards={amount}: read or first issuance failure")
                required={"admission_admin_shared","admission_admin_issue","admission_public","admission_export"}
                for index,(old,new) in enumerate(zip(mixed_before,mixed_after)):
                    if not required.issubset(old) or not required.issubset(new):
                        capacity_failures.append(f"mixed cards={amount} instance={index+1}: missing admission counters")
                    elif any(new[key]!=old[key] for key in required):
                        capacity_failures.append(f"mixed cards={amount} instance={index+1}: admission rejection or reset")
                if len(mixed_before)!=2 or len(mixed_after)!=2:
                    capacity_failures.append(f"mixed cards={amount}: expected two instances")
                print(f"CAPACITY_MIXED cards={amount} passed={len(capacity_failures)==before_failures}",flush=True)
            for name in paths:
                ok=[event[2] for event in mixed if event[0]==name and event[1]==200]
                print(f"MIXED_LATENCY cards={amount} section={name} samples={len(ok)} "
                      f"p50_ms={perc(ok,50):.1f} p95_ms={perc(ok,95):.1f} p99_ms={perc(ok,99):.1f} max_ms={max(ok):.1f}",flush=True)

        end_metrics=[stats(diag) for diag in diagnostics]
        print(f"POOL cards={amount} instances={len(diagnostics)} before={baseline_metrics} after={end_metrics}",flush=True)
        plan_dir=os.getenv("CHEZHI_PLAN_DIR")
        if plan_dir and amount==100_000:
            capture_plans(sql,plan_dir,"audited" if audited else "optimized",audited)
    print(f"PERFORMANCE_500MS_TARGET {'PASS' if slo_pass else 'MISS'} trials={trials} samples_per_page_per_trial={16*iterations}",flush=True)
    if strict:
        if not slo_pass:
            capacity_failures.append("repeated HTTPS P95 exceeded 500ms")
        print(f"CAPACITY_GATE {'FAIL' if capacity_failures else 'PASS'} failures={capacity_failures}",flush=True)
        assert not capacity_failures, capacity_failures
    if os.getenv("CHEZHI_REQUIRE_PERF")=="1":
        assert benchmark and slo_pass,"repeated HTTPS P95 did not meet the 500 ms target"
    print("PASS HTTPS dashboard functional checks under both synthetic data sizes",flush=True)


def main():
    binary = str(Path(sys.argv[1]).resolve())
    baseline=os.getenv("CHEZHI_AUDITED_BASELINE")=="1"
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
            if baseline:
                grants="\n".join(line for line in grants.splitlines() if "chezhi_deployment" not in line and "chezhi_challenges" not in line and "chezhi_secure_bindings" not in line and "auth_epoch" not in line and "chezhi_signing_policy" not in line and "chezhi_signing_history" not in line)
            sql(None, stdin=grants)
            runtime_env = dict(os.environ, CHEZHI_DATABASE_URL=dsn(role), CHEZHI_OWNER_PASSWORD_FILE=str(owner_file))
            cli(runtime_env, "db-owner-init", success=False)
            if not baseline:
                cli(migration_env,"db-set-mode",database,"test")
            missing_port=port()
            missing_host=f"127.0.0.1:{missing_port}"
            no_owner=cli(dict(runtime_env,CHEZHI_MODE="test",CHEZHI_LISTEN=missing_host,
                              CHEZHI_PUBLIC_ORIGIN="http://"+missing_host,CHEZHI_CSRF_KEY_FILE=str(secret)),success=False)
            assert "configured owner credential" in no_owner.stderr
            if not baseline:
                cli(migration_env,"db-set-mode",database,"server")
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
            excessive=cli(dict(env_a,CHEZHI_DATABASE_URL=dsn()),success=False)
            assert "restricted PostgreSQL runtime grants" in excessive.stderr
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
                cookie, valid_key, device, password = test_cluster(a, b, da, sql, password, restart)
                if not baseline and os.getenv("CHEZHI_BENCHMARK_ONLY")!="1":
                    live_local=cli(dict(env_a,CHEZHI_MODE="local",CHEZHI_STORAGE="postgres",
                                        CHEZHI_LISTEN=f"127.0.0.1:{port()}"),success=False)
                    assert "different mode" in live_local.stderr
                    reject=cli(migration_env,"db-set-mode",database,"local",success=False)
                    assert "deployment is online" in reject.stderr
                    cli(migration_env,"db-recover-security",database,success=False)
                    cookie,password=check_sensitive_limit(a,b,sql,password,restart)
                    if os.getenv("CHEZHI_BENCHMARK_ONLY")!="1":
                        cookie=verify_secure_restore(binary,a,b,pg,sql,cli,migration_env,runtime_env,
                                                      grants,env_a,password,valid_key,device)
                try:
                    sql(f"ALTER DATABASE {database} ALLOW_CONNECTIONS false", db=original)
                    sql(f"SELECT pg_terminate_backend(pid,3000) FROM pg_stat_activity WHERE datname='{database}'", db=original)
                    eventually(lambda: da.request("/readyz")[0] == 503)
                    assert a.request("/healthz")[0] == 200
                    assert a.page("/", cookie)[0] == 503
                    assert b.license("validate", valid_key, device, 503)["error"]["code"] == "unavailable"
                finally:
                    sql(f"ALTER DATABASE {database} ALLOW_CONNECTIONS true", db=original)
                eventually(lambda: da.request("/readyz")[0] == 200 and db.request("/readyz")[0] == 200)
                assert b.page("/", cookie)[0] == 200
                sql("DELETE FROM chezhi_rate_limits")
                assert b.license("validate", valid_key, device)["data"]["valid"]
                measure_dashboard_http(a,b,cookie,sql,[da,db])
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

            if not baseline and os.getenv("CHEZHI_BENCHMARK_ONLY")!="1":
                run_caddy_suite(root,path,binary,common,cert_ctx,password,sql,Client,instance,eventually,port)
            if not baseline:
                cli(migration_env,"db-set-mode",database,"local")
                local_port=port()
                local_host=f"127.0.0.1:{local_port}"
                local_env=dict(runtime_env,CHEZHI_MODE="local",CHEZHI_STORAGE="postgres",CHEZHI_LISTEN=local_host)
                with instance(binary,local_env,Client(local_port,local_host),"/login",structured=False):
                    wrong=cli(env_a,success=False)
                    assert "different mode" in wrong.stderr
                    duplicate=cli(dict(local_env,CHEZHI_LISTEN=f"127.0.0.1:{port()}"),success=False)
                    assert "already has an instance" in duplicate.stderr
                    assert sql("SELECT count(*) FROM chezhi_sessions")=="0"
                    assert Client(local_port,local_host).page("/",cookie)[0]==303
                cli(migration_env,"db-set-mode",database,"test")
                print("PASS cross-mode isolation in both directions with real processes and old-session invalidation",flush=True)
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

            if not baseline:
                cli(migration_env,"db-set-mode",database,"server")
            image = os.getenv("CHEZHI_TEST_CONTAINER_IMAGE")
            if image:
                test_container(image, suffix, path, env_a, a, da)
            if not baseline and os.getenv("CHEZHI_BENCHMARK_ONLY")!="1":
                run_v2_suite(root,path,binary,common,migration_env,runtime_env,password,grants,
                             pg,sql,cli,Client,instance,eventually,port,cert_ctx)
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
