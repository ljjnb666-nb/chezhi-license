"""Run the checked-in proxy template through real Caddy endpoints."""
from contextlib import ExitStack, contextmanager
from http.client import HTTPConnection
import os
from pathlib import Path
import re
import secrets
import signal
import ssl
import subprocess
import tempfile


@contextmanager
def caddy_proxy(root, folder, image, executable, port, backend):
    fixture = "chezhi-caddy-" + secrets.token_hex(5)
    config = folder / (fixture + ".Caddyfile")
    if executable:
        cert = (folder / "tls-cert.pem").as_posix()
        key = (folder / "tls-key.pem").as_posix()
    else:
        cert, key = "/inputs/tls-cert.pem", "/inputs/tls-key.pem"
    template = (root / "Caddyfile.example").read_text(encoding="utf-8")
    config.write_text(template.replace("localhost:8443",f"localhost:{port}")
                      .replace("127.0.0.1:8080",f"127.0.0.1:{backend}")
                      .replace("/run/secrets/tls_cert",f'"{cert}"')
                      .replace("/run/secrets/tls_key",f'"{key}"'),encoding="utf-8")
    args = ["--config", str(config) if executable else "/inputs/" + config.name, "--adapter", "caddyfile"]
    if executable:
        subprocess.run([executable,"validate",*args],check=True,timeout=15,capture_output=True)
        with tempfile.TemporaryFile() as log:
            flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
            process = subprocess.Popen([executable,"run",*args],stdout=log,stderr=log,creationflags=flags)
            try:
                yield
                if process.poll() is not None:
                    log.seek(0)
                    raise AssertionError(log.read().decode(errors="replace"))
            finally:
                if process.poll() is None:
                    process.send_signal(signal.CTRL_BREAK_EVENT if os.name=="nt" else signal.SIGTERM)
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
    else:
        command=["docker","run","--rm","--network","host","-v",f"{folder}:/inputs:ro"]
        subprocess.run([*command,image,"caddy","validate",*args],check=True,timeout=60,capture_output=True)
        subprocess.run([*command,"-d","--name",fixture,image,"caddy","run",*args],check=True,
                       timeout=60,stdout=subprocess.DEVNULL)
        try:
            yield
        finally:
            subprocess.run(["docker","stop","--time","5",fixture],check=True,timeout=20,stdout=subprocess.DEVNULL)


def raw_forwarded(backend, host, source, headers):
    with_headers=HTTPConnection("127.0.0.1",backend,source_address=(source,0),timeout=5)
    try:
        with_headers.putrequest("GET","/healthz",skip_host=True)
        with_headers.putheader("Host",host)
        for key,value in headers:
            with_headers.putheader(key,value)
        with_headers.endheaders()
        return with_headers.getresponse().status
    finally:
        with_headers.close()


def run_caddy_suite(root, folder, binary, common, cert_ctx, password, sql,
                    Client, instance, eventually, port):
    executable=os.getenv("CHEZHI_TEST_CADDY_BINARY")
    image=os.getenv("CHEZHI_TEST_CADDY_IMAGE")
    if not executable and not image:
        return
    ca, cb, ua, ub, da, db = [port() for _ in range(6)]
    host=f"localhost:{ca}"
    def settings(upstream,diagnostic):
        return dict(common,CHEZHI_LISTEN=f"127.0.0.1:{upstream}",CHEZHI_DIAGNOSTICS=f"127.0.0.1:{diagnostic}",
                    CHEZHI_PUBLIC_ORIGIN="https://"+host,CHEZHI_TRUSTED_PROXIES="127.0.0.1/32",
                    CHEZHI_TLS_CERT="",CHEZHI_TLS_KEY="")
    a,b=Client(ca,host,cert_ctx),Client(cb,host,cert_ctx)
    def diag(n):
        return Client(n,f"127.0.0.1:{n}")
    def proxy(external,upstream):
        return caddy_proxy(root,folder,image,executable,external,upstream)

    sql("DELETE FROM chezhi_rate_limits")
    with instance(binary,settings(ua,da),diag(da)),instance(binary,settings(ub,db),diag(db)),proxy(cb,ub),ExitStack() as first:
        first.enter_context(proxy(ca,ua))
        eventually(lambda:a.request("/healthz")[0]==200 and b.request("/healthz")[0]==200)
        cookie=a.login("admin",password,peer=b)
        assert b.page("/?view=account",cookie)[0]==200
        try:
            Client(ca,host,ssl.create_default_context()).request("/healthz")
        except ssl.SSLCertVerificationError:
            pass
        else:
            raise AssertionError("untrusted proxy TLS certificate accepted")
        form=dict(csrf=a.csrf("/?view=members",cookie),name="caddy_member",role="viewer",action="member-create")
        for origin in (False,"https://untrusted.invalid"):
            assert b.form("/members",form,cookie,origin=origin)[0]==403
        assert b.form("/members",{**form,"csrf":"invalid"},cookie)[0]==403
        status,_,body=b.form("/members",form,cookie)
        assert status==200
        key=re.search(r'rows="2">([0-9a-f]{64})</textarea>',body)[1]
        member=a.login("caddy_member",key)
        assert b.page("/?view=issue",member)[0]==403
        assert a.form("/backup",dict(csrf=a.csrf("/?view=account",member,"logout_csrf")),member)[0]==403
        raw=a.issue(cookie,"real-caddy-order")
        assert b.license("activate",raw,"caddy-device")["data"]["valid"]
        for index in range(7):
            assert (a if index%2 else b).license("validate",raw,"caddy-device",
                extra={"X-Forwarded-For":f"198.51.100.{index+1}","X-Forwarded-Proto":"http",
                       "X-Forwarded-Host":"fake.invalid"})["data"]["valid"]
        assert b.license("validate",raw,"caddy-device",429,{"X-Forwarded-For":"192.0.2.3"})["error"]["code"]=="rate_limited"
        form["action"],form["role"]="member-role","operator"
        assert b.form("/members",form,cookie)[0]==200
        assert a.page("/",member)[0]==303
        assert b.form("/logout-all",dict(logout_csrf=a.csrf("/?view=account",cookie,"logout_csrf")),cookie)[0]==303
        assert a.page("/",cookie)[0]==303
        cookie=b.login("admin",password)
        genuine=[("X-Forwarded-Proto","https"),("X-Forwarded-For","127.0.0.1")]
        assert raw_forwarded(ua,host,"127.0.0.2",genuine)==403
        for extra in ([("X-Forwarded-For","127.0.0.2")],[("X-Forwarded-Proto","https")]):
            assert raw_forwarded(ua,host,"127.0.0.1",genuine+extra)==403
        assert raw_forwarded(ua,host,"127.0.0.1",[("X-Forwarded-Proto","https"),("X-Forwarded-For","127.0.0.1, 10.0.0.1")])==403
        assert raw_forwarded(ua,host,"127.0.0.1",[("X-Forwarded-Proto","https"),("X-Forwarded-For","invalid")])==403
        first.close()
        try:
            a.request("/healthz")
        except OSError:
            pass
        else:
            raise AssertionError("stopped proxy accepted a request")
        with proxy(ca,ua):
            eventually(lambda:a.request("/healthz")[0]==200)
            assert a.page("/?view=account",cookie)[0]==200
    print("PASS real Caddy config validation, Secure Host-only cookies, Origin, CSRF, permissions, issuance, activation, shared logout and limits, headers, TLS rejection and proxy recovery",flush=True)
