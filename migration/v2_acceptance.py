"""Independent Python/OpenSSL wire verification against real V2 processes.
All keys, cards, and databases are disposable fixtures. No third-party
Python cryptography dependency; OpenSSL 3 is already required by the suite.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import struct
import subprocess
import time
import re
from collections import Counter
from threading import BoundedSemaphore
from urllib.parse import urlsplit, urlunsplit

from caddy_acceptance import caddy_proxy

P256_N = int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
ED25519_SPKI = bytes.fromhex("302a300506032b6570032100")


def openssl(*args, data=None):
    return subprocess.run(["openssl", *map(str, args)], input=data, capture_output=True,
                          check=True, timeout=15).stdout


def scope_bytes(scope, product="chezhi"):
    product = product.encode("ascii")
    return bytes.fromhex(scope) + bytes([len(product)]) + product


def card_hash(card):
    # Generated fixture cards are canonical Crockford Base32 already.
    return sha256(card.encode("ascii")).digest()


def challenge_bytes(scope, op, card, public, data):
    return (b"CHEZHI/PROOF/V2\0" + scope_bytes(scope) +
            bytes([{"activate": 1, "validate": 2, "renew": 3}[op]]) +
            bytes.fromhex(data["nonce"]) + card_hash(card) +
            sha256(bytes.fromhex(public)).digest() +
            struct.pack(">Qqq", data["epoch"], data["issued_at"], data["expires_at"]))


def credential_bytes(data):
    return (b"CHEZHI/CREDENTIAL/V2\0" + scope_bytes(data["deployment"], data["product"]) +
            bytes.fromhex(data["license_id"]) + bytes.fromhex(data["device"]) +
            bytes.fromhex(data["key_id"]) + bytes.fromhex(data["nonce"]) + struct.pack(">Qqqq", data["revision"],
            data["issued_at"], data["expires_at"], data["license_expires_at"]))


def device(folder, name):
    key = folder / (name + ".fixture")
    openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", key)
    spki = openssl("pkey", "-in", key, "-pubout", "-outform", "DER")
    assert len(spki) == 91 and spki[-65] == 4
    return key, spki[-65:].hex()


def sign(key, transcript):
    # P-256 signatures have a short-form DER sequence and two integers.
    der = openssl("dgst", "-sha256", "-sign", key, data=transcript)
    assert der[0] == 0x30 and der[1] == len(der) - 2
    i, values = 2, []
    for _ in range(2):
        assert der[i] == 2
        size = der[i+1]
        values.append(int.from_bytes(der[i+2:i+2+size], "big"))
        i += 2 + size
    assert i == len(der)
    r, s = values
    assert 0 < r < P256_N and 0 < s < P256_N
    return (r.to_bytes(32, "big") + min(s, P256_N-s).to_bytes(32, "big")).hex()


def post(client, action, body, status=200, extra=None):
    code, headers, raw = client.request("/api/v2/licenses/"+action, "POST",
                                        json.dumps(body), {"Content-Type": "application/json", **(extra or {})})
    assert code == status, (action, code, status)
    reply = json.loads(raw)
    assert reply["version"] == "v2" and reply["request_id"] == headers["x-request-id"]
    if status != 200:
        assert "data" not in reply and "error" in reply
        return reply["error"]["code"]
    assert "error" not in reply
    if action != "challenge":
        assert reply["data"]["nonce"] == body["nonce"]
    return reply["data"]


def prepare(client, scope, action, card, key, public):
    data = post(client, "challenge", dict(key=card, public_key=public, operation=action))
    assert data["deployment"] == scope and data["product"] == "chezhi"
    transcript = challenge_bytes(scope, action, card, public, data)
    assert data["transcript"] == transcript.hex()
    assert 0 < data["expires_at"] - data["issued_at"] <= 120
    return dict(key=card, public_key=public, nonce=data["nonce"], signature=sign(key, transcript))


def verify(folder, data, scope, public, card, signer):
    assert data["valid"] is True and data["deployment"] == scope and data["product"] == "chezhi"
    assert data["device"] == sha256(bytes.fromhex(public)).hexdigest()
    assert data["license_id"] == card_hash(card)[:12].hex()
    assert data["key_id"] == sha256(bytes.fromhex(signer)).hexdigest()
    assert 0 < data["expires_at"]-data["issued_at"] <= 300
    assert data["license_expires_at"] == 0 or data["expires_at"] <= data["license_expires_at"]
    transcript = credential_bytes(data)
    assert transcript.hex() == data["transcript"]
    # Verify independently of the Go proof package, using a provisioned key.
    pk, msg, sig = (folder / name for name in ("verify-public.der", "verify-message.bin", "verify-signature.bin"))
    pk.write_bytes(ED25519_SPKI + bytes.fromhex(signer))
    msg.write_bytes(transcript)
    sig.write_bytes(bytes.fromhex(data["signature"]))
    openssl("pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey", pk,
            "-rawin", "-in", msg, "-sigfile", sig)


def vector():
    # The exact Go fixed challenge fixture; independent encoding in Python.
    transcript = (b"CHEZHI/PROOF/V2\0" + scope_bytes("01"*32, "chezhi1") +
                  b"\x01" + bytes([2])*32 + bytes([3])*32 + bytes([4])*32 +
                  struct.pack(">Qqq", 1, 1700000000, 1700000120))
    assert len(transcript) == 177
    assert sha256(transcript).hexdigest() == "5f1e67d4edd02f440ea3c2e2c8eab78cfa060a6dcfe31e2b02509a59fa36ab09"


def exercise_capacity(folder, a, b, diagnostics, query, scope, card, key, public, signer):
    """Bounded synthetic workload on the disposable V2 database only."""
    # The previous functional assertions use the same fixture source budget.
    # Isolate measurement from them; never clear a production rate limiter.
    query("DELETE FROM chezhi_rate_limits")
    def snapshot():
        return query("SELECT to_jsonb(t)::text FROM chezhi_secure_bindings t ORDER BY card_id"), query(
            "SELECT to_jsonb(t)::text FROM chezhi_cards t ORDER BY id")
    def metrics():
        values = []
        for diagnostic in diagnostics:
            status, _, body = diagnostic.request("/metrics")
            assert status == 200
            value = {name:int(count) for name,count in re.findall(
                r"^(chezhi_db_[a-z_]+) (\d+)$",body,re.M)}
            for name in ("chezhi_http_requests_total","chezhi_http_errors_total"):
                match = re.search(r"^"+name+r'\{group="public"\} (\d+)$',body,re.M)
                assert match is not None,"public request metric missing"
                value[name] = int(match[1])
            assert {"chezhi_db_connections_open","chezhi_db_connections_in_use",
                    "chezhi_db_connections_idle","chezhi_db_pool_waits_total"} <= value.keys()
            values.append(value)
        return values
    def pctl(values, p):
        ordered = sorted(values)
        return ordered[(p*len(ordered)+99)//100-1]
    before = snapshot()
    pool_before = metrics()
    clients = (a,b)
    # The server intentionally admits only three simultaneous public
    # handlers per instance. Keep one spare slot for response-finalization
    # overlap. Worker concurrency is not the HTTP in-flight limit.
    slots = (BoundedSemaphore(2),BoundedSemaphore(2))
    def worker(i):
        start = time.perf_counter()
        with slots[i%2]:
            proof = prepare(clients[i%2],scope,"renew",card,key,public)
        challenged = time.perf_counter()
        with slots[1-i%2]:
            data = post(clients[1-i%2],"renew",proof)
        completed = time.perf_counter()
        return (data,(challenged-start)*1000,(completed-challenged)*1000,(completed-start)*1000)
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(worker,range(32)))
    elapsed = time.perf_counter()-started
    # Independent OpenSSL verifier uses fixed temporary file names: serialize
    # verification outside the measured parallel request path.
    nonces = set()
    for data,_,_,_ in results:
        verify(folder,data,scope,public,card,signer)
        assert data["nonce"] not in nonces
        nonces.add(data["nonce"])
    assert len(nonces)==32 and len({x[0]["revision"] for x in results})==1
    assert snapshot()==before,"renewal changed binding or license lifecycle"
    for label,index in (("challenge_and_sign",1),("renew",2),("end_to_end",3)):
        samples=[x[index] for x in results]
        print(f"V2_CAPACITY phase={label} workers=16 http_inflight_budget=4 transactions=32 p50_ms={pctl(samples,50):.1f} "
              f"p95_ms={pctl(samples,95):.1f} p99_ms={pctl(samples,99):.1f} max_ms={max(samples):.1f}",flush=True)
    print(f"V2_CAPACITY throughput={32/elapsed:.2f} transactions_per_second success=32 errors=0 "
          f"pool_before={pool_before} pool_after={metrics()}",flush=True)
    proof=prepare(a,scope,"renew",card,key,public)
    def duplicate(i):
        with slots[i%2]:
            code,headers,raw=clients[i%2].request("/api/v2/licenses/renew","POST",json.dumps(proof),
                                                   {"Content-Type":"application/json"})
        reply=json.loads(raw)
        assert reply["version"]=="v2" and reply["request_id"]==headers["x-request-id"]
        if code==200:
            assert reply["data"]["nonce"]==proof["nonce"]
            return code,reply["data"]
        assert code==403 and "data" not in reply and reply["error"]["code"]=="authorization_denied"
        return code,None
    with ThreadPoolExecutor(max_workers=8) as pool:
        duplicates=list(pool.map(duplicate,range(8)))
    assert Counter(code for code,_ in duplicates)=={200:1,403:7}
    verify(folder,next(data for code,data in duplicates if code==200),scope,public,card,signer)
    assert snapshot()==before,"replayed renewal changed binding or license lifecycle"
    # Public counters are finalized in the handler defer. Give the final
    # response's bookkeeping a bounded opportunity to settle.
    deadline = time.monotonic()+3
    expected = (37,36)  # 32 requests each, then one challenge + 8 replays
    while True:
        observed = metrics()
        deltas = tuple(after["chezhi_http_requests_total"]-prior["chezhi_http_requests_total"]
                       for prior,after in zip(pool_before,observed))
        if deltas==expected or time.monotonic()>=deadline:
            break
        time.sleep(0.05)
    assert deltas==expected,("public metric delta",deltas,expected)
    assert all(after["chezhi_http_errors_total"]==prior["chezhi_http_errors_total"]
               and after["chezhi_db_pool_waits_total"]>=prior["chezhi_db_pool_waits_total"]
               for prior,after in zip(pool_before,observed))
    print(f"V2_METRICS_PASS public_requests={sum(deltas)} server_errors=0 per_instance={deltas}",flush=True)
    print("PASS V2 bounded capacity, independent signatures, stable licensing state, cross-instance replay rejection",flush=True)
    query("DELETE FROM chezhi_rate_limits")


def run_v2_suite(root, folder, binary, common, migration_env, runtime_env, password,
                 grants, pg, sql, cli, Client, instance, eventually, port, cert_ctx):
    vector()
    suffix = secrets.token_hex(5)
    live, restored = "chezhi_v2_"+suffix, "chezhi_v2_restore_"+suffix
    dump = "/tmp/"+live+".dump"
    def target(env, name):
        address = urlsplit(env["CHEZHI_DATABASE_URL"])
        return dict(env, CHEZHI_DATABASE_URL=urlunsplit(address._replace(path="/"+name)))
    def query(statement, db=live):
        return sql(statement, db=db)
    def policy(db=live):
        return query("SELECT deployment,public_key FROM chezhi_signing_policy", db).split("|")
    def trust(db=live):
        result = cli(target(migration_env, db), "db-signing-info").stdout
        scope, public = policy(db)
        assert scope in result and public in result
        return scope, public
    def make_signer(name):
        path = folder / name
        output = cli(migration_env,"license-key-generate",str(path)).stdout
        return path, output.strip().split()[-1]
    def endpoint(db, signer, proxy=False):
        service, diagnostic = port(), port()
        external = port() if proxy else service
        host = f"localhost:{external}"
        env = dict(target(common,db), CHEZHI_SIGNING_KEY_FILE=str(signer),
                   CHEZHI_LISTEN=f"127.0.0.1:{service}", CHEZHI_DIAGNOSTICS=f"127.0.0.1:{diagnostic}",
                   CHEZHI_PUBLIC_ORIGIN="https://"+host, CHEZHI_LICENSE_PER_MINUTE="120",
                   CHEZHI_LICENSE_GLOBAL_PER_MINUTE="240")
        if proxy:
            env.update(CHEZHI_TRUSTED_PROXIES="127.0.0.1/32", CHEZHI_TLS_CERT="", CHEZHI_TLS_KEY="")
        return env, Client(external,host,cert_ctx), Client(diagnostic,f"127.0.0.1:{diagnostic}"),service
    pg("createdb",live)
    created_restore = False
    try:
        owner = folder / ("v2-owner-"+suffix)
        owner.write_text(password)
        m = target(migration_env,live)
        r = target(runtime_env,live)
        cli(m,"db-init")
        sql(None,db=live,stdin=grants)
        cli(m,"db-set-mode",live,"server")
        cli(dict(m,CHEZHI_OWNER_PASSWORD_FILE=str(owner)),"db-owner-init")
        owner.unlink()
        # Create a historical legacy-bound card before secure policy activation.
        el,legacy,dl,_=endpoint(live,"")
        with instance(binary,el,dl):
            legacy_cookie=legacy.login("admin",password)
            legacy_card=legacy.issue(legacy_cookie,"v2-legacy-order")
            assert legacy_card
            assert legacy.license("activate",legacy_card,"legacy-device")["data"]["valid"]
        signer,public_key = make_signer("v2-signing-"+suffix)
        cli(r,"db-set-signing-key",live,"none",public_key,success=False)
        cli(m,"db-set-signing-key",live,"none",public_key)
        cli(r,"db-check","--runtime")
        scope,public_key = trust()
        ea,a,da,_ = endpoint(live,signer)
        eb,b,db,_ = endpoint(live,signer)
        cli(dict(ea,CHEZHI_SIGNING_KEY_FILE=""),success=False)
        k1,p1 = device(folder,"device1-"+suffix)
        k2,p2 = device(folder,"device2-"+suffix)
        with instance(binary,ea,da),instance(binary,eb,db):
            cookie = a.login("admin",password)
            legacy_before=query("SELECT activated,expires FROM chezhi_cards WHERE ref='v2-legacy-order'")
            assert post(b,"activate",prepare(a,scope,"activate",legacy_card,k1,p1),403)=="authorization_denied"
            legacy_id=card_hash(legacy_card)[:12].hex()
            assert a.form("/?view=cards",dict(csrf=a.csrf("/?view=cards",cookie),id=legacy_id,action="unbind"),cookie)[0]==200
            upgraded=post(b,"activate",prepare(a,scope,"activate",legacy_card,k1,p1))
            verify(folder,upgraded,scope,p1,legacy_card,public_key)
            assert query("SELECT activated,expires FROM chezhi_cards WHERE ref='v2-legacy-order'")==legacy_before
            assert b.license("activate",legacy_card,"legacy-device")["data"]["status"]=="secure_protocol_required"
            card = a.issue(cookie,"v2-secure-order")
            assert card
            assert b.license("activate",card,"legacy")["data"]["status"]=="secure_protocol_required"
            browser = b.form("/activate",dict(csrf=b.csrf("/activate"),key=card,device="legacy"))
            assert browser[0]==200 and "secure_protocol_required" in browser[2]
            one = prepare(a,scope,"activate",card,k1,p1)
            # Cross-operation and concurrent same nonce: one successful commit.
            assert post(b,"validate",one,403)=="authorization_denied"
            wrong=dict(one,signature=("00"*64))
            assert post(b,"activate",wrong,403)=="authorization_denied"
            def activate(client):
                code,headers,raw=client.request("/api/v2/licenses/activate","POST",json.dumps(one),
                                                {"Content-Type":"application/json"})
                reply=json.loads(raw)
                assert reply["version"]=="v2" and reply["request_id"]==headers["x-request-id"]
                return code,reply
            with ThreadPoolExecutor(2) as pool:
                results=list(pool.map(activate,(a,b)))
            assert sorted(code for code,_ in results)==[200,403]
            credential=next(x["data"] for code,x in results if code==200)
            assert credential["nonce"]==one["nonce"]
            verify(folder,credential,scope,p1,card,public_key)
            assert post(b,"activate",one,403)=="authorization_denied"
            assert post(a,"activate",prepare(b,scope,"activate",card,k2,p2),403)=="authorization_denied"
            current=post(b,"renew",prepare(a,scope,"renew",card,k1,p1))
            verify(folder,current,scope,p1,card,public_key)
            # Simulate application-level loss of a committed response by
            # discarding its result. Recovery must use a fresh challenge.
            lost=prepare(a,scope,"validate",card,k1,p1)
            post(b,"validate",lost)
            assert post(a,"validate",lost,403)=="authorization_denied"
            recovered=post(a,"validate",prepare(b,scope,"validate",card,k1,p1))
            verify(folder,recovered,scope,p1,card,public_key)
            assert recovered["nonce"]!=lost["nonce"] and recovered["revision"]==current["revision"]
            assert recovered["license_expires_at"]==current["license_expires_at"]
            stale=prepare(a,scope,"validate",card,k1,p1)
            fields=dict(csrf=a.csrf("/?view=cards",cookie),id=credential["license_id"],action="unbind")
            assert b.form("/?view=cards",fields,cookie)[0]==200
            assert post(b,"validate",stale,403)=="authorization_denied"
            assert a.license("activate",card,"legacy")["data"]["status"]=="secure_protocol_required"
            rebound=post(b,"activate",prepare(a,scope,"activate",card,k2,p2))
            verify(folder,rebound,scope,p2,card,public_key)
            assert rebound["revision"]>credential["revision"] and rebound["license_expires_at"]==credential["license_expires_at"]
            exercise_capacity(folder,a,b,(da,db),query,scope,card,k2,p2,public_key)
            pending=prepare(a,scope,"validate",card,k2,p2)
            revoked=a.issue(cookie,"v2-revoked-order")
            assert revoked
            rev=post(a,"activate",prepare(b,scope,"activate",revoked,k1,p1))
            assert b.form("/?view=cards",{**fields,"id":rev["license_id"],"action":"revoke"},cookie)[0]==200
            assert post(b,"validate",prepare(a,scope,"validate",revoked,k1,p1),403)=="authorization_denied"
            # Browser-only headers and malformed field rejection.
            assert post(a,"challenge",dict(key=card,public_key=p2,operation="validate"),403,
                        {"Origin":"https://example.invalid"})=="browser_origin_forbidden"
            assert post(a,"challenge",dict(key=card,public_key=p2,operation="validate",extra="x"),400)=="invalid_json"
            assert query("SELECT count(*) FROM chezhi_secure_bindings")=="3"
            dump_started=time.perf_counter()
            pg("pg_dump","-d",live,"-Fc","--no-owner","--no-acl","-f",dump)
            dump_seconds=time.perf_counter()-dump_started
            assert post(b,"validate",pending,200)["valid"]
        print("PASS V2 real two-process TLS, independent OpenSSL transcripts/signatures, atomic replay, foreign key denial, unbind/rebind, revoke and legacy downgrade",flush=True)

        recovery_started=time.perf_counter()
        pg("createdb",restored)
        created_restore=True
        pg("pg_restore","-d",restored,"--exit-on-error","--single-transaction","--no-owner","--no-acl",dump)
        restore_seconds=time.perf_counter()-recovery_started
        sql(None,db=restored,stdin=grants)
        er,rr,dr,_=endpoint(restored,signer)
        cli(er,success=False)
        assert int(query("SELECT count(*) FROM chezhi_challenges",restored))>0
        before=query("SELECT to_jsonb(t)::text FROM chezhi_secure_bindings t ORDER BY card_id",restored)
        cards_before=query("SELECT to_jsonb(t)::text FROM chezhi_cards t ORDER BY id",restored)
        cli(target(migration_env,restored),"db-recover-security",restored)
        assert query("SELECT count(*) FROM chezhi_challenges",restored)=="0"
        assert query("SELECT to_jsonb(t)::text FROM chezhi_secure_bindings t ORDER BY card_id",restored)==before
        assert query("SELECT to_jsonb(t)::text FROM chezhi_cards t ORDER BY id",restored)==cards_before
        new_scope,new_pub=trust(restored)
        assert new_scope!=scope and new_pub==public_key
        cli(target(runtime_env,restored),"db-check","--runtime")
        with instance(binary,er,dr):
            assert post(rr,"validate",pending,403)=="authorization_denied"
            renewed=post(rr,"renew",prepare(rr,new_scope,"renew",card,k2,p2))
            verify(folder,renewed,new_scope,p2,card,public_key)
            assert post(rr,"validate",prepare(rr,new_scope,"validate",revoked,k1,p1),403)=="authorization_denied"
            assert rr.license("activate",card,"legacy")["data"]["status"]=="secure_protocol_required"
        print(f"V2_RECOVERY_TIMING dump_seconds={dump_seconds:.3f} restore_create_seconds={restore_seconds:.3f} "
              f"verified_recovery_seconds={time.perf_counter()-recovery_started:.3f}",flush=True)
        print("PASS V2 native logical restore, old challenge rejection, changed scope, preserved secure bindings and revoked state",flush=True)

        new_signer,new_key=make_signer("v2-rotated-"+suffix)
        old_id=sha256(bytes.fromhex(public_key)).hexdigest()
        cli(m,"db-set-signing-key",live,old_id,new_key)
        cli(ea,success=False)
        rotated_scope,rotated_pub=trust()
        assert rotated_scope!=scope and rotated_pub==new_key
        cli(m,"db-set-signing-key",live,sha256(bytes.fromhex(new_key)).hexdigest(),public_key,success=False)
        assert query("SELECT count(*) FROM chezhi_signing_history")=="2"
        ec,c,dc,_=endpoint(live,new_signer)
        with instance(binary,ec,dc):
            result=post(c,"validate",prepare(c,rotated_scope,"validate",card,k2,p2))
            verify(folder,result,rotated_scope,p2,card,new_key)
        print("PASS V2 offline rotation, old private-key startup refusal, retired-key refusal, new credential trust",flush=True)

        executable=os.getenv("CHEZHI_TEST_CADDY_BINARY")
        image=os.getenv("CHEZHI_TEST_CADDY_IMAGE")
        if executable or image:
            ep,p,dp,backend=endpoint(live,new_signer,proxy=True)
            with instance(binary,ep,dp),caddy_proxy(root,folder,image,executable,p.port,backend):
                eventually(lambda:p.request("/healthz")[0]==200)
                data=post(p,"renew",prepare(p,rotated_scope,"renew",card,k2,p2))
                verify(folder,data,rotated_scope,p2,card,new_key)
                assert p.license("activate",card,"legacy")["data"]["status"]=="secure_protocol_required"
            print("PASS V2 actual Caddy TLS proxy and secure-only protocol enforcement",flush=True)
    finally:
        if created_restore:
            pg("dropdb","--force",restored)
        pg("dropdb","--force",live)
        subprocess.run(["docker","exec",os.environ["CHEZHI_TEST_POSTGRES_CONTAINER"],"rm","-f",dump],
                       check=True,timeout=20)
