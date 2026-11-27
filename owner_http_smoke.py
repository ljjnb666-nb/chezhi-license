"""Real HTTP and process restart test for owner credential lifecycle."""
import base64, http.cookiejar, json, os, re, signal, subprocess, sys, tempfile, urllib.error, urllib.parse, urllib.request
from pathlib import Path
from urllib.parse import urlsplit
binary=str(Path(sys.argv[1]).resolve())
postgres = os.environ.get("CHEZHI_STORAGE") == "postgres"

def read_postgres(statement):
    admin = urlsplit(os.environ["CHEZHI_TEST_DATABASE_URL"]).username
    database = urlsplit(os.environ["CHEZHI_DATABASE_URL"]).path.lstrip("/")
    return subprocess.check_output([
        "docker", "exec", os.environ["CHEZHI_TEST_POSTGRES_CONTAINER"],
        "psql", "-U", admin, "-d", database, "-qAt", "-v", "ON_ERROR_STOP=1", "-c", statement,
    ], text=True, timeout=15).strip()
with tempfile.TemporaryDirectory() as directory:
    def start():
        p=subprocess.Popen([binary,directory],stdout=subprocess.PIPE,text=True)
        lines=[p.stdout.readline() for _ in range(5)]
        return p,lines[1].split('URL: ')[1].strip(),lines[3].split('Password: ')[1].strip()
    def stop(p):
        p.send_signal(signal.SIGINT);p.wait(timeout=7)
    def browser():return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    def req(op,url,path='',fields=None,headers=None):
        h={'Accept':'text/html'};h.update(headers or {})
        if fields is not None:h['Origin']=url.rstrip('/')
        r=urllib.request.Request(url+path,data=None if fields is None else urllib.parse.urlencode(fields).encode(),headers=h)
        try:
            with op.open(r,timeout=8) as x:return x.status,x.geturl(),x.read().decode()
        except urllib.error.HTTPError as e:return e.code,e.geturl(),e.read().decode()
    def login(op,url,password):
        token=re.search(r'name="login_csrf" value="([^"]+)"',req(op,url,'login')[2])[1]
        return req(op,url,'login',{'username':'admin','password':password,'login_csrf':token})
    p,url,temp=start(); permanent='Unique-Example-Password-Long-2026'
    try:
        a,b=browser(),browser();assert login(a,url,temp)[0]==200 and login(b,url,temp)[0]==200
        page=req(a,url,'?view=account')[2];token=re.search(r'name="csrf" value="([^"]+)"',page)[1]
        f={'csrf':token,'current_password':temp,'new_password':permanent,'confirm_password':permanent}
        assert req(a,url,'account/password',f)[1].endswith('/login')
        assert req(b,url)[1].endswith('/login') and login(b,url,temp)[0]==401 and login(b,url,permanent)[0]==200
        if postgres:
            raw = read_postgres("SELECT row_to_json(o) FROM chezhi_owner o")
            owner = json.loads(raw)
            assert owner["version"] == 1 and len(owner["salt"]) == len(owner["digest"]) == 64
            assert not (Path(directory)/"owner.json").exists()
        else:
            raw=(Path(directory)/'owner.json').read_text()
        assert permanent not in raw and temp not in raw
        print('PASS owner password configuration, two-session revocation and old credential rejection')
    finally:stop(p)
    p,url,display=start()
    try:
        assert display.startswith('(configured') and permanent not in display
        c=browser();assert login(c,url,permanent)[0]==200
        assert req(browser(),url,headers={'Accept':'application/json','Authorization':'Basic '+base64.b64encode(('admin:'+temp).encode()).decode()})[0]==401
        print('PASS restarted process authenticates persisted credential, no bootstrap disclosure or Basic Auth bypass')
        if postgres:
            audit = json.loads(read_postgres("SELECT json_agg(json_build_object('Action', action, 'Actor', actor, 'Target', target)) FROM chezhi_audit"))
            assert not (Path(directory)/"state.json").exists()
        else:
            audit=json.loads((Path(directory)/'state.json').read_text())['Audit']
        events={x['Action'] for x in audit}
        assert {'login_success','login_failed','password_changed'}<=events
        assert all(permanent not in json.dumps(x) and temp not in json.dumps(x) for x in audit)
        print('PASS persistent security audit without credentials')
        token=re.search(r'name="csrf" value="([^"]+)"',req(c,url,'?view=account')[2])[1]
        replacement='Replacement-Long-Password-2026'
        assert req(c,url,'account/password',{'csrf':token,'current_password':permanent,'new_password':replacement,'confirm_password':replacement})[1].endswith('/login')
        assert login(browser(),url,permanent)[0]==401 and login(browser(),url,replacement)[0]==200
        print('PASS existing credential file rotation and old password rejection')
    finally:stop(p)
