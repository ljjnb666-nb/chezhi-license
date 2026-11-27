import subprocess, tempfile, signal, sys, re, urllib.request, urllib.parse, urllib.error, http.cookiejar, zipfile, io, json, hashlib
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent/"migration"))
from restore_backup import restore
with tempfile.TemporaryDirectory() as d:
    p=subprocess.Popen([sys.argv[1],d],stdout=subprocess.PIPE,text=True)
    try:
        lines=[p.stdout.readline() for _ in range(5)]; url=lines[1].split('URL: ')[1].strip(); pw=lines[3].split('Password: ')[1].strip()
        def client(): return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        owner,member=client(),client()
        def req(op,path='',fields=None):
            h={'Accept':'text/html'}
            if fields is not None:h['Origin']=url.rstrip('/')
            r=urllib.request.Request(url+path,data=urllib.parse.urlencode(fields).encode() if fields is not None else None,headers=h)
            try:
                with op.open(r,timeout=5) as x:return x.status,x.geturl(),x.read()
            except urllib.error.HTTPError as e:return e.code,e.geturl(),e.read()
        def csrf(b,name='csrf'): return re.search(rb'name="'+name.encode()+rb'" value="([^"]+)"',b)[1].decode()
        def login(op,name,password):
            token=csrf(req(op,'login')[2],'login_csrf')
            return req(op,'login',{'username':name,'password':password,'login_csrf':token})
        assert login(owner,'admin',pw)[0]==200
        token=csrf(req(owner,'?view=members')[2]);result=req(owner,'members',{'csrf':token,'action':'member-create','name':'read_only','role':'viewer'})[2];secret=re.search(rb'aria-label="\xe6\x88\x90\xe5\x91\x98\xe7\x99\xbb\xe5\xbd\x95\xe5\x87\xad\xe6\x8d\xae" rows="2">([0-9a-f]{64})</textarea>',result)[1].decode()
        assert login(member,'read_only',secret)[0]==200
        assert secret.encode() not in req(owner,'?view=members')[2]
        assert req(member,'?view=issue')[0]==403 and req(member,'?view=members')[0]==403
        mt=csrf(req(member,'?view=cards')[2]) if b'name="csrf"' in req(member,'?view=cards')[2] else csrf(req(member,'?view=account')[2],'logout_csrf')
        assert req(member,'?view=cards',{'csrf':mt,'action':'issue'})[0]==403 and req(member,'backup',{'csrf':mt})[0]==403 and req(member,'export',{'csrf':mt})[0]==403
        print('PASS member creation, login, one-time credential, server-side read-only restrictions')
        assert req(owner,'members',{'csrf':token,'action':'member-role','name':'read_only','role':'operator'})[0]==200
        assert req(member)[1].endswith('/login'); assert login(member,'read_only',secret)[0]==200
        mt=csrf(req(member,'?view=issue')[2]);assert '已生成'.encode() in req(member,'?view=issue',{'csrf':mt,'action':'issue','preset':'30','quantity':'1','amount':'0','channel':'test','sale_ref':'=1+1','confirmed':'yes'})[2]
        assert req(owner,'members',{'csrf':token,'action':'member-disable','name':'read_only'})[0]==200 and req(member)[1].endswith('/login')
        print('PASS role change revokes old session, operator issuance, account disable')
        code,_,b=req(owner,'backup',{'csrf':token});assert code==200
        with zipfile.ZipFile(io.BytesIO(b)) as z:
            assert set(z.namelist())=={'state.json','plans.json','manifest.json'} and z.testzip() is None
            m=json.loads(z.read('manifest.json'));assert all(hashlib.sha256(z.read(n)).hexdigest()==h for n,h in m['SHA256'].items())
            assert len(json.loads(z.read('state.json'))['Cards'])==1 and secret.encode() not in z.read('state.json')
            events=json.loads(z.read('state.json'))['Audit']
            assert any(a['Action']=='issue' and a.get('Actor')=='read_only' for a in events)
            assert any(a['Action']=='member-disable' and a.get('Actor')=='admin' and a.get('Target')=='read_only' for a in events)
        source=Path(d)/'backup.zip';source.write_bytes(b);restored=Path(d)/'restored'
        assert restore(source,restored)['cards']==1 and not (restored/'members.json').exists()
        with zipfile.ZipFile(source) as z:
            assert (restored/'state.json').read_bytes()==z.read('state.json') and (restored/'plans.json').read_bytes()==z.read('plans.json')
        second=subprocess.Popen([sys.argv[1],str(restored)],stdout=subprocess.PIPE,text=True)
        try:
            newlines=[second.stdout.readline() for _ in range(5)];newurl=newlines[1].split('URL: ')[1].strip();newpw=newlines[3].split('Password: ')[1].strip()
            import base64
            auth='Basic '+base64.b64encode(('admin:'+newpw).encode()).decode()
            with urllib.request.urlopen(urllib.request.Request(newurl+'?view=cards',headers={'Authorization':auth}),timeout=5) as response:
                import html; assert response.status==200 and '=1+1' in html.unescape(response.read().decode())
        finally:second.send_signal(signal.SIGINT);second.wait(timeout=7)
        print('PASS authenticated operator attribution and actual backup restore into new running instance')
        code,_,b=req(owner,'export',{'csrf':token});assert code==200 and b"'=1+1" in b
        print('PASS actual ZIP business backup, manifest integrity and safe CSV export')
    finally:p.send_signal(signal.SIGINT);p.wait(timeout=7)
