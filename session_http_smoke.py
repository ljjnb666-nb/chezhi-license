import subprocess, tempfile, signal, sys, re, urllib.request, urllib.parse, urllib.error, http.cookiejar
with tempfile.TemporaryDirectory() as d:
    p=subprocess.Popen([sys.argv[1],d],stdout=subprocess.PIPE,text=True)
    try:
        lines=[p.stdout.readline() for _ in range(5)]; url=lines[1].split('URL: ')[1].strip(); pw=lines[3].split('Password: ')[1].strip()
        jar=http.cookiejar.CookieJar(); op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        def req(path='', fields=None, origin=None, opener=op):
            h={'Accept':'text/html'}
            if fields is not None:h['Origin']=origin or url.rstrip('/')
            r=urllib.request.Request(url+path, data=urllib.parse.urlencode(fields).encode() if fields is not None else None,headers=h)
            try:
                with opener.open(r,timeout=5) as x:return x.status,x.geturl(),x.read().decode()
            except urllib.error.HTTPError as e:return e.code,e.geturl(),e.read().decode()
        status,where,b=req();assert status==200 and where.endswith('/login'); token=re.search(r'name="login_csrf" value="([^"]+)"',b)[1]
        f={'username':'admin','password':pw,'login_csrf':token};assert req('login',f,'http://evil.test')[0]==403
        assert req('login',dict(f,password='wrong'))[0]==401
        status,where,b=req('login',f);assert status==200 and '<h1>概览</h1>' in b and len(list(jar))==1
        print('PASS browser-style login redirect, origin check, bad password and cookie session')
        b=req('?view=plans')[2]; csrf=re.search(r'name="csrf" value="([^"]+)"',b)[1]
        fields={'csrf':csrf,'action':'plans'}
        for k in [1,7,30,90,365,0]:fields['price_'+str(k)]='';fields['visible_'+str(k)]='yes'
        fields['price_30']='9.90';del fields['visible_365']
        assert '套餐设置已保存' in req('?view=plans',fields)[2]
        public=req('purchase',opener=urllib.request.build_opener())[2];assert '¥9.90' in public and '年卡' not in public and csrf not in public
        assert 'data-price="9.90"' in req('?view=issue')[2]
        print('PASS catalog save, public visibility, reference price and private token isolation')
        saved=list(jar)[0];assert req('logout',{'logout_csrf':'wrong'})[0]==403
        assert req('logout',{'logout_csrf':csrf})[1].endswith('/login')
        jar.set_cookie(saved);assert req()[1].endswith('/login')
        print('PASS logout CSRF protection and old session replay rejection')
    finally:p.send_signal(signal.SIGINT);p.wait(timeout=7)
