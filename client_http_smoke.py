import base64, html, json, re, signal, subprocess, sys, tempfile, urllib.request, urllib.parse, urllib.error
with tempfile.TemporaryDirectory() as d:
    p=subprocess.Popen([sys.argv[1],d],stdout=subprocess.PIPE,text=True)
    try:
        lines=[p.stdout.readline() for _ in range(5)]
        url=lines[1].split('URL: ')[1].strip(); origin=url.rstrip('/'); pw=lines[3].split('Password: ')[1].strip()
        auth='Basic '+base64.b64encode(('admin:'+pw).encode()).decode()
        def req(path='', data=None, headers=None):
            r=urllib.request.Request(url+path,data=data,headers=headers or {})
            try:
                with urllib.request.urlopen(r,timeout=4) as response: return response.status,response.read().decode()
            except urllib.error.HTTPError as e:return e.code,e.read().decode()
        code, page=req('?view=issue',headers={'Authorization':auth}); assert code==200
        csrf=re.search(r'name="csrf" value="([^"]+)"',page)[1]
        assert all(x in page for x in ('view=overview','view=issue','view=cards','view=audit','view=settings','/purchase'))
        def admin(data):return req(data=urllib.parse.urlencode(dict(data,csrf=csrf)).encode(),headers={'Authorization':auth,'Origin':origin})
        code,page=admin({'action':'issue','days':30,'quantity':1,'amount':0,'channel':'test','sale_ref':'p12-smoke','confirmed':'yes'});assert code==200
        key=html.unescape(re.search(r'<textarea readonly aria-label="生成卡密">(.*?)</textarea>',page,re.S)[1]).strip()
        id=re.search(r'name="id" value="([^"]+)"',req('?view=cards',headers={'Authorization':auth})[1])[1]
        assert admin({'action':'qq','qq':'123456789'})[0]==200
        code,page=req('purchase'); assert code==200 and '123456789' in page and '永久卡' in page and csrf not in page and key not in page and 'p12-smoke' not in page
        assert req('purchase',b'')[0]==405 and req()[0]==401
        print('PASS purchase page, QQ configuration, navigation and admin isolation')
        def activate(device,extra=None):
            headers={'Content-Type':'application/json'}; headers.update(extra or {})
            return req('api/demo/activate',json.dumps({'key':key,'device':device}).encode(),headers)
        assert activate('A',{'Origin':'null'})[0]==403 and activate('A',{'Origin':'http://evil.test'})[0]==403
        assert req('api/demo/activate',b'{}',{'Content-Type':'text/plain'})[0]==415
        print('PASS native API rejects browser-origin and non-JSON requests')
        code,b=activate('A');assert code==200 and json.loads(b)['valid'] and json.loads(b)['expiry'] and key not in b
        code,b=activate('B');assert code==200 and json.loads(b)['reason']=='device_mismatch'
        print('PASS native activation and foreign device denial')
        assert admin({'action':'revoke','id':id})[0]==200
        code,b=activate('A');assert code==200 and json.loads(b)['reason']=='revoked'
        print('PASS native API honors revocation')
    finally:
        p.send_signal(signal.SIGINT); p.wait(timeout=7)
