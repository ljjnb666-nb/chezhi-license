"""Generate real test state through local HTTP, stop server, rehearse DB migration."""
import base64, html, json, re, signal, sqlite3, subprocess, sys, tempfile
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.parse import urlencode
from rehearse import rehearse

with tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp); data=root/'data'; db=root/'stage.db'
    p=subprocess.Popen([str(Path(sys.argv[1]).resolve()),str(data)],stdout=subprocess.PIPE,text=True)
    try:
        lines=[p.stdout.readline() for _ in range(5)]
        url=lines[1].split('URL: ')[1].strip(); password=lines[3].split('Password: ')[1].strip()
        auth='Basic '+base64.b64encode(('admin:'+password).encode()).decode()
        def request(path='',fields=None,admin=True):
            headers={'Authorization':auth} if admin else {}
            if fields is not None: headers['Origin']=url.rstrip('/')
            with urlopen(Request(url+path,headers=headers,data=urlencode(fields).encode() if fields is not None else None),timeout=5) as r:
                return r.read().decode()
        csrf=re.search(r'name="csrf" value="([^"]+)"',request('?view=issue'))[1]
        page=request(fields=dict(csrf=csrf,action='issue',days=30,quantity=2,amount=0,channel='test',sale_ref='migration-runtime-test',confirmed='yes'))
        keys=html.unescape(re.search(r'<textarea readonly aria-label="生成卡密">(.*?)</textarea>',page,re.S)[1]).split()
        assert len(keys)==2
        usercsrf=re.search(r'name="csrf" value="([^"]+)"',request('activate',admin=False))[1]
        assert '授权验证成功' in request('activate',dict(csrf=usercsrf,key=keys[0],device='A'),False)
        state=json.loads((data/'state.json').read_bytes()); first=state['Cards'][0]
        assert '操作完成' in request(fields=dict(csrf=csrf,action='revoke',id=first['id']))
        assert '客服配置已保存' in request(fields=dict(csrf=csrf,action='qq',qq='123456789'))
    finally:
        p.send_signal(signal.SIGINT); p.wait(timeout=8)
    source=data/'state.json'; raw=source.read_bytes(); result=rehearse(source,db)
    assert source.read_bytes()==raw and result['cards']==2 and result['audit']==5
    with sqlite3.connect(db) as conn:
        assert conn.execute('select activated,expires,revoked from staged_cards where ordinal=0').fetchone()==(first['activated'],first['expires'],1)
        assert conn.execute('select activated,expires,revoked from staged_cards where ordinal=1').fetchone()==(None,None,0)
        assert conn.execute('select qq from migration_meta').fetchone()==('123456789',)
    assert all(key.encode() not in db.read_bytes() for key in keys)
    print('PASS actual runtime state -> SQLite staging: 2 cards, 5 audit events, timestamps, revocation, QQ, source unchanged, no raw test keys')
