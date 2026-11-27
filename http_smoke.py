import subprocess,tempfile,urllib.request,urllib.parse,urllib.error,base64,re,html,signal,sys
with tempfile.TemporaryDirectory() as d:
 p=subprocess.Popen([sys.argv[1],d],stdout=subprocess.PIPE,text=True)
 try:
  lines=[p.stdout.readline() for _ in range(5)]; url=lines[1].split('URL: ')[1].strip(); origin=url.rstrip('/'); pw=lines[3].split('Password: ')[1].strip(); auth='Basic '+base64.b64encode(('admin:'+pw).encode()).decode()
  def request(data=None,o=None,path="",authenticated=True):
   h={'Authorization':auth} if authenticated else {};
   if o is not None:h['Origin']=o
   req=urllib.request.Request(url+path,data=None if data is None else urllib.parse.urlencode(data).encode(),headers=h)
   try:
    with urllib.request.urlopen(req,timeout=4) as r:return r.status,r.headers,r.read().decode()
   except urllib.error.HTTPError as r:return r.code,r.headers,r.read().decode()
  status,h,b=request(path="?view=issue"); assert status==200 and h['Referrer-Policy']=='same-origin'; csrf=re.search(r'name="csrf" value="([^"]+)"',b)[1]; print('PASS actual HTTP GET same-origin policy')
  issue={'csrf':csrf,'action':'issue','days':30,'quantity':1,'amount_yuan':'0.00','sale_ref':'smoke-p01','channel':'test','confirmed':'yes'}
  for o in ['null','http://evil.test',origin+':1']:
   assert request(issue,o)[0]==403
  page=request(path="?view=cards")[2]; assert '卡密管理' in page and '无匹配记录' in page; print('PASS 3 invalid origins rejected; no card created')
  status,h,b=request(issue,origin);assert status==200 and '已生成' in b and '本次生成的卡密' in b; key=html.unescape(re.search(r'<textarea readonly aria-label="生成卡密">(.*?)</textarea>',b,re.S)[1]).strip(); print('PASS same-origin issue and rendered card')
  status,h,b=request(path="activate",authenticated=False);assert status==200 and '购买卡密可添加 QQ' in b and '卡密记录' not in b and csrf not in b; user_csrf=re.search(r'name="csrf" value="([^"]+)"',b)[1];assert user_csrf!=csrf and request(authenticated=False)[0]==401;print('PASS independent user route and admin isolation')
  def post(data,expected):
   is_user=data.get('action')=='validate';status,h,b=request(dict(data,csrf=user_csrf if is_user else csrf),origin,path='activate' if is_user else '',authenticated=not is_user);assert status==200 and expected in b and b.endswith('</html>\n'),(status,expected,b[-150:]);return b
  post({'action':'validate','key':key,'device':'A'},'授权验证成功');post({'action':'validate','key':key,'device':'B'},'device_mismatch');print('PASS activation and foreign device rejection')
  post({'action':'qq','qq':'123456789'},'客服配置已保存');id=re.search(r'name="id" value="([^"]+)"',request(path='?view=cards')[2])[1];print('PASS QQ configuration')
  post({'action':'unbind','id':id},'操作完成');post({'action':'validate','key':key,'device':'B'},'授权验证成功');print('PASS unbind and rebind')
  post({'action':'revoke','id':id},'操作完成');post({'action':'validate','key':key,'device':'B'},'revoked');print('PASS revocation')
  status,h,b=request(dict(issue,sale_ref='batch-p1',preset='7',quantity=25),origin);assert status==200 and len(html.unescape(re.search(r'<textarea readonly aria-label="生成卡密">(.*?)</textarea>',b,re.S)[1]).split())==25 and b.endswith('</html>\n'); cards=request(path='?view=cards')[2]; assert '共 26 张卡密' in cards and '第 1 / 2 页' in cards; print('PASS batch issue and pagination')
  status,h,b=request(path='?q=batch-p1&page=2');assert status==200 and '匹配 25 条' in b and '第 2 / 2 页' in b; ids=re.findall(r'name="ids" value="([^"]+)"',b);assert len(ids)==5;print('PASS search and second page')
  payload={'csrf':csrf,'action':'batch-revoke','ids':ids,'confirm_batch':'yes'}; raw=urllib.parse.urlencode(payload,doseq=True).encode();req=urllib.request.Request(url,data=raw,headers={'Authorization':auth,'Origin':origin});
  with urllib.request.urlopen(req,timeout=4) as r: assert r.status==200 and '批量操作完成' in r.read().decode()
  assert '匹配 5 条' in request(path='?q=batch-p1&status='+urllib.parse.quote('已吊销'))[2];print('PASS atomic batch revoke and status filter')
  assert '123456789' in request(path='activate',authenticated=False)[2]; print('PASS QQ visible to user without admin credentials')
 finally:
  p.send_signal(signal.SIGINT);p.wait(timeout=7)
