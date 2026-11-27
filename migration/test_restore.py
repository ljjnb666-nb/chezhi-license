import hashlib,json,tempfile,unittest,zipfile,warnings
from pathlib import Path
from restore_backup import restore,PLANS,InvalidState

class RestoreTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name);self.src=self.root/'backup.zip';self.dest=self.root/'restored'
        self.state={'QQ':'----------','Cards':None,'Audit':None}
        self.plans=[{'Days':d,'Name':n,'PriceCents':None,'Visible':True} for d,n in PLANS]
    def archive(self,change=None):
        files={'state.json':json.dumps(self.state).encode(),'plans.json':json.dumps(self.plans).encode()}
        files['manifest.json']=json.dumps({'Format':1,'Created':'2026-01-01T00:00:00Z','SHA256':{n:hashlib.sha256(b).hexdigest() for n,b in files.items()}}).encode()
        if change:change(files)
        with zipfile.ZipFile(self.src,'w') as z:
            for n,b in files.items():z.writestr(n,b)
    def reject(self):
        with self.assertRaises((InvalidState,ValueError,zipfile.BadZipFile)):restore(self.src,self.dest)
        self.assertFalse(self.dest.exists())
    def test_valid(self):
        self.archive();before=self.src.read_bytes();self.assertEqual(restore(self.src,self.dest)['cards'],0);self.assertEqual(before,self.src.read_bytes());self.assertEqual(json.loads((self.dest/'plans.json').read_bytes()),self.plans)
    def test_existing(self):
        self.archive();self.dest.mkdir();(self.dest/'keep').touch()
        with self.assertRaises(FileExistsError):restore(self.src,self.dest)
        self.assertTrue((self.dest/'keep').exists())
    def test_digest(self):self.archive(lambda f:f.update({'state.json':b'{}'}));self.reject()
    def test_traversal(self):self.archive(lambda f:f.update({'../outside':b'x'}));self.reject();self.assertFalse((self.root/'outside').exists())
    def test_duplicate(self):
        self.archive()
        with warnings.catch_warnings():
            warnings.simplefilter('ignore');
            with zipfile.ZipFile(self.src,'a') as z:z.writestr('state.json',b'{}')
        self.reject()
    def test_bad_plan(self):self.plans[0]['PriceCents']=-1;self.archive();self.reject()
    def test_bad_state(self):self.state['QQ']='x';self.archive();self.reject()
    def test_member_excluded(self):self.archive(lambda f:f.update({'members.json':b'[]'}));self.reject()
    def test_actor_roundtrip(self):
        self.state['Audit']=[{'At':'2026-01-01T00:00:00Z','Action':'member-create','CardID':'','Actor':'admin','Target':'staff1'}];self.archive();restore(self.src,self.dest);self.assertEqual(json.loads((self.dest/'state.json').read_bytes()),self.state)
if __name__=='__main__':unittest.main(verbosity=2)
