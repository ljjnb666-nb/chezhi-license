from contextlib import closing
import copy, hashlib, json, sqlite3, tempfile, unittest
from pathlib import Path
from rehearse import rehearse, InvalidState, rows_from

class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name); self.src=self.root/'state.json'; self.dest=self.root/'staging.db'
        h=hashlib.sha256(b'test-only').hexdigest(); self.cid=h[:24]
        self.state={'QQ':'----------','Cards':[{'id':self.cid,'hash':h,'prefix':'ABCDE','days':30,'sale_ref':'test-order','channel':'test','amount_cents':0,'created':'2026-01-01T00:00:00Z','activated':'2026-01-02T00:00:00.123456789Z','expires':'2026-02-01T00:00:00.123456789Z','device_hash':'a'*64,'revoked':True}],'Audit':[{'At':'2026-01-01T00:00:00Z','Action':'issue','CardID':self.cid},{'At':'2026-01-02T00:00:00Z','Action':'bind','CardID':self.cid},{'At':'2026-01-03T00:00:00Z','Action':'revoke','CardID':self.cid}]}
    def save(self): self.src.write_text(json.dumps(self.state),encoding='utf-8')
    def reject(self):
        self.save(); before=self.src.read_bytes()
        with self.assertRaises(InvalidState): rehearse(self.src,self.dest)
        self.assertFalse(self.dest.exists()); self.assertEqual(before,self.src.read_bytes())
    def test_roundtrip(self):
        self.save(); before=self.src.read_bytes(); r=rehearse(self.src,self.dest)
        self.assertEqual((r['cards'],r['audit']),(1,3)); self.assertFalse(r['production_migrated']); self.assertEqual(before,self.src.read_bytes())
        with closing(sqlite3.connect(self.dest)) as c, c:
            self.assertEqual(c.execute('select expires,revoked from staged_cards').fetchone(),('2026-02-01T00:00:00.123456789Z',1))
    def test_empty(self): self.state={'QQ':'----------','Cards':None,'Audit':None}; self.save(); self.assertEqual(rehearse(self.src,self.dest)['cards'],0)
    def test_no_overwrite(self):
        self.save(); self.dest.write_bytes(b'keep');
        with self.assertRaises(FileExistsError): rehearse(self.src,self.dest)
        self.assertEqual(self.dest.read_bytes(),b'keep')
    def test_running_instance(self): self.save(); (self.root/'instance.lock').touch(); self.reject()
    def test_duplicate(self): self.state['Cards'].append(copy.deepcopy(self.state['Cards'][0])); self.reject()
    def test_orphan_audit(self): self.state['Audit'][0]['CardID']='0'*24; self.reject()
    def test_expiry_changed(self): self.state['Cards'][0]['expires']='2026-02-01T00:00:00.123456780Z'; self.reject()
    def test_plaintext_field(self): self.state['Cards'][0]['key']='should-not-be-copied'; self.reject()
    def test_invalid_device_type(self): self.state['Cards'][0]['device_hash']=False; self.reject()
    def test_unactivated_with_device(self): del self.state['Cards'][0]['activated']; self.reject()
    def test_duplicate_json_property(self):
        with self.assertRaises(InvalidState): rows_from(b'{"QQ":"----------","QQ":"12345","Cards":[],"Audit":[]}')
    def test_batch_conflict(self):
        c=copy.deepcopy(self.state['Cards'][0]); c.update(hash='b'*64,id='b'*24,amount_cents=2); self.state['Cards'].append(c); self.reject()
    def test_db_constraints(self):
        self.save(); rehearse(self.src,self.dest)
        with closing(sqlite3.connect(self.dest)) as c, c:
            c.execute('pragma foreign_keys=on')
            with self.assertRaises(sqlite3.IntegrityError): c.execute('update staged_cards set days=-1')
            with self.assertRaises(sqlite3.IntegrityError): c.execute("insert into staged_audit values (9,'x','bind','bad',NULL,NULL)")
if __name__=='__main__': unittest.main(verbosity=2)
