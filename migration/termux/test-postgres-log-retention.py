#!/usr/bin/env python3
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("retention", Path(__file__).with_name("postgres-log-retention.py"))
retention = importlib.util.module_from_spec(spec)
spec.loader.exec_module(retention)

class RetentionTests(unittest.TestCase):
    def test_inventory(self):
        now = 1795900000
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pg = root / "pgdata"
            pg.mkdir(mode=0o700)
            legacy = root / "postgres.log"
            legacy.write_bytes(b"legacy fixture")
            self.assertEqual(retention.inventory(root, now)["state"], "COLLECTOR_NOT_CONFIGURED")
            logs = pg / "chezhi-pg-log"
            logs.mkdir(mode=0o700)
            files = []
            for i in range(10):
                path = logs / f"postgresql-20261101-0000{i:02}.log"
                path.write_bytes(b"fixture")
                path.chmod(0o600)
                stamp = now - (20-i)*86400
                os.utime(path, (stamp, stamp))
                files.append(path)
            pointer = pg / "current_logfiles"
            pointer.write_text(f"stderr chezhi-pg-log/{files[0].name}\n")
            result = retention.inventory(root, now)
            self.assertEqual(result["files"], 10)
            self.assertEqual(result["collector_bytes"], 70)
            self.assertEqual(result["eligible_count"], 2)
            self.assertEqual(result["eligible_bytes"], 14)
            self.assertEqual(result["legacy_log_bytes"], 14)
            # The oldest active log must remain excluded; all files stay intact.
            self.assertEqual(len(list(logs.iterdir())), 10)
            pointer.write_text("stderr ../../outside.log\n")
            with self.assertRaises(ValueError):
                retention.inventory(root, now)
            pointer.write_text(f"stderr chezhi-pg-log/{files[0].name}\n")
            bad = logs / "postgresql-20261101-010101.log"
            bad.symlink_to(legacy)
            with self.assertRaises(ValueError):
                retention.inventory(root, now)
            bad.unlink()
            os.link(files[0], bad)
            with self.assertRaises(ValueError):
                retention.inventory(root, now)
            bad.unlink()
            files[-1].chmod(0o644)
            with self.assertRaises(ValueError):
                retention.inventory(root, now)
            files[-1].chmod(0o600)
            os.utime(files[-1], (now+1,now+1))
            with self.assertRaises(ValueError):
                retention.inventory(root, now)
            os.utime(files[-1], (now-1,now-1))
            with files[-1].open("r+b") as stream:
                stream.truncate(retention.BUDGET+1)
            result = retention.inventory(root, now)
            self.assertTrue(result["collector_over_budget"])
            self.assertTrue(result["total_log_over_budget"])
            self.assertEqual(files[0].read_bytes(), b"fixture")
            self.assertEqual(legacy.read_bytes(), b"legacy fixture")

if __name__ == "__main__":
    unittest.main()
