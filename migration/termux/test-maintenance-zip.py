#!/usr/bin/env python3
import contextlib
import hashlib
import io
import pathlib
import stat
import tempfile
import unittest
import warnings
import zipfile
from importlib.machinery import SourceFileLoader
v = SourceFileLoader("verify_maintenance", str(pathlib.Path(__file__).with_name("verify-maintenance-zip.py"))).load_module()

class VerificationTests(unittest.TestCase):
    def test_exact_archive(self):
        checkout = "a" * 40
        files = {name: b"fixture" for name in v.FILES}
        files["source-commit.txt"] = (checkout + "\n").encode()
        files["NOTICE"] = b"UNSIGNED LOCAL TEST ONLY; NO TUNNEL OR PUBLIC DEPLOYMENT\n"
        manifest = "".join(hashlib.sha256(data).hexdigest() + "  " + name + "\n"
                           for name, data in sorted(files.items())).encode()
        entries = list(files.items()) + [("SHA256SUMS", manifest)]
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "fixture.zip"
            def check(items, expected=checkout, reject=False):
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    with zipfile.ZipFile(path, "w") as archive:
                        for name, data in items:
                            archive.writestr(name, data)
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                if reject:
                    with self.assertRaises(ValueError):
                        v.verify(path, digest, expected)
                else:
                    with contextlib.redirect_stdout(io.StringIO()):
                        v.verify(path, digest, expected)
            check(entries)
            with self.assertRaises(ValueError):
                v.verify(path, "0"*64, checkout)
            check(entries, "b"*40, True)
            check(entries + [("../escape", b"bad")], reject=True)
            check(entries + [entries[0]], reject=True)
            check(entries[:-1], reject=True)
            # A legacy archive without the observer must not be silently accepted,
            # even when its manifest is recomputed consistently.
            legacy = {name: data for name, data in files.items()
                      if name != "gateway-status-observer.py"}
            legacy_manifest = "".join(hashlib.sha256(data).hexdigest() + "  " + name + "\n"
                                      for name, data in sorted(legacy.items())).encode()
            check(list(legacy.items()) + [("SHA256SUMS", legacy_manifest)], reject=True)
            check([(name, b"tamper" if name == "gateway-status-observer.py" else data)
                   for name, data in entries], reject=True)
            check([(name, b"tamper" if name == "GATEWAY.md" else data)
                   for name, data in entries], reject=True)
            link = zipfile.ZipInfo("GATEWAY.md")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            check([(link if name == "GATEWAY.md" else name, data)
                   for name, data in entries], reject=True)

if __name__ == "__main__":
    unittest.main()
