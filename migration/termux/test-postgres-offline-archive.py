#!/usr/bin/env python3
"""Real PostgreSQL 18 offline archive fixture; disposable cluster only."""
import gzip
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import time

here = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("retention", here / "postgres-log-retention.py")
retention = importlib.util.module_from_spec(spec)
spec.loader.exec_module(retention)

def run(*args):
    return subprocess.run(list(map(str,args)), check=True, timeout=45,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout.strip()

def hashes(folder):
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in folder.iterdir() if p.is_file()}

def main():
    os.umask(0o077)
    assert os.getuid() != 0
    with tempfile.TemporaryDirectory(prefix="chezhi-pg18-archive-") as tmp:
        root=Path(tmp)
        pg=root/"pgdata"
        ctl=root/"managed-v1"
        ctl.mkdir(mode=0o700)
        (ctl/"installed").write_text("managed-v1\n")
        run("initdb","-D",pg,"-U","postgres","--auth=trust","--no-locale","--encoding=UTF8")
        with (pg/"postgresql.conf").open("a") as conf:
            conf.write("\n"+(here/"postgres-logging.candidate.conf").read_text())
            conf.write(f"\nlisten_addresses = ''\nunix_socket_directories = '{root}'\n")
        def start():
            run("pg_ctl","-D",pg,"-l",root/"postgres.log","-w","-t","20","start")
        def stop():
            run("pg_ctl","-D",pg,"-w","-t","20","-m","fast","stop")
        def sql(statement):
            return run("psql","-X","-At","-v","ON_ERROR_STOP=1","-h",root,
                       "-U","postgres","-d","postgres","-c",statement)
        logs=pg/"chezhi-pg-log"
        try:
            start()
            assert int(sql("SHOW server_version_num"))//10000==18
            sql("CREATE TABLE recovery_fixture(id integer PRIMARY KEY); INSERT INTO recovery_fixture VALUES (17)")
            active=retention.current(pg)
            now=time.time()
            synthetic={}
            for i in range(10):
                path=logs/f"postgresql-20000101-0000{i:02}.log"
                data=f"disposable historical log {i}\n".encode()
                path.write_bytes(data)
                os.utime(path,(now-(20-i)*86400,)*2)
                synthetic[path.name]=data
            try:
                retention.archive_offline(root,time.time())
            except ValueError as exc:
                assert str(exc)=="database PID marker present"
            else:
                raise AssertionError("active PostgreSQL archive unexpectedly allowed")
            assert all((logs/name).read_bytes()==data for name,data in synthetic.items())
            stop()
            assert not (pg/"postmaster.pid").exists()
            before=hashes(logs)
            legacy=(root/"postgres.log").read_bytes()
            if not (pg/"current_logfiles").exists():
                # A missing native pointer must be a HOLD, not inferred
                # from timestamps or from the previous online observation.
                try:
                    retention.archive_offline(root,time.time())
                except FileNotFoundError:
                    pass
                else:
                    raise AssertionError("missing native pointer accepted")
                assert hashes(logs)==before
                print("PG18_OFFLINE_POINTER_ABSENT_HOLD no cleanup performed",flush=True)
            else:
                assert retention.current(pg)==active
                _,eligible=retention.inventory(root,time.time(),selected=True)
                assert eligible and all(name in synthetic for _,name,_ in eligible)
                expected={name for _,name,_ in eligible}
                result=retention.archive_offline(root,time.time())
                assert result["archived"]==len(expected)
                assert set(hashes(logs))==set(before)-expected
                assert hashes(logs)=={n:d for n,d in before.items() if n not in expected}
                archives=root/"pg-log-archives"
                for name in expected:
                    data=synthetic[name]
                    archive=archives/(name+"."+hashlib.sha256(data).hexdigest()+".gz")
                    assert gzip.decompress(archive.read_bytes())==data
                    assert archive.stat().st_mode & 0o777==0o600
                assert retention.archive_offline(root,time.time())["archived"]==0
                print(f"PASS PG18_OFFLINE_ARCHIVE actual pg_ctl stopped, archived={len(expected)}, protected logs and exact readback",flush=True)
            assert (root/"postgres.log").read_bytes()==legacy
            start()
            assert sql("SELECT id FROM recovery_fixture")=="17"
            stop()
            print("PASS PG18_OFFLINE_ARCHIVE_RESTART preserved fixture data",flush=True)
        finally:
            if (pg/"postmaster.pid").exists():
                stop()

if __name__=="__main__":
    main()
