"""Verify a local business backup and restore only into a NEW directory."""
import argparse, hashlib, json, os, stat, sys, zipfile
from pathlib import Path
from rehearse import MAX_BYTES, InvalidState, require, rows_from, unique_object, timestamp, integer

NAMES = {'state.json','plans.json','manifest.json'}
PLANS = [(1,'日卡 · 1 天'),(7,'周卡 · 7 天'),(30,'月卡 · 30 天'),(90,'季卡 · 90 天'),(365,'年卡 · 365 天'),(0,'永久卡')]

def strict_json(raw):
    return json.loads(raw,object_pairs_hook=unique_object,parse_constant=lambda _: (_ for _ in ()).throw(InvalidState('invalid JSON number')))

def verify(source):
    source=Path(source)
    require(source.is_file() and not source.is_symlink(),'backup must be a regular file')
    require(source.stat().st_size<=MAX_BYTES,'backup too large')
    with zipfile.ZipFile(source) as z:
        entries=z.infolist()
        require(len(entries)==3 and {i.filename for i in entries}==NAMES,'unexpected or duplicate backup entries')
        require(sum(i.file_size for i in entries)<=MAX_BYTES,'uncompressed backup too large')
        data={}
        for i in entries:
            require(not i.is_dir() and not stat.S_ISLNK(i.external_attr>>16) and not i.flag_bits&1,'invalid backup entry')
            limit=MAX_BYTES if i.filename=='state.json' else 65536
            require(i.file_size<=limit,'entry too large')
            with z.open(i) as f: raw=f.read(limit+1)
            require(len(raw)==i.file_size,'entry size mismatch')
            data[i.filename]=raw
    m=strict_json(data['manifest.json'])
    require(isinstance(m,dict) and set(m)=={'Format','Created','SHA256'} and type(m['Format']) is int and m['Format']==1,'invalid manifest')
    timestamp(m['Created'])
    require(isinstance(m['SHA256'],dict) and set(m['SHA256'])==NAMES-{'manifest.json'},'invalid digest list')
    for name in NAMES-{'manifest.json'}:
        require(m['SHA256'][name]==hashlib.sha256(data[name]).hexdigest(),'digest mismatch')
    _,cards,audits=rows_from(data['state.json'])
    plans=strict_json(data['plans.json'])
    require(isinstance(plans,list) and len(plans)==len(PLANS),'invalid plans')
    for p,(days,name) in zip(plans,PLANS):
        require(isinstance(p,dict) and set(p)=={'Days','Name','PriceCents','Visible'} and type(p['Days']) is int and p['Days']==days and p['Name']==name and type(p['Visible']) is bool and (p['PriceCents'] is None or integer(p['PriceCents'],0,100000000)),'invalid plan configuration')
    return data, len(cards), len(audits)

def restore(source,destination):
    data,cards,audits=verify(source)
    destination=Path(destination)
    # Never write into an existing directory, even if empty. No archive extraction.
    destination.mkdir(mode=0o700)
    try:
        for name in ('state.json','plans.json'):
            fd=os.open(destination/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'wb') as f:
                f.write(data[name]); f.flush(); os.fsync(f.fileno())
            require((destination/name).read_bytes()==data[name],'restore verification failed')
    except BaseException:
        for name in ('state.json','plans.json'):
            (destination/name).unlink(missing_ok=True)
        destination.rmdir()
        raise
    return {'result':'RESTORE_TO_NEW_DIRECTORY_PASS','cards':cards,'audit':audits,'members_restored':False}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('backup',type=Path);p.add_argument('destination',type=Path);args=p.parse_args()
    try: print(json.dumps(restore(args.backup,args.destination),ensure_ascii=False))
    except (InvalidState,OSError,ValueError,RuntimeError,zipfile.BadZipFile,NotImplementedError,OverflowError,RecursionError) as e:
        print('Restore refused: '+(str(e) if isinstance(e,InvalidState) else type(e).__name__),file=sys.stderr);return 1
    return 0
if __name__=='__main__':sys.exit(main())
