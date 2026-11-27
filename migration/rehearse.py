"""Offline migration rehearsal for CheZhi License local test data. Python stdlib only."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import sys

MAX_BYTES = 64 * 1024 * 1024
HEX = re.compile(r'[0-9a-f]+\Z')
PREFIX = re.compile(r'[0-9ABCDEFGHJKMNPQRSTVWXYZ]{5}\Z')
QQ = re.compile(r'(?:[0-9]{5,12}|----------)\Z')
CARD_KEYS = {'id','hash','prefix','days','sale_ref','channel','amount_cents','created','revoked'}
OPTIONAL = {'activated','expires','device_hash'}
CARD_ACTIONS = {'issue','bind','unbind','revoke'}
MEMBER_ACTIONS = {'member-create','member-reset','member-role','member-disable','member-enable'}
ACTIONS = CARD_ACTIONS | MEMBER_ACTIONS | {'support_config','plans_config','login_success','login_failed','logout','logout_all','password_changed','password_failed'}
ACTOR = re.compile(r'[a-zA-Z][a-zA-Z0-9_-]{2,31}\Z')

class InvalidState(ValueError):
    pass

def require(condition, message):
    if not condition:
        raise InvalidState(message)

def unique_object(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out, 'duplicate JSON property')
        out[key] = value
    return out

def hex_value(value, size):
    return isinstance(value,str) and len(value)==size and HEX.fullmatch(value) is not None

def integer(value, lo, hi):
    return type(value) is int and lo <= value <= hi

def timestamp(value):
    require(isinstance(value,str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})',value) is not None,'invalid timestamp')
    try:
        return dt.datetime.fromisoformat(value.replace('Z','+00:00')).astimezone(dt.timezone.utc)
    except ValueError:
        raise InvalidState('invalid timestamp') from None

def nanos_tail(value):
    match=re.search(r"\.(\d+)",value)
    return (match.group(1) if match else "").ljust(9,"0")[6:9]

def rows_from(raw):
    try:
        state=json.loads(raw,object_pairs_hook=unique_object,parse_constant=lambda _: (_ for _ in ()).throw(InvalidState('invalid JSON number')))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise InvalidState('invalid JSON') from None
    require(isinstance(state,dict) and set(state)=={'QQ','Cards','Audit'},'unexpected state fields')
    require(isinstance(state['QQ'],str) and QQ.fullmatch(state['QQ']), 'invalid QQ configuration')
    cards=[]; audits=[]; ids=set(); hashes=set(); orders={}
    source_cards=state['Cards'] if state['Cards'] is not None else []
    source_audit=state['Audit'] if state['Audit'] is not None else []
    require(isinstance(source_cards,list) and isinstance(source_audit,list),'invalid record lists')
    for i,c in enumerate(source_cards):
        require(isinstance(c,dict) and CARD_KEYS <= set(c) <= CARD_KEYS|OPTIONAL,'unexpected card fields')
        h=c['hash']; cid=c['id']; prefix=c['prefix']; days=c['days']; ref=c['sale_ref']; channel=c['channel']; amount=c['amount_cents']; revoked=c['revoked']
        require(hex_value(h,64) and hex_value(cid,24) and cid==h[:24],'invalid card hash or ID')
        require(cid not in ids and h not in hashes,'duplicate card ID or hash')
        require(isinstance(prefix,str) and PREFIX.fullmatch(prefix),'invalid card prefix')
        require(integer(days,0,3650) and integer(amount,0,100000000) and type(revoked) is bool,'invalid card plan or amount')
        require(isinstance(ref,str) and 1<=len(ref.encode('utf-8'))<=80 and ref.strip()==ref and '\x00' not in ref,'invalid order reference')
        require(isinstance(channel,str) and channel in {'test','wechat','alipay'},'invalid channel')
        order=(days,channel,amount,c['created']); require(ref not in orders or orders[ref]==order,'inconsistent batch order'); orders[ref]=order
        created=timestamp(c['created']); activated=c.get('activated'); expires=c.get('expires'); device=c.get('device_hash'); device=None if device=='' else device
        require(device is None or hex_value(device,64),'invalid device hash')
        if activated is None:
            require(expires is None and device is None,'unactivated card contains activation data')
        else:
            start=timestamp(activated); require(start>=created,'activation precedes issuance')
            if days==0: require(expires is None,'perpetual card has expiry')
            else: require(expires is not None and timestamp(expires)==start+dt.timedelta(days=days) and nanos_tail(expires)==nanos_tail(activated),'expiry differs from original plan')
        ids.add(cid); hashes.add(h)
        cards.append((i,cid,h,prefix,days,ref,channel,amount,c['created'],activated,expires,device,int(revoked)))
    for i,a in enumerate(source_audit):
        require(isinstance(a,dict) and {'At','Action','CardID'} <= set(a) <= {'At','Action','CardID','Actor','Target'},'unexpected audit fields')
        timestamp(a['At']); action=a['Action']; cid=a['CardID']
        require(isinstance(action,str) and action in ACTIONS,'invalid audit action')
        require(isinstance(cid,str) and (cid in ids if action in CARD_ACTIONS else cid==''),'orphan audit record')
        actor=a.get('Actor',''); target=a.get('Target','')
        require(isinstance(actor,str) and (actor=='' or ACTOR.fullmatch(actor)), 'invalid audit actor')
        require(isinstance(target,str) and (ACTOR.fullmatch(target) if action in MEMBER_ACTIONS else target==''), 'invalid audit target')
        audits.append((i,a['At'],action,cid or None,actor or None,target or None))
    return state['QQ'],cards,audits

def read_source(source):
    require(source.is_file() and not source.is_symlink(),'source must be a regular state file')
    require(not (source.parent/'instance.lock').exists(),'stop service before migration; instance.lock present')
    with source.open('rb') as f: raw=f.read(MAX_BYTES+1)
    require(len(raw)<=MAX_BYTES,'source exceeds offline migration size limit')
    return raw

def rehearse(source, destination):
    source=Path(source); destination=Path(destination)
    raw=read_source(source)
    qq,cards,audits=rows_from(raw)
    digest=hashlib.sha256(raw).hexdigest()
    # O_EXCL prevents overwriting an earlier rehearsal or existing database.
    fd=os.open(destination,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600); os.close(fd)
    try:
        conn=sqlite3.connect(destination)
        try:
            conn.execute('PRAGMA foreign_keys=ON')
            conn.executescript((Path(__file__).with_name('staging.sql')).read_text(encoding='utf-8'))
            with conn:
                conn.execute('INSERT INTO migration_meta VALUES (1,?,?)',(digest,qq))
                conn.executemany('INSERT INTO staged_cards VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',cards)
                conn.executemany('INSERT INTO staged_audit VALUES (?,?,?,?,?,?)',audits)
            require(conn.execute('PRAGMA integrity_check').fetchall()==[('ok',)],'database integrity check failed')
            require(conn.execute('PRAGMA foreign_key_check').fetchall()==[],'database foreign key check failed')
            require(conn.execute('SELECT source_sha256,qq FROM migration_meta').fetchall()==[(digest,qq)],'metadata mismatch')
            require(conn.execute('SELECT * FROM staged_cards ORDER BY ordinal').fetchall()==cards,'card round-trip mismatch')
            require(conn.execute('SELECT * FROM staged_audit ORDER BY ordinal').fetchall()==audits,'audit round-trip mismatch')
            require(read_source(source)==raw,'source changed during rehearsal')
        finally: conn.close()
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    return {'cards':len(cards),'audit':len(audits),'source_sha256':digest,'result':'STAGING_ROUNDTRIP_PASS','production_migrated':False}

def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('source',type=Path); p.add_argument('destination',type=Path)
    args=p.parse_args()
    try: print(json.dumps(rehearse(args.source,args.destination),ensure_ascii=False))
    except (InvalidState,OSError,sqlite3.Error,OverflowError,UnicodeError) as e:
        # Do not print database contents or private paths.
        print('Migration refused: '+(str(e) if isinstance(e,InvalidState) else type(e).__name__),file=sys.stderr); return 1
    return 0
if __name__=='__main__': sys.exit(main())
