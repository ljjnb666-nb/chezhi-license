#!/usr/bin/env python3
"""Read-only advisory and explicit offline archive maintenance for native collector logs."""
import json
import contextlib
import fcntl
import gzip
import hashlib
import subprocess
import tempfile
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import sys
import time

NAME = r"postgresql-[0-9]{8}-[0-9]{6}\.log"
KEEP = 7
AGE = 7 * 86400
BUDGET = 128 * 1024 * 1024
MIN_FREE = 1024 * 1024 * 1024
MAX_FILES = 10000

def private_dir(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
        raise ValueError("invalid private directory")

def current(pg):
    # Never follow a symlink or read arbitrary file contents.
    fd = os.open(pg / "current_logfiles", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise ValueError("invalid collector pointer")
        data = stream.read(4097)
    match = re.fullmatch(rb"stderr chezhi-pg-log/(" + NAME.encode() + rb")\n", data)
    if not match:
        raise ValueError("unexpected collector pointer")
    return match[1].decode("ascii")

def inventory(root, now, *, selected=False):
    private_dir(root)
    pg = root / "pgdata"
    private_dir(pg)
    logs = pg / "chezhi-pg-log"
    free = shutil.disk_usage(root).free
    legacy = root / "postgres.log"
    legacy_bytes = 0
    if os.path.lexists(legacy):
        info = legacy.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise ValueError("unexpected legacy log type")
        legacy_bytes = info.st_size
    result = {"free_bytes": free, "legacy_log_bytes": legacy_bytes,
              "low_free_space": free < MIN_FREE, "legacy_over_budget": legacy_bytes > BUDGET}
    if not os.path.lexists(logs) and not os.path.lexists(pg / "current_logfiles"):
        result = dict(result, state="COLLECTOR_NOT_CONFIGURED", eligible_count=0, eligible_bytes=0)
        return (result, []) if selected else result
    private_dir(logs)
    active = current(pg)
    entries = []
    with os.scandir(logs) as scan:
        for index, item in enumerate(scan):
            if index >= MAX_FILES:
                raise ValueError("inventory limit exceeded")
            info = item.stat(follow_symlinks=False)
            if (not re.fullmatch(NAME, item.name) or not stat.S_ISREG(info.st_mode)
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid()
                    or info.st_nlink != 1 or info.st_mtime > now):
                raise ValueError("unexpected log entry or future timestamp")
            entries.append((info.st_mtime, item.name, info.st_size))
    if active not in {name for _, name, _ in entries} or current(pg) != active:
        raise ValueError("collector pointer changed or missing; retry inventory")
    ordered = sorted(entries, reverse=True)
    eligible = [entry for entry in ordered[KEEP:] if entry[1] != active and now-entry[0] >= AGE]
    total = sum(entry[2] for entry in entries)
    result = dict(result, state="ADVISORY_ONLY", files=len(entries), collector_bytes=total,
                  collector_over_budget=total > BUDGET, total_log_over_budget=total+legacy_bytes > BUDGET,
                  eligible_count=len(eligible), eligible_bytes=sum(entry[2] for entry in eligible))
    return (result, eligible) if selected else result
    
def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

@contextlib.contextmanager
def offline(root, status=None):
    """Cooperative M4 locks, never stop or start a process."""
    private_dir(root)
    pg = root / "pgdata"
    private_dir(pg)
    ctl = root / "managed-v1"
    private_dir(ctl)
    if (ctl / "installed").is_symlink() or (ctl / "installed").read_bytes() != b"managed-v1\n":
        raise ValueError("managed controller marker invalid")
    def check():
        if os.path.lexists(pg / "postmaster.pid"):
            raise ValueError("database PID marker present")
        if status is None:
            code = subprocess.run(["pg_ctl", "-D", str(pg), "status"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5).returncode
        else:
            code = status()
        if code != 3:
            raise ValueError("database not proven stopped")
    with contextlib.ExitStack() as stack:
        for path in (ctl / "controller.lock", ctl / "control.lock", root / "service.lock"):
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            stack.callback(os.close, fd)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
                raise ValueError("invalid maintenance lease")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError("managed service or operation active") from None
        check()
        yield check

def file_digest(path, expected=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise ValueError("invalid protected log")
        if expected is not None and (info.st_mtime, info.st_size) != expected:
            raise ValueError("log changed since inventory")
        if info.st_size > BUDGET:
            raise ValueError("individual log exceeds maintenance batch limit")
        data = stream.read(BUDGET+1)
        after = os.fstat(stream.fileno())
        if len(data)!=info.st_size or (after.st_mtime_ns,after.st_size)!=(info.st_mtime_ns,info.st_size):
            raise ValueError("log changed during read")
        return data, (info.st_dev,info.st_ino,info.st_mtime_ns,info.st_size)

def archive_offline(root, now, status=None):
    """Explicit maintenance only; preserve verified private gzip before unlink.
    Any interrupted run leaves the archive or source, never overwrites it."""
    with offline(root, status) as check:
        result, entries = inventory(root, now, selected=True)
        if not entries:
            return dict(result, archived=0, removed_bytes=0)
        if result["low_free_space"]:
            raise ValueError("insufficient free space for safe archive")
        archives = root / "pg-log-archives"
        archives.mkdir(mode=0o700, exist_ok=True)
        private_dir(archives)
        logs = root / "pgdata" / "chezhi-pg-log"
        removed = 0
        count = 0
        for mtime,name,size in reversed(entries):
            if size > BUDGET or removed+size > BUDGET:
                break
            if shutil.disk_usage(root).free < MIN_FREE + size:
                raise ValueError("insufficient free space for archive")
            check()
            _, eligible = inventory(root, now, selected=True)
            if (mtime,name,size) not in eligible:
                raise ValueError("log no longer eligible")
            original = logs / name
            data, fingerprint = file_digest(original,(mtime,size))
            digest = hashlib.sha256(data).hexdigest()
            target = archives / (name+"."+digest+".gz")
            # Existing archive must match exactly; never overwrite.
            if not os.path.lexists(target):
                with tempfile.NamedTemporaryFile(dir=archives,prefix=".archive-",delete=False) as out:
                    pending = Path(out.name)
                    try:
                        with gzip.GzipFile(fileobj=out,mode="wb",mtime=0) as zipped:
                            zipped.write(data)
                        out.flush()
                        os.fsync(out.fileno())
                        os.link(pending,target,follow_symlinks=False)
                    finally:
                        pending.unlink(missing_ok=True)
            sync_dir(archives)
            fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd,"rb") as raw:
                info=os.fstat(raw.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:
                    raise ValueError("invalid archive file")
                with gzip.GzipFile(fileobj=raw,mode="rb") as zipped:
                    decoded=zipped.read(size+1)
                if decoded!=data:
                    raise ValueError("archive verification failed")
            check()
            _, eligible = inventory(root,now,selected=True)
            latest=original.lstat()
            if (mtime,name,size) not in eligible or (latest.st_dev,latest.st_ino,latest.st_mtime_ns,latest.st_size)!=fingerprint:
                raise ValueError("source changed before cleanup")
            original.unlink()
            sync_dir(logs)
            count+=1
            removed+=size
        return dict(result, archived=count, removed_bytes=removed)

if __name__ == "__main__":
    try:
        if sys.argv[1:] not in ([], ["archive-offline", "CONFIRM_OFFLINE_LOG_ARCHIVE"]):
            raise ValueError("invalid arguments; explicit offline confirmation required")
        if os.environ.get("HOME") not in ("/data/data/com.termux/files/home", "/data/user/0/com.termux/files/home") or platform.machine() != "aarch64":
            raise ValueError("use private Termux ARM64 home")
        root = Path(os.environ["HOME"]) / ".chezhi-license-staging"
        private_dir(root)
        marker = root / "initialized"
        info = marker.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_size > 64 or marker.read_text() != "loopback-staging-v1\n":
            raise ValueError("staging marker invalid")
        if sys.argv[1:]:
            result = archive_offline(root, time.time())
            print(json.dumps(result, sort_keys=True))
            print("PG_LOG_ARCHIVE_OK verified local archive; offline only")
        else:
            result = inventory(root, time.time())
            print(json.dumps(result, sort_keys=True))
            print("PG_LOG_INVENTORY_OK advisory only; no files removed")
    except (OSError, ValueError, EOFError, subprocess.SubprocessError) as exc:
        # OSError may include unexpected filenames; do not print those.
        print("PG_LOG_INVENTORY_HOLD: " + (str(exc) if isinstance(exc, ValueError) else "filesystem or collector state unavailable"), file=sys.stderr)
        sys.exit(1)
