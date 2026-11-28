#!/usr/bin/env python3
"""Read-only retention advisory for the native collector; never remove logs."""
import json
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

def inventory(root, now):
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
        return dict(result, state="COLLECTOR_NOT_CONFIGURED", eligible_count=0, eligible_bytes=0)
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
    return dict(result, state="ADVISORY_ONLY", files=len(entries), collector_bytes=total,
                collector_over_budget=total > BUDGET, total_log_over_budget=total+legacy_bytes > BUDGET,
                eligible_count=len(eligible), eligible_bytes=sum(entry[2] for entry in eligible))
    
if __name__ == "__main__":
    try:
        if len(sys.argv) != 1:
            raise ValueError("read-only inventory accepts no arguments")
        if os.environ.get("HOME") not in ("/data/data/com.termux/files/home", "/data/user/0/com.termux/files/home") or platform.machine() != "aarch64":
            raise ValueError("use private Termux ARM64 home")
        root = Path(os.environ["HOME"]) / ".chezhi-license-staging"
        private_dir(root)
        marker = root / "initialized"
        info = marker.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_size > 64 or marker.read_text() != "loopback-staging-v1\n":
            raise ValueError("staging marker invalid")
        result = inventory(root, time.time())
        print(json.dumps(result, sort_keys=True))
        print("PG_LOG_INVENTORY_OK advisory only; no files removed")
    except (OSError, ValueError) as exc:
        # OSError may include unexpected filenames; do not print those.
        print("PG_LOG_INVENTORY_HOLD: " + (str(exc) if isinstance(exc, ValueError) else "filesystem or collector state unavailable"), file=sys.stderr)
        sys.exit(1)
