#!/usr/bin/env python3
"""Local-only gateway status observer. Never grants access or proves readiness."""
import argparse
import datetime as dt
import json
import os
import re
import stat
import time
import unittest
import tempfile
from pathlib import Path

MAX_BYTES = 4096
MAX_AGE_NS = 180 * 1_000_000_000
COUNTERS = {"total", "http_200", "denied", "limited", "unavailable", "other", "active"}
FLAGS = {"alert_5xx_open", "alert_429_open"}
FIELDS = COUNTERS | FLAGS | {"version", "started_utc", "observed_utc", "lifecycle"}
UTC = dt.timezone.utc


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def stamp(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z", value
    ):
        raise ValueError("invalid UTC timestamp")
    # Go emits RFC3339Nano; datetime alone truncates the last three digits.
    whole, _, fraction = value[:-1].partition(".")
    second = dt.datetime.fromisoformat(whole + "+00:00")
    return datetime_ns(second) + int(fraction.ljust(9, "0") or "0")


def datetime_ns(value):
    delta = value - dt.datetime(1970, 1, 1, tzinfo=UTC)
    return ((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1000


def parse(raw, now):
    if len(raw) > MAX_BYTES:
        raise ValueError("oversized snapshot")
    s = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs)
    if not isinstance(s, dict) or set(s) != FIELDS:
        raise ValueError("invalid schema")
    if type(s["version"]) is not int or s["version"] != 1:
        raise ValueError("unsupported version")
    if s["lifecycle"] not in ("OBSERVING", "STOPPING"):
        raise ValueError("invalid lifecycle")
    for key in COUNTERS:
        limit = (1 << (63 if key == "active" else 64)) - 1
        if type(s[key]) is not int or not 0 <= s[key] <= limit:
            raise ValueError("invalid counter")
    for key in FLAGS:
        if type(s[key]) is not bool:
            raise ValueError("invalid alert flag")
    started, observed = stamp(s["started_utc"]), stamp(s["observed_utc"])
    now_ns = datetime_ns(now)
    if not started <= observed <= now_ns or now_ns - observed > MAX_AGE_NS:
        raise ValueError("stale or inconsistent timestamp")
    # Counters are separate atomic samples, not a transactional sum.
    return s


def read_snapshot(directory, now=None):
    # POSIX only. Ancestors must be controlled by the operator; same-UID
    # tampering is outside the producer/consumer trust boundary.
    if not os.path.isabs(directory):
        raise ValueError("absolute private directory required")
    dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(dfd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("invalid directory ownership or mode")
        fd = os.open("status.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > MAX_BYTES):
                raise ValueError("invalid status file")
            with os.fdopen(fd, "rb", closefd=False) as source:
                raw = source.read(MAX_BYTES + 1)
                return parse(raw, dt.datetime.now(UTC) if now is None else now)
        finally:
            os.close(fd)
    finally:
        os.close(dfd)


class Observer:
    """In-memory deduplication; no persistent state or external delivery."""
    def __init__(self):
        self.last = None
        self.unavailable = False

    def update(self, current):
        if current is None:
            events = [] if self.unavailable else ["STATUS_UNAVAILABLE"]
            self.unavailable = True
            return events
        previous = self.last
        events = []
        gap = self.unavailable
        same = previous is not None and stamp(previous["started_utc"]) == stamp(current["started_utc"])
        if previous is not None and (stamp(current["observed_utc"]) < stamp(previous["observed_utc"])
                or stamp(current["started_utc"]) < stamp(previous["started_utc"])
                or (stamp(current["observed_utc"]) == stamp(previous["observed_utc"]) and current != previous)
                or (same and previous["lifecycle"] == "STOPPING" and current["lifecycle"] == "OBSERVING")):
            return self.update(None)
        if gap:
            events.append("STATUS_AVAILABLE_NOT_READY")
            self.unavailable = False
        if previous is None or not same:
            events.append("OBSERVATION_STARTED_NOT_READY" if previous is None else "GENERATION_CHANGED_NOT_READY")
        if current["lifecycle"] == "STOPPING":
            if not same or previous["lifecycle"] != "STOPPING":
                events.append("STOPPING_NOT_READY")
        else:
            for key, label in (("alert_5xx_open", "HTTP_5XX"), ("alert_429_open", "HTTP_429")):
                continuous = same and not gap and previous["lifecycle"] == "OBSERVING"
                if current[key] and (not continuous or not previous[key]):
                    events.append(label + "_OPEN")
                elif continuous and previous[key] and not current[key]:
                    events.append(label + "_FLAG_CLOSED_NOT_PROOF_OF_RECOVERY")
        self.last = current
        return events


def sample(directory):
    try:
        return read_snapshot(directory)
    except (OSError, ValueError, TypeError, RecursionError, AttributeError):
        return None


class Tests(unittest.TestCase):
    def setUp(self):
        self.now = dt.datetime(2026, 11, 28, 12, tzinfo=UTC)
        self.s = {**dict.fromkeys(COUNTERS, 0), **dict.fromkeys(FLAGS, False),
                  "version": 1, "started_utc": "2026-11-28T11:59:00Z",
                  "observed_utc": "2026-11-28T12:00:00Z", "lifecycle": "OBSERVING"}

    def test_schema(self):
        raw = json.dumps(self.s).encode()
        self.assertEqual(parse(raw, self.now), self.s)
        for change in ({"version": True}, {"version": 2}, {"active": -1},
                       {"alert_429_open": 1}, {"extra": 0}, {"total": 1 << 64},
                       {"observed_utc": "2026-11-28T12:00:01Z"},
                       {"started_utc": "2026-11-28T12:00:01Z"},
                       {"lifecycle": "READY"}):
            with self.assertRaises(ValueError):
                parse(json.dumps({**self.s, **change}).encode(), self.now)
        for bad in (raw[:-1] + b',"version":1}', b"{}", b"x" * 4097):
            with self.assertRaises(ValueError):
                parse(bad, self.now)
        with self.assertRaises(ValueError):
            parse(raw, self.now + dt.timedelta(seconds=181))

    @unittest.skipUnless(os.name == "posix", "POSIX private status contract")
    def test_files(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            directory.chmod(0o700)
            target = directory / "status.json"
            target.write_text(json.dumps(self.s))
            target.chmod(0o600)
            self.assertEqual(read_snapshot(root, self.now), self.s)
            target.chmod(0o644)
            with self.assertRaises(ValueError):
                read_snapshot(root, self.now)
            target.unlink()
            protected = directory / "protected"
            protected.write_text("preserve")
            target.symlink_to(protected)
            with self.assertRaises(OSError):
                read_snapshot(root, self.now)
            self.assertEqual(protected.read_text(), "preserve")
            target.unlink()
            os.mkfifo(target, 0o600)
            with self.assertRaises(ValueError):
                read_snapshot(root, self.now)

    def test_nanosecond_boundaries(self):
        self.assertEqual(stamp("2026-11-28T12:00:00.000000002Z") -
                         stamp("2026-11-28T12:00:00.000000001Z"), 1)
        raw = json.dumps({**self.s, "observed_utc": "2026-11-28T12:00:00.000000001Z"}).encode()
        with self.assertRaises(ValueError):
            parse(raw, self.now)
        parse(raw, self.now + dt.timedelta(microseconds=1))
        raw = json.dumps({**self.s, "started_utc": "2026-11-28T11:56:59Z",
                          "observed_utc": "2026-11-28T11:57:00Z"}).encode()
        parse(raw, self.now)
        with self.assertRaises(ValueError):
            parse(raw, self.now + dt.timedelta(microseconds=1))
        o = Observer()
        first = {**self.s, "observed_utc": "2026-11-28T12:00:00.000000001Z"}
        second = {**first, "observed_utc": "2026-11-28T12:00:00.000000002Z",
                  "alert_429_open": True}
        o.update(first)
        self.assertEqual(o.update(second), ["HTTP_429_OPEN"])
        self.assertEqual(o.update(first), ["STATUS_UNAVAILABLE"])
        self.assertEqual(o.update(first), [])

    def test_events(self):
        o = Observer()
        self.assertEqual(o.update(None), ["STATUS_UNAVAILABLE"])
        self.assertEqual(o.update(None), [])
        opened = {**self.s, "alert_5xx_open": True}
        self.assertIn("HTTP_5XX_OPEN", o.update(opened))
        self.assertEqual(o.update(opened), [])
        closed = {**self.s, "observed_utc": "2026-11-28T12:01:00Z"}
        self.assertEqual(o.update(closed), ["HTTP_5XX_FLAG_CLOSED_NOT_PROOF_OF_RECOVERY"])
        self.assertEqual(o.update(None), ["STATUS_UNAVAILABLE"])
        self.assertNotIn("HTTP_5XX_FLAG_CLOSED_NOT_PROOF_OF_RECOVERY", o.update(closed))
        conflicting = {**closed, "started_utc": "2026-11-28T12:00:30Z"}
        self.assertEqual(o.update(conflicting), ["STATUS_UNAVAILABLE"])
        self.assertEqual(o.update(conflicting), [])
        changed = {**conflicting, "observed_utc": "2026-11-28T12:01:01Z"}
        self.assertEqual(o.update(changed), ["STATUS_AVAILABLE_NOT_READY", "GENERATION_CHANGED_NOT_READY"])
        self.assertEqual(o.update({**changed, "lifecycle": "STOPPING",
                                   "observed_utc": "2026-11-28T12:02:00Z"}), ["STOPPING_NOT_READY"])
        self.assertEqual(o.update(changed), ["STATUS_UNAVAILABLE"])
        self.assertEqual(o.update(changed), [])  # older generation/sample stays rejected
        later_old = {**changed, "started_utc": self.s["started_utc"],
                     "observed_utc": "2026-11-28T12:03:00Z"}
        self.assertEqual(o.update(later_old), [])
        invalid_resume = {**changed, "observed_utc": "2026-11-28T12:03:00Z"}
        self.assertEqual(o.update(invalid_resume), [])

    def test_gap_never_claims_recovery(self):
        o = Observer()
        opened = {**self.s, "alert_5xx_open": True, "alert_429_open": True}
        o.update(opened)
        o.update(None)
        closed = {**self.s, "observed_utc": "2026-11-28T12:01:00Z"}
        self.assertEqual(o.update(closed), ["STATUS_AVAILABLE_NOT_READY"])
        self.assertEqual(o.update(closed), [])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory")
    parser.add_argument("--watch", action="store_true", help="emit local transitions every 30 seconds")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        if args.directory or args.watch:
            parser.error("--self-test is standalone")
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
        return 0 if result.wasSuccessful() else 1
    if not args.directory or not os.path.isabs(args.directory):
        parser.error("--directory must be absolute")
    if os.name != "posix":
        parser.error("POSIX private file contract required")
    observer = Observer()
    try:
        while True:
            current = sample(args.directory)
            for event in observer.update(current):
                print("gateway_observer " + event, flush=True)
            if not args.watch:
                return 0 if current is not None and current["lifecycle"] == "OBSERVING" else 2
            time.sleep(30)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
