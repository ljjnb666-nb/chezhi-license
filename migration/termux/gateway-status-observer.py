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
import uuid
import sys
from contextlib import contextmanager
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
    if started > observed:
        raise ValueError("inconsistent timestamp")
    if now is not None:
        now_ns = datetime_ns(now)
        if observed > now_ns or now_ns - observed > MAX_AGE_NS:
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
        self.restarted = False

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
                elif continuous and not self.restarted and previous[key] and not current[key]:
                    events.append(label + "_FLAG_CLOSED_NOT_PROOF_OF_RECOVERY")
        self.last = current
        self.restarted = False
        return events


def sample(directory):
    try:
        return read_snapshot(directory)
    except (OSError, ValueError, TypeError, RecursionError, AttributeError):
        return None


# One private, operator-created directory per observer. The checkpoint is a
# bounded transactional outbox: persist state + events before output, then
# acknowledge only after flush. Crash replay may duplicate stable event IDs.
STATE_FILE = "observer.json"
STATE_LIMIT = 16384
EVENTS = {
    "STATUS_UNAVAILABLE", "STATUS_AVAILABLE_NOT_READY",
    "OBSERVATION_STARTED_NOT_READY", "GENERATION_CHANGED_NOT_READY",
    "STOPPING_NOT_READY", "HTTP_5XX_OPEN", "HTTP_429_OPEN",
    "HTTP_5XX_FLAG_CLOSED_NOT_PROOF_OF_RECOVERY",
    "HTTP_429_FLAG_CLOSED_NOT_PROOF_OF_RECOVERY",
}


@contextmanager
def private_directory(directory):
    if not os.path.isabs(directory):
        raise ValueError("absolute private directory required")
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("invalid private directory")
        yield fd
    finally:
        os.close(fd)


def check_state(raw):
    if len(raw) > STATE_LIMIT:
        raise ValueError("oversized checkpoint")
    state = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs)
    if not isinstance(state, dict) or set(state) != {
        "version", "last", "unavailable", "updated_utc", "pending"
    }:
        raise ValueError("invalid checkpoint schema")
    if type(state["version"]) is not int or state["version"] != 1 or type(state["unavailable"]) is not bool:
        raise ValueError("invalid checkpoint version or flag")
    updated = stamp(state["updated_utc"])
    if state["last"] is not None:
        last = parse(json.dumps(state["last"]).encode(), None)
        if stamp(last["observed_utc"]) > updated:
            raise ValueError("checkpoint precedes observation")
    if not isinstance(state["pending"], list) or len(state["pending"]) > 4:
        raise ValueError("invalid pending batch")
    ids = set()
    for event in state["pending"]:
        if (not isinstance(event, dict) or set(event) != {"id", "event"}
                or not isinstance(event["id"], str)
                or not re.fullmatch(r"[0-9a-f]{32}", event["id"])
                or event["id"] in ids or not isinstance(event["event"], str)
                or event["event"] not in EVENTS):
            raise ValueError("invalid pending event")
        ids.add(event["id"])
    return state


def read_state(fd):
    try:
        item = os.open(STATE_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(item)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > STATE_LIMIT):
            raise ValueError("invalid checkpoint file")
        with os.fdopen(item, "rb", closefd=False) as source:
            return check_state(source.read(STATE_LIMIT + 1))
    finally:
        os.close(item)


def save_state(fd, state):
    raw = json.dumps(state, separators=(",", ":"), allow_nan=False).encode()
    check_state(raw)
    # Refuse an unexpected existing file rather than silently replacing it.
    read_state(fd)
    name = ".observer-" + uuid.uuid4().hex
    item = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                   0o600, dir_fd=fd)
    try:
        with os.fdopen(item, "wb") as target:
            target.write(raw)
            target.flush()
            os.fsync(target.fileno())
        os.replace(name, STATE_FILE, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        try:
            os.unlink(name, dir_fd=fd)
        except FileNotFoundError:
            pass


def deliver(fd, state, emit):
    if not state["pending"]:
        return
    for event in state["pending"]:
        emit(event)
    # Do not acknowledge a partially emitted batch or invent exactly-once delivery.
    acknowledged = {**state, "pending": []}
    save_state(fd, acknowledged)
    state["pending"] = []


def durable_sample(fd, observer, current, emit, now=None):
    events = observer.update(current)
    now = dt.datetime.now(UTC) if now is None else now
    updated = now.isoformat().replace("+00:00", "Z")
    # Never move the durable clock behind a retained observation, even after
    # a wall-clock rollback. Fail rather than fabricate a fresh heartbeat.
    state = {"version": 1, "last": observer.last, "unavailable": observer.unavailable,
             "updated_utc": updated,
             "pending": [{"id": uuid.uuid4().hex, "event": event} for event in events]}
    previous = read_state(fd)
    if previous is not None and (previous["pending"] or stamp(updated) < stamp(previous["updated_utc"])):
        raise ValueError("unacknowledged batch or checkpoint clock rollback")
    save_state(fd, state)
    deliver(fd, state, emit)
    return state


def restore_observer(state):
    observer = Observer()
    if state is not None:
        observer.last = state["last"]
        observer.unavailable = state["unavailable"]
        # Across a restart we cannot assert continuous observation or recovery.
        observer.restarted = True
    return observer


def heartbeat_ok(state, now):
    if state is None or state["pending"]:
        return False
    age = datetime_ns(now) - stamp(state["updated_utc"])
    return 0 <= age <= 90 * 1_000_000_000


def emit_local(event):
    print("gateway_observer id=" + event["id"] + " " + event["event"], flush=True)


def durable_watch(status_directory, state_directory):
    import fcntl
    with private_directory(status_directory) as status_fd, private_directory(state_directory) as fd:
        a, b = os.fstat(status_fd), os.fstat(fd)
        if (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino):
            raise ValueError("producer and observer directories must differ")
        # Lock the directory inode: no stale lock-file cleanup or PID guessing.
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = read_state(fd)
        if state is not None:
            deliver(fd, state, emit_local)
        observer = restore_observer(state)
        while True:
            durable_sample(fd, observer, sample(status_directory), emit_local)
            time.sleep(30)


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


    @unittest.skipUnless(os.name == "posix", "POSIX checkpoint contract")
    def test_durable_replay_and_restart(self):
        opened = {**self.s, "alert_5xx_open": True}
        with tempfile.TemporaryDirectory() as root, private_directory(root) as fd:
            o = Observer()
            received = []
            def interrupted(event):
                received.append(event.copy())
                raise OSError("synthetic output failure")
            with self.assertRaises(OSError):
                durable_sample(fd, o, opened, interrupted, self.now)
            state = read_state(fd)
            self.assertEqual(len(state["pending"]), 2)
            self.assertFalse(heartbeat_ok(state, self.now))
            with self.assertRaises(ValueError):
                durable_sample(fd, restore_observer(state), opened, lambda event: None, self.now)
            self.assertEqual(read_state(fd), state)  # never overwrite unacknowledged events

            replay = []
            deliver(fd, state, replay.append)
            self.assertEqual(replay[0], received[0])
            self.assertEqual(len(replay), 2)
            self.assertEqual(read_state(fd)["pending"], [])
            self.assertTrue(heartbeat_ok(read_state(fd), self.now))
            self.assertFalse(heartbeat_ok(read_state(fd), self.now + dt.timedelta(seconds=91)))
            self.assertFalse(heartbeat_ok(read_state(fd), self.now - dt.timedelta(seconds=1)))
            self.assertEqual(stat.S_IMODE((Path(root) / STATE_FILE).stat().st_mode), 0o600)
            o = restore_observer(read_state(fd))
            replay.clear()
            durable_sample(fd, o, opened, replay.append, self.now)
            self.assertEqual(replay, [])  # unchanged open survives restart without duplicate
            o = restore_observer(read_state(fd))
            closed = {**self.s, "observed_utc": "2026-11-28T12:00:01Z"}
            durable_sample(fd, o, closed, replay.append, self.now + dt.timedelta(seconds=1))
            self.assertEqual(replay, [])  # no inferred recovery across restart
            with self.assertRaises(ValueError):
                durable_sample(fd, o, None, replay.append, self.now)
            self.assertEqual(read_state(fd)["updated_utc"], "2026-11-28T12:00:01Z")


    @unittest.skipUnless(os.name == "posix", "POSIX checkpoint contract")
    def test_checkpoint_fail_closed(self):
        with tempfile.TemporaryDirectory() as root, private_directory(root) as fd:
            durable_sample(fd, Observer(), self.s, lambda event: None, self.now)
            target = Path(root) / STATE_FILE
            target.write_text("{}")
            with self.assertRaises(ValueError):
                read_state(fd)
            with self.assertRaises(ValueError):
                durable_sample(fd, Observer(), self.s, lambda event: None, self.now)
            self.assertEqual(target.read_text(), "{}")
            target.unlink()
            other = Path(root) / "protected"
            other.write_text("preserve")
            target.symlink_to(other)
            with self.assertRaises(OSError):
                read_state(fd)
            self.assertEqual(other.read_text(), "preserve")

    @unittest.skipUnless(os.name == "posix", "POSIX checkpoint contract")
    def test_single_writer_lease(self):
        import fcntl
        with tempfile.TemporaryDirectory() as root, private_directory(root) as first, private_directory(root) as second:
            fcntl.flock(first, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                fcntl.flock(second, fcntl.LOCK_EX | fcntl.LOCK_NB)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory")
    parser.add_argument("--watch", action="store_true", help="emit local transitions every 30 seconds")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--state-directory", help="private observer checkpoint directory")
    parser.add_argument("--check-state", action="store_true", help="check durable observer heartbeat only")
    args = parser.parse_args()
    if args.self_test:
        if args.directory or args.watch or args.state_directory or args.check_state:
            parser.error("--self-test is standalone")
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
        return 0 if result.wasSuccessful() else 1
    if os.name != "posix":
        parser.error("POSIX private file contract required")
    if args.check_state:
        if args.directory or args.watch or not args.state_directory:
            parser.error("--check-state requires only --state-directory")
        try:
            with private_directory(args.state_directory) as fd:
                ok = heartbeat_ok(read_state(fd), dt.datetime.now(UTC))
        except (OSError, ValueError, TypeError, RecursionError):
            ok = False
        print("OBSERVER_HEARTBEAT_FRESH_NOT_READY" if ok else "OBSERVER_HEARTBEAT_UNAVAILABLE")
        return 0 if ok else 2
    if not args.directory or not os.path.isabs(args.directory):
        parser.error("--directory must be absolute")
    if args.state_directory:
        if not args.watch:
            parser.error("--state-directory requires --watch")
        try:
            durable_watch(args.directory, args.state_directory)
        except KeyboardInterrupt:
            return 130
        except (OSError, ValueError, TypeError, RecursionError):
            print("OBSERVER_CHECKPOINT_OR_OUTPUT_FAILED", file=sys.stderr, flush=True)
            return 2
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
