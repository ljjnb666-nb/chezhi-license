#!/usr/bin/env python3
"""Verify the local maintenance ZIP without extracting or executing its contents."""
import hashlib
import pathlib
import re
import stat
import sys
import zipfile

FILES = {
    "chezhi-gateway-android-arm64", "source-commit.txt", "GATEWAY.md",
    "cloudflared.disabled.yml", "gateway-service.sh", "NOTICE",
    "maintenance-preflight.sh", "postgres-logging.candidate.conf",
    "encrypted-export.sh", "encrypted-receive.sh", "stage-loopback-tls.sh",
    "postgres-log-retention.py",
}
LIMIT = 64 * 1024 * 1024

def verify(path, expected_zip, expected_checkout):
    if not re.fullmatch(r"[0-9a-f]{64}", expected_zip):
        raise ValueError("invalid trusted ZIP digest")
    if not re.fullmatch(r"[0-9a-f]{40}", expected_checkout):
        raise ValueError("invalid trusted checkout commit")
    # Read a bounded private byte snapshot; verify exactly what is parsed.
    import io
    with pathlib.Path(path).open("rb") as source:
        data = source.read(LIMIT + 1)
    if len(data) > LIMIT or hashlib.sha256(data).hexdigest() != expected_zip:
        raise ValueError("ZIP size or digest mismatch")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        names = [item.filename for item in entries]
        if len(names) != len(set(names)) or set(names) != FILES | {"SHA256SUMS"}:
            raise ValueError("unexpected or duplicate archive entries")
        if sum(item.file_size for item in entries) > LIMIT:
            raise ValueError("uncompressed archive too large")
        for item in entries:
            mode = stat.S_IFMT(item.external_attr >> 16)
            if item.is_dir() or mode not in (0, stat.S_IFREG) or item.flag_bits & 1:
                raise ValueError("unsupported ZIP entry type")
        manifest = archive.read("SHA256SUMS").decode("ascii")
        parsed = {}
        for line in manifest.splitlines():
            match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
            if not match or match[2] in parsed:
                raise ValueError("invalid or duplicate manifest entry")
            parsed[match[2]] = match[1]
        if set(parsed) != FILES:
            raise ValueError("manifest coverage mismatch")
        for name, digest in parsed.items():
            if hashlib.sha256(archive.read(name)).hexdigest() != digest:
                raise ValueError("internal file digest mismatch")
        if archive.read("source-commit.txt") != (expected_checkout + "\n").encode("ascii"):
            raise ValueError("checkout commit mismatch")
        if archive.read("NOTICE") != b"UNSIGNED LOCAL TEST ONLY; NO TUNNEL OR PUBLIC DEPLOYMENT\n":
            raise ValueError("unexpected release notice")
    print("MAINTENANCE_ZIP_VERIFIED entries=13 unsigned local-only candidate")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit("Usage: verify-maintenance-zip.py ZIP TRUSTED_SHA256 TRUSTED_CHECKOUT_SHA")
    try:
        verify(*sys.argv[1:])
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, NotImplementedError) as exc:
        sys.exit("Verification failed: " + str(exc))
