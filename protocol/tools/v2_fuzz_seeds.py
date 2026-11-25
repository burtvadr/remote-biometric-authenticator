#!/usr/bin/env python3
"""Seed local parser and state fuzz corpora from synthetic protocol fixtures."""
import argparse
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CODES = list(range(10, 25)) + list(range(30, 39))
DOMAINS = ["AUTH-REQUEST", "MATCHED", "AUTH-RESPONSE", "ENROLL-KEY-PROOF", "POLICY", "ATTEST", "ENROLL-OFFER", "ENROLL-CONTEXT"]
DOMAINS = ["RBA-V2-" + name for name in DOMAINS]


def rows(name):
    for line in (ROOT / "protocol/test-vectors" / name).read_text().splitlines():
        if line and not line.startswith("#"):
            yield line.split("\t")


def seeds():
    result = {name: set() for name in ("v2_frame", "v2_payload", "v2_transcript")}
    for row in rows("v2-wire.tsv"):
        result["v2_frame"].add(bytes.fromhex(row[2]))
    for name, mode, raw, extra in rows("v2-message.tsv"):
        data = bytes.fromhex(raw)
        if mode in ("accept", "reject"):
            result["v2_frame"].add(data)
        elif mode == "transcript":
            result["v2_transcript"].add(bytes([DOMAINS.index(name)]) + data)
        elif mode in ("verify", "bad-signature"):
            result["v2_transcript"].add(bytes([DOMAINS.index(extra.split(":")[0])]) + data)
        else:
            raise ValueError(f"unknown fixture mode: {mode}")
    for frame in result["v2_frame"]:
        if len(frame) >= 13 and frame.startswith(b"PAF2"):
            code = int.from_bytes(frame[5:7], "big")
            if code in CODES and len(frame[13:]) <= 65536:
                result["v2_payload"].add(bytes([CODES.index(code)]) + frame[13:])
    # Explicit valid and invalid transition cases plus terminal suffix replay.
    result["v2_host_state"] = {
        bytes([branch, stage, fault, 0, 1, 2, 0])
        for branch in range(2) for stage in range(2) for fault in range(8)
    }
    result["v2_jvm_state"] = {
        bytes([0, stage, fault, 0, 1, 2, 0])
        for stage in range(4) for fault in range(6)
    } | {
        bytes([1, direction, fault, 0, 1, 2, 0])
        for direction in range(2) for fault in range(9)
    }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "linux/fuzz/corpus")
    args = parser.parse_args()
    for target, items in seeds().items():
        directory = args.output / target
        directory.mkdir(parents=True, exist_ok=True)
        for data in sorted(items):
            path = directory / ("seed-" + hashlib.sha256(data).hexdigest())
            if path.exists():
                if path.read_bytes() != data:
                    raise RuntimeError(f"seed mismatch: {path}")
            else:
                path.write_bytes(data)
        print(f"{target}: {len(items)} unique fixture seeds")


if __name__ == "__main__":
    main()
