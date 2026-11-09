#!/usr/bin/env python3
"""Apparatus for FX-60 (#1169): ask a Session owner's media service for its image directly.

    media_forward_probe.py <node> <room> <owner> <service-tag> <activity-entry>

As <node>, over the daemon's own control socket (ADR-026 §4: `Opening::Use`, then the node-level
`Request::Forward`), forward a local port to <owner>'s service <service-tag> in <room> (room, owner
and entry base32), and send it the one request a requester's daemon sends:
`GET /media/<activity-entry hex>`, naming the Session activity record that announced the image.
This skips every check the requester's own daemon makes before it asks
(`ipc_omp_media::authorized`), so what comes back is what the owner's service decided alone.

Prints one JSON line: {"kind": "answer", "status": <first response line or "">, "body": <bytes
after the head>, "sha256": <hex of those bytes>}, or {"kind": "apparatus", "error": ...} when the
forward itself could not be set up.
"""
import base64
import hashlib
import json
import socket
import struct
import subprocess
import sys

T_USE, ATTACH_NO, T_FORWARD, T_BOUND, T_STOP_FORWARD = 4100, 0, 8, 8, 9


def fail(error):
    print(json.dumps({"kind": "apparatus", "error": error}), flush=True)
    sys.exit(2)


def head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for code, fmt in ((24, ">B"), (25, ">H"), (26, ">I"), (27, ">Q")):
        if n < 1 << (8 * struct.calcsize(fmt)):
            return bytes([major << 5 | code]) + struct.pack(fmt, n)
    raise ValueError(n)


def enc(item):
    if isinstance(item, int):
        return head(0, item)
    if isinstance(item, bytes):
        return head(2, len(item)) + item
    if isinstance(item, str):
        data = item.encode()
        return head(3, len(data)) + data
    return head(4, len(item)) + b"".join(enc(x) for x in item)


def dec(data, at=0):
    """One CBOR item at `at`: (value, next). Maps and floats are not read by this probe."""
    first = data[at]
    major, info = first >> 5, first & 31
    at += 1
    if info < 24:
        n = info
    else:
        size = {24: 1, 25: 2, 26: 4, 27: 8}[info]
        n = int.from_bytes(data[at:at + size], "big")
        at += size
    if major == 0:
        return n, at
    if major == 1:
        return -1 - n, at
    if major in (2, 3):
        raw = data[at:at + n]
        return (raw if major == 2 else raw.decode(errors="replace")), at + n
    if major == 4:
        items = []
        for _ in range(n):
            item, at = dec(data, at)
            items.append(item)
        return items, at
    if major == 7:
        return {20: False, 21: True, 22: None}.get(info, info), at
    raise ValueError(f"cbor major type {major}")


def b32(text):
    return base64.b32decode(text.upper() + "=" * (-len(text) % 8))


def frame(sock):
    size = b""
    while len(size) < 4:
        part = sock.recv(4 - len(size))
        if not part:
            return None
        size += part
    (length,) = struct.unpack(">I", size)
    body = b""
    while len(body) < length:
        part = sock.recv(length - len(body))
        if not part:
            return None
        body += part
    return dec(body)[0]


def send(sock, item):
    body = enc(item)
    sock.sendall(struct.pack(">I", len(body)) + body)


def daemon_socket():
    """The control socket the running daemon listens on: it binds a temporary name in the socket's
    directory and renames it to vox.sock, so lsof names the directory, not the socket."""
    import os
    lock = os.path.join(os.environ["VOX_DATA_DIR"], ".daemon", "lock")
    try:
        pid = open(lock).read().split()[0]
    except (OSError, IndexError):
        fail(f"no running daemon in {lock}")
    out = subprocess.run(["/usr/sbin/lsof", "-a", "-p", pid, "-U", "-Fn"], capture_output=True,
                         text=True).stdout
    for line in out.splitlines():
        if line.startswith("n/"):
            candidate = os.path.join(os.path.dirname(line[1:]), "vox.sock")
            if os.path.exists(candidate):
                return candidate
    fail(f"daemon {pid} listens on no vox.sock: {out!r}")


def main():
    if len(sys.argv) != 6:
        fail("usage: media_forward_probe.py <node> <room> <owner> <service-tag> <activity-entry>")
    node, room, owner, tag, entry = sys.argv[1:]
    entry = b32(entry).hex()
    if len(entry) != 64:
        fail(f"the activity entry is not a 32-byte digest: {sys.argv[5]!r}")
    control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    control.settimeout(30)
    control.connect(daemon_socket())
    if frame(control) is None:
        fail("the daemon closed before its hello")
    send(control, [T_USE, node, ATTACH_NO, [], []])
    using = frame(control)
    if not isinstance(using, list) or not using:
        fail(f"the daemon did not answer the opening: {using!r}")
    send(control, [T_FORWARD, b32(room), b32(owner), tag, "127.0.0.1:0"])
    bound = frame(control)
    if not (isinstance(bound, list) and len(bound) == 2 and bound[0] == T_BOUND):
        fail(f"the forward was not bound (opening answered {using!r}): {bound!r}")
    host, port = bound[1].rsplit(":", 1)
    answer = b""
    try:
        media = socket.create_connection((host, int(port)), timeout=30)
    except OSError as error:
        fail(f"could not connect to the local forward: {error}")
    try:
        with media:
            media.sendall(f"GET /media/{entry} HTTP/1.1\r\nHost: vox\r\nConnection: close\r\n\r\n".encode())
            while True:
                part = media.recv(65536)
                if not part:
                    break
                answer += part
    except socket.timeout:
        fail("timed out waiting for the owner's media service")
    except (ConnectionResetError, ConnectionAbortedError, ConnectionRefusedError, BrokenPipeError):
        pass  # A close or reset is the service ending the request.
    except OSError as error:
        fail(f"media transport failed: {error}")
    send(control, [T_STOP_FORWARD, bound[1]])
    status, _, rest = answer.partition(b"\r\n")
    body = rest.partition(b"\r\n\r\n")[2] if rest else b""
    print(json.dumps({"kind": "answer", "status": status.decode(errors="replace"), "body": len(body),
                      "sha256": hashlib.sha256(body).hexdigest()}), flush=True)


main()
