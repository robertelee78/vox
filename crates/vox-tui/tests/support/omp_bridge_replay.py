#!/usr/bin/env python3
"""Apparatus: replay a recorded OMP bridge conversation to a real `vox`.

    omp_bridge_replay.py <capture.jsonl> [--stream-activity|--stream-async|--stream-unicode|--stream-cancel]

Five captures in omp-image-capture/ (authorized, streaming, async-error, unicode, cancel) are what
crossed the bridge socket between the stock Vox OMP extension, loaded by stock OMP 18.18.0, and a
real host `vox daemon`, recorded byte for byte by a logging relay. forged.jsonl is not a stock
capture: it is crafted test-side attacker input in the same format, whose image offer announces an
all-zero SHA-256 for bytes identical to the authorized image. Each file holds one JSON line per
chunk, {"conn", "dir": "daemon->omp"|"omp->daemon", "b64"}, plus the relay's
{"watch": "install", "session", "route"} line. This process takes the extension's place and
speaks its protocol to the real `vox`, presenting only what the extension presents:

  - `vox agent omp-watch --node $VOX_NODE` owns the Session (revoke, then install this process's
    own socket, token and generation reference, with the captured Session id and route);
  - `vox agent hook --attention-register` and `--omp-check-uncertainty` register it, with the
    extension's environment;
  - the daemon's subscription is answered with the captured extension->daemon lines of the
    captured subscription, in order and unchanged. A captured media response is sent only when
    the daemon asks for that media id, at the point where the capture answered it. Nothing after
    the last captured media response is replayed. Asked again for a media id the capture
    answered, it answers again as the extension does: the same record under the next cursor.
  - `--stream-activity` uses the dedicated streaming capture and gates its original progress,
    media and final records for the observing app. It moves the captured media answer between
    progress and final and renumbers cursors, without changing semantic payloads.
  - `--stream-async` gates real captured running-job, completed-job and error records while
    the app observes. Unrelated captured Drive control frames are not replayed.
  - `--stream-unicode` releases the captured multipart Unicode result after the app observes
    the tool start, without replaying unrelated Drive-control or later model frames.
  - `--stream-cancel` releases a genuine interrupted-tool result after its running progress.

Commands, one JSON reply line each (the stager's json-host protocol):
  register               -> {"session": id} once registered
  served <n> <seconds>   -> {"requested": [...], "answered": [...], "subscriptions": n, "replayed": n}
                            once n media requests were answered, or at the bound; "replayed"
                            counts subscriptions sent every captured line before the first answer
  requested <n> <seconds> -> state once n media requests arrived, or at the bound
  advance | release | finish | link -> send gated progress, media, final or attacker link
  job | complete | error -> send captured async job and error stages
  unicode -> send the captured long Unicode result
  cancel -> send the captured interrupted-tool result
Failures reply {"kind": "apparatus", "error": ...}.
"""
import base64
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time

DAEMON, OMP = "daemon->omp", "omp->daemon"


def load(path):
    streams, session, route = {}, None, None
    with open(path) as f:
        for raw in f:
            record = json.loads(raw)
            if record.get("watch") == "install":
                session, route = record["session"], record["route"]
            elif "b64" in record:
                stream = streams.setdefault(record["conn"], {DAEMON: bytearray(), OMP: bytearray()})
                stream[record["dir"]] += base64.b64decode(record["b64"])
    return streams, session, route


def lines(data):
    return [line + b"\n" for line in bytes(data).split(b"\n")[:-1]]


def media_answers(omp_lines):
    """The first line of each captured media answer with the media id it answers, each answered
    id's lines, and the line after the last answer's final part."""
    gates, spans, chunks, end = {}, {}, {}, 0
    for index, line in enumerate(omp_lines):
        frame = json.loads(line)
        event = frame.get("event") if frame.get("type") == "event" else None
        if not isinstance(event, dict) or event.get("type") != "semantic":
            continue
        cursor = event["cursor"]
        if event["part"] == 0:
            chunks[cursor] = (index, bytearray())
        start, data = chunks[cursor]
        data += base64.b64decode(event["data"])
        if event["part"] + 1 == event["parts"]:
            record = json.loads(bytes(data))
            if record.get("kind") in ("media", "media-unavailable"):
                gates[start], end = record["id"], index + 1
                spans[record["id"]] = [json.loads(raw) for raw in omp_lines[start:index + 1]]
            del chunks[cursor]
    return gates, spans, end


async_streaming = len(sys.argv) == 3 and sys.argv[2] == "--stream-async"
unicode_streaming = len(sys.argv) == 3 and sys.argv[2] == "--stream-unicode"
cancel_streaming = len(sys.argv) == 3 and sys.argv[2] == "--stream-cancel"
streams, SESSION, ROUTE = load(sys.argv[1])
subscription = None
for conn in sorted(streams):
    sent = [json.loads(line) for line in lines(streams[conn][DAEMON])]
    if (len(sent) > 1 and sent[1].get("type") == "subscribe"
            and (async_streaming or unicode_streaming or cancel_streaming
                 or any(m.get("type") == "media" for m in sent))):
        subscription = conn
if subscription is None or not SESSION or not ROUTE:
    print(json.dumps({"kind": "apparatus", "error": "the capture holds no matching subscription"}), flush=True)
    sys.exit(2)
REPLAY = lines(streams[subscription][OMP])
GATES, ANSWERS, LAST = media_answers(REPLAY)
if not async_streaming and not unicode_streaming and not cancel_streaming:
    REPLAY = REPLAY[:LAST]
# The extension numbers its semantic records per follower; a repeated answer takes the next one.
CURSOR = max(frame["event"]["cursor"] for frame in map(json.loads, REPLAY)
             if frame.get("type") == "event" and frame["event"].get("type") == "semantic")
VOX, NODE = os.environ["VOX_BIN"], os.environ["VOX_NODE"]
TOKEN = secrets.token_hex(32)
state = {"requested": [], "answered": [], "subscriptions": 0, "replayed": 0}
changed = threading.Condition()
streaming = len(sys.argv) == 3 and sys.argv[2] == "--stream-activity"
stream_steps = {name: threading.Event() for name in ("advance", "release", "finish", "link", "job", "complete", "error", "unicode", "partial", "empty-final", "cancel")}
stream_done = {name: threading.Event() for name in stream_steps}

def cancel_replay(sock, reader):
    """Release the real captured cancellation after its running progress is visible."""
    frames = [json.loads(line) for line in REPLAY]
    semantic = {f["event"]["cursor"]: f for f in frames
                if f.get("type") == "event" and f.get("event", {}).get("type") == "semantic"}
    if set(semantic) != set(range(1, 6)) or any(f["event"]["parts"] != 1 for f in semantic.values()):
        raise ValueError("cancellation capture has unexpected semantic frames")
    result = json.loads(base64.b64decode(semantic[5]["event"]["data"]))
    if result.get("name") != "proof_cancel" or result.get("status") != "cancelled":
        raise ValueError("capture has no cancelled proof tool")
    def wire(frame):
        return json.dumps(frame, separators=(",", ":")).encode() + b"\n"
    prefix = [f for f in frames if f.get("type") == "subscribed"
              or (f.get("type") == "event" and f.get("event", {}).get("type") == "state")]
    sock.sendall(b"".join(map(wire, prefix + [semantic[n] for n in range(1, 5)])))
    note("replayed")
    if not stream_steps["cancel"].wait(120):
        raise ValueError("the cancellation was never released")
    sock.sendall(wire(semantic[5]))
    stream_done["cancel"].set()
    for _ in reader:
        pass

def unicode_replay(sock, reader):
    """Release original multipart tool output after its initial running row is visible."""
    frames = [json.loads(line) for line in REPLAY]
    parts = {n: [] for n in range(1, 8)}
    for frame in frames:
        event = frame.get("event", {})
        if frame.get("type") == "event" and event.get("type") == "semantic" and event.get("cursor") in parts:
            parts[event["cursor"]].append(frame)
    for cursor, group in parts.items():
        if not group or [f["event"]["part"] for f in group] != list(range(len(group))) or any(
                f["event"]["parts"] != len(group) for f in group):
            raise ValueError(f"Unicode capture has incomplete cursor {cursor}")
    result = json.loads(b"".join(base64.b64decode(f["event"]["data"]) for f in parts[4]))
    if result.get("name") != "proof_unicode" or result.get("status") != "completed":
        raise ValueError("Unicode capture has no completed proof tool")
    partial = json.loads(base64.b64decode(parts[6][0]["event"]["data"]))
    final = json.loads(base64.b64decode(parts[7][0]["event"]["data"]))
    if not (partial.get("kind") == "message" and not partial.get("complete")
            and "proof_unicode_response" in partial.get("text", "")
            and final.get("id") == partial.get("id") and final.get("complete")
            and final.get("text") == ""):
        raise ValueError("capture has no matching partial and empty final")
    def wire(frame):
        return json.dumps(frame, separators=(",", ":")).encode() + b"\n"
    prefix = [f for f in frames if f.get("type") == "subscribed"
              or (f.get("type") == "event" and f.get("event", {}).get("type") == "state")]
    sock.sendall(b"".join(wire(f) for f in prefix + sum((parts[n] for n in range(1, 4)), [])))
    note("replayed")
    if not stream_steps["unicode"].wait(120):
        raise ValueError("the Unicode result was never released")
    sock.sendall(b"".join(map(wire, parts[4])))
    stream_done["unicode"].set()
    for step, cursor in (("partial", 6), ("empty-final", 7)):
        if not stream_steps[step].wait(120):
            raise ValueError(f"the Unicode {step} was never released")
        # Cursor 5 is the earlier partial; send it before the later captured partial.
        if step == "partial":
            sock.sendall(b"".join(map(wire, parts[5])))
        sock.sendall(b"".join(map(wire, parts[cursor])))
        stream_done[step].set()
    for _ in reader:
        pass

def async_replay(sock, reader):
    """Send captured semantic records only, releasing later states while the app watches."""
    frames = [json.loads(line) for line in REPLAY]
    semantic = {f["event"]["cursor"]: f for f in frames
                if f.get("type") == "event" and f.get("event", {}).get("type") == "semantic"}
    if set(semantic) != set(range(1, 16)) or any(f["event"]["parts"] != 1 for f in semantic.values()):
        raise ValueError("async capture does not have the expected semantic records")
    payloads = {n: json.loads(base64.b64decode(f["event"]["data"])) for n, f in semantic.items()}
    if not (payloads[6].get("kind") == "job" and payloads[6].get("status") == "running"
            and payloads[10].get("kind") == "job" and payloads[10].get("status") == "completed"
            and payloads[13].get("kind") == "tool" and payloads[13].get("status") == "error"):
        raise ValueError("async capture has unexpected job or error outcomes")
    def wire(frame):
        return json.dumps(frame, separators=(",", ":")).encode() + b"\n"
    prefix = [f for f in frames if f.get("type") == "subscribed"
              or (f.get("type") == "event" and f.get("event", {}).get("type") == "state")]
    sock.sendall(b"".join(map(wire, prefix + [semantic[n] for n in range(1, 6)])))
    note("replayed")
    for step, start, end in (("job", 6, 9), ("complete", 9, 12), ("error", 12, 16)):
        if not stream_steps[step].wait(120):
            raise ValueError(f"the async {step} stage was never released")
        sock.sendall(b"".join(wire(semantic[n]) for n in range(start, end)))
        stream_done[step].set()
    # Keep the subscription open while the app reads the last outcome.
    for _ in reader:
        pass


def stream_replay(sock, reader):
    """Stage the real captured progress while the app watches and its image fetch is held.

    The captured media answer is moved between the second and final tool updates. Cursor
    numbers are reassigned contiguously; the semantic payloads themselves are unchanged.
    """
    frames = [json.loads(line) for line in REPLAY]
    semantic = {f["event"]["cursor"]: f for f in frames
                if f.get("type") == "event" and f.get("event", {}).get("type") == "semantic"}
    if set(semantic) != set(range(1, 10)) or any(f["event"]["parts"] != 1 for f in semantic.values()):
        raise ValueError("streaming capture does not have the expected complete semantic records")
    def wire(frame, cursor=None):
        frame = json.loads(json.dumps(frame))
        if cursor is not None:
            frame["event"]["cursor"] = cursor
        return json.dumps(frame, separators=(",", ":")).encode() + b"\n"
    first = next(i for i, f in enumerate(frames) if f is semantic[6])
    sock.sendall(b"".join(wire(f) for f in frames[:first]))
    note("replayed")
    line = reader.readline()
    if not line:
        raise ValueError("media request never arrived")
    request = json.loads(line)
    media_id = next(iter(ANSWERS))
    if request.get("type") != "media" or request.get("id") != media_id:
        raise ValueError(f"unexpected streaming media request: {request!r}")
    note("requested", media_id)
    if not stream_steps["advance"].wait(120):
        raise ValueError("streaming progress was never released")
    sock.sendall(wire(semantic[6]))
    stream_done["advance"].set()
    if not stream_steps["release"].wait(120):
        raise ValueError("streaming media was never released")
    sock.sendall(wire(semantic[9], 7))
    note("answered", media_id)
    stream_done["release"].set()
    if not stream_steps["finish"].wait(120):
        raise ValueError("streaming final was never released")
    for f in frames[first:]:
        event = f.get("event", {})
        cursor = event.get("cursor") if event.get("type") == "semantic" else None
        if cursor in (6, 9):
            continue
        sock.sendall(wire(f, cursor + 1 if cursor is not None else None))
    stream_done["finish"].set()
    # An attacker-controlled peer can also send Markdown. Unlike the preceding capture,
    # this record is deliberately crafted by the proof to exercise the URL boundary.
    if not stream_steps["link"].wait(120):
        raise ValueError("attacker link was never released")
    target = os.environ.get("VOX_PROOF_LINK_URL", "")
    safe = os.environ.get("VOX_PROOF_HTTP_URL", "")
    if not target or not safe:
        raise ValueError("the attacker link targets are missing")
    attack = json.loads(json.dumps(semantic[8]))
    attack["event"]["data"] = base64.b64encode(json.dumps({
        "kind": "message", "id": "proof-untrusted-link", "role": "assistant",
        "text": f"Follow [unsafe-link]({target}) or [safe-link]({safe})", "complete": True
    }, separators=(",", ":")).encode()).decode()
    sock.sendall(wire(attack, 10))
    stream_done["link"].set()
    cursor = 10
    for line in reader:
        request = json.loads(line)
        if request.get("type") == "media" and request.get("id") in ANSWERS:
            note("requested", request["id"])
            cursor += 1
            sock.sendall(b"".join(wire(f, cursor) for f in ANSWERS[request["id"]]))
            note("answered", request["id"])


directory = tempfile.mkdtemp(prefix="vox-omp-")
os.chmod(directory, 0o700)
ENDPOINT = os.path.join(directory, "bridge.sock")


def note(key, value=None):
    with changed:
        state[key] = state[key] + 1 if value is None else state[key] + [value]
        changed.notify_all()


def serve(sock):
    reader = sock.makefile("rb")
    try:
        auth = json.loads(reader.readline() or b"{}")
        if auth.get("type") != "auth" or not secrets.compare_digest(str(auth.get("token", "")), TOKEN):
            return
        first = json.loads(reader.readline() or b"{}")
        if first.get("type") == "route":
            available = first.get("session") == SESSION
            sock.sendall((json.dumps({"outcome": "available", "session": SESSION, "route": ROUTE, "client": ROUTE,
                                      "admission": True} if available else {"outcome": "unavailable"}) + "\n").encode())
            return
        if first.get("type") == "attention":
            sock.sendall((json.dumps({"id": first.get("id"), "outcome": "unavailable",
                                      "error": "The exact Session route is unavailable"}) + "\n").encode())
            return
        if first.get("type") != "subscribe" or first.get("session") != SESSION:
            return
        note("subscriptions")
        if cancel_streaming:
            cancel_replay(sock, reader)
            return
        if unicode_streaming:
            unicode_replay(sock, reader)
            return
        if async_streaming:
            async_replay(sock, reader)
            return
        if streaming:
            stream_replay(sock, reader)
            return
        position = 0
        while position < len(REPLAY):
            if position in GATES:
                if position == min(GATES):
                    note("replayed")
                line = reader.readline()
                if not line:
                    print("replay: the daemon closed the bridge before asking for the captured media", file=sys.stderr)
                    return
                request = json.loads(line)
                if request.get("type") != "media":
                    print(f"replay: unexpected daemon frame {request.get('type')!r}; closing", file=sys.stderr)
                    return
                note("requested", request.get("id"))
                if request.get("id") != GATES[position]:
                    print("replay: the daemon asked for media the capture did not answer here; closing", file=sys.stderr)
                    return
                note("answered", request.get("id"))
            end = min([gate for gate in GATES if gate > position] + [len(REPLAY)])
            sock.sendall(b"".join(REPLAY[position:end]))
            position = end
        # The capture's extension stayed connected; so does this one. A media id it answered is
        # answered again, as the extension reads the same item again; nothing else is.
        cursor = CURSOR
        for line in reader:
            request = json.loads(line)
            if request.get("type") == "media":
                note("requested", request.get("id"))
                if request.get("id") in ANSWERS:
                    cursor += 1
                    for frame in ANSWERS[request["id"]]:
                        frame["event"]["cursor"] = cursor
                    sock.sendall(b"".join(json.dumps(frame, separators=(",", ":")).encode() + b"\n"
                                          for frame in ANSWERS[request["id"]]))
                    note("answered", request.get("id"))
    except (OSError, ValueError):
        pass
    finally:
        sock.close()


listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
listener.bind(ENDPOINT)
os.chmod(ENDPOINT, 0o600)
listener.listen(8)


def accept():
    while True:
        conn, _ = listener.accept()
        threading.Thread(target=serve, args=(conn,), daemon=True).start()


threading.Thread(target=accept, daemon=True).start()
watcher = subprocess.Popen([VOX, "agent", "omp-watch", "--node", NODE], stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE, stderr=sys.stderr)
frames = []
frame_seen = threading.Condition()


def read_watcher():
    for line in watcher.stdout:
        with frame_seen:
            frames.append(json.loads(line))
            frame_seen.notify_all()


threading.Thread(target=read_watcher, daemon=True).start()


def await_frame(match, within):
    deadline = time.monotonic() + within
    with frame_seen:
        while True:
            for frame in frames:
                if match(frame):
                    return frame
            remaining = deadline - time.monotonic()
            if remaining <= 0 or watcher.poll() is not None:
                raise RuntimeError(f"omp-watch never said what was awaited; it said {frames}")
            frame_seen.wait(remaining)


def command(identity, **fields):
    watcher.stdin.write((json.dumps({"id": identity, **fields}) + "\n").encode())
    watcher.stdin.flush()
    ack = await_frame(lambda f: f.get("type") == "ack" and f.get("id") == identity, 30)
    if ack.get("ok") is not True:
        raise RuntimeError(f"omp-watch refused {fields['op']}: {ack}")


def register():
    instance = await_frame(lambda f: f.get("type") == "owner", 30)["instance"]
    await_frame(lambda f: f.get("type") == "ready", 60)
    generation = secrets.token_hex(32)
    command("1", op="revoke")
    command("2", op="install", generation=generation, session=SESSION, endpoint=ENDPOINT, token=TOKEN, route=ROUTE)
    env = dict(os.environ, VOX_NODE=NODE, VOX_HARNESS="omp", VOX_SESSION=SESSION,
               VOX_OPENCODE_WAKE_SOCKET=ENDPOINT, VOX_OPENCODE_WAKE_TOKEN=TOKEN,
               VOX_OPENCODE_MIRROR_SOCKET=ENDPOINT, VOX_OPENCODE_ATTENTION_SOCKET=ENDPOINT,
               VOX_OPENCODE_ATTENTION_TOKEN=TOKEN, VOX_OPENCODE_ATTENTION_ROUTE=ROUTE,
               VOX_OMP_INSTANCE=instance, VOX_OMP_GENERATION=generation)
    for name in ("CODEX_THREAD_ID", "CLAUDE_CODE_SESSION_ID", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_CODE_MESSAGING_SOCKET",
                 "CLAUDE_CODE_MESSAGING_TOKEN", "OPENCODE_SESSION_ID", "VOX_OPENCODE_HEADLESS"):
        env.pop(name, None)
    said = []
    for step in ("--attention-register", "--omp-check-uncertainty"):
        # The extension's own retry schedule for a temporarily unavailable registration.
        for delay in (1, 2, 4, 8, 16, 30, None):
            hook = subprocess.run([VOX, "agent", "hook", "--node", NODE, "--session", SESSION, step], env=env,
                                  stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
            said.append(f"{step} exited {hook.returncode}: {hook.stderr.decode(errors='replace').strip()}")
            if hook.returncode == 0:
                break
            if hook.returncode != 75 or delay is None:
                raise RuntimeError("; ".join(said))
            time.sleep(delay)
    return {"session": SESSION}


def served(count, within):
    deadline = time.monotonic() + within
    with changed:
        while len(state["answered"]) < count and time.monotonic() < deadline:
            changed.wait(deadline - time.monotonic())
        return dict(state)

def requested(count, within):
    deadline = time.monotonic() + within
    with changed:
        while len(state["requested"]) < count and time.monotonic() < deadline:
            changed.wait(deadline - time.monotonic())
        return dict(state)


def advance_stream(step):
    if not streaming and not async_streaming and not unicode_streaming and not cancel_streaming:
        raise ValueError("streaming was not requested")
    stream_steps[step].set()
    if not stream_done[step].wait(30):
        raise ValueError(f"the streaming {step} frame was not sent")
    return {"step": step}




for raw in sys.stdin:
    words = raw.split()
    try:
        if words == ["register"]:
            reply = register()
        elif len(words) == 3 and words[0] == "served":
            reply = served(int(words[1]), float(words[2]))
        elif len(words) == 3 and words[0] == "requested":
            reply = requested(int(words[1]), float(words[2]))
        elif len(words) == 1 and words[0] in stream_steps:
            reply = advance_stream(words[0])
        else:
            reply = {"kind": "apparatus", "error": f"unknown command {raw.strip()!r}"}
    except Exception as error:  # every staging failure is the apparatus's, said as such
        reply = {"kind": "apparatus", "error": str(error)}
    print(json.dumps(reply), flush=True)
watcher.stdin.close()
watcher.wait(5)
