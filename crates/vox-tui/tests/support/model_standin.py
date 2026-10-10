#!/usr/bin/env python3
"""A stand-in model server on loopback: no model, no network beyond 127.0.0.1.

It records every request a harness sends, as one JSON line, and answers each turn "ok".
It speaks just enough of Anthropic Messages (Claude Code), OpenAI Responses (Codex) and
OpenAI Chat Completions (OpenCode), all streamed, for a harness to finish its turn.

argv: <port file> <request log> [--run-status] [--script <dir>]. It binds 127.0.0.1:0 and
writes the port it got to the port file once it listens.

With --run-status it plays a model that does what the agent skill's description says at the
start of a session: when a turn offers a shell tool and the request carries the skill's
`vox agent status --harness` instruction, it answers with one call of that tool running
`vox agent status --harness <harness>`, the harness the endpoint names (Anthropic Messages:
claude, OpenAI Responses: codex, Chat Completions: opencode); when the turn carries that call's result, it answers
"VOX STATUS SAID:" and the result, word for word, so the harness prints it. Nothing else.

With --script <dir> it plays a model following the skill's instructions one command at a time:
when `<dir>/<harness>.cmds` holds lines and the turn offers a shell tool, it answers with one
call of that tool per line, in order (each followed by `echo "[exit $?]"`), one call per
request, the line chosen by how many results the turn already carries; once every line has a
result, it answers "VOX RAN:" and each line with its result, under `### <n> $ <line>`, so the
harness prints them, and writes the same to `<dir>/<harness>.ran`. The proof writes the
`.cmds` file before the turn and removes it after."""
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT_FILE, LOG = sys.argv[1], sys.argv[2]
RUN_STATUS = "--run-status" in sys.argv[3:]
SCRIPT = sys.argv[sys.argv.index("--script") + 1] if "--script" in sys.argv[3:] else None
REPLY = "ok"
TRIGGER = "vox agent status --harness"
SAID = "VOX STATUS SAID:\n"
RAN = "VOX RAN:\n"
HARNESS = {"messages": "claude", "responses": "codex", "chat": "opencode"}


def text_of(v):
    """Every string in v, joined."""
    if isinstance(v, str):
        return v
    if isinstance(v, list):
        return "\n".join(text_of(x) for x in v)
    if isinstance(v, dict):
        return "\n".join(text_of(x) for x in v.values())
    return ""


def tool_results(body, kind):
    """The text of every tool call's result this turn carries, in order."""
    out = []
    if kind == "messages":
        for m in body.get("messages", []):
            c = m.get("content")
            if isinstance(c, list):
                for part in c:
                    if isinstance(part, dict) and part.get("type") == "tool_result":
                        out.append(text_of(part.get("content")))
    elif kind == "responses":
        for item in body.get("input", []) if isinstance(body.get("input"), list) else []:
            if isinstance(item, dict) and item.get("type", "").endswith("_call_output"):
                out.append(text_of(item.get("output")))
    else:
        for m in body.get("messages", []):
            if m.get("role") == "tool":
                out.append(text_of(m.get("content")))
    return out


def script_of(kind):
    """The lines the proof gave this harness to run, or None."""
    if SCRIPT is None:
        return None
    try:
        with open(os.path.join(SCRIPT, HARNESS[kind] + ".cmds")) as f:
            lines = [l.rstrip("\n") for l in f if l.strip()]
    except OSError:
        return None
    return lines or None


def shell_tool(body, kind, cmd=None):
    """The turn's shell tool: (name, arguments running cmd, by default the status command), or
    None."""
    if cmd is None:
        cmd = f"vox agent status --harness {HARNESS[kind]}"
    names = []
    for t in body.get("tools", []) or []:
        if not isinstance(t, dict):
            continue
        names.append(t.get("name") or (t.get("function") or {}).get("name"))
    if kind == "messages" and "Bash" in names:
        return "Bash", {"command": cmd, "description": "Vox status"}
    if kind == "responses":
        if "exec_command" in names:
            return "exec_command", {"cmd": cmd}
        if "shell_command" in names:
            return "shell_command", {"command": cmd}
        if "shell" in names:
            return "shell", {"command": ["bash", "-lc", cmd]}
    if kind == "chat" and "bash" in names:
        # A command may wait on the proof (up to ten minutes), past the tool's two-minute default.
        return "bash", {"command": cmd, "description": "Vox status", "timeout": 600000}
    return None


def plan(body, kind):
    """What this turn answers: ("text", words) or ("tool", name, arguments)."""
    if not isinstance(body, dict):
        return ("text", REPLY)
    script = script_of(kind)
    if script is not None:
        results = tool_results(body, kind)
        if len(results) < len(script):
            tool = shell_tool(body, kind, script[len(results)] + '; echo "[exit $?]"')
            if tool:
                return ("tool",) + tool + (len(results),)
            return ("text", REPLY)
        ran = RAN + "".join(f"### {i} $ {c}\n{r}\n" for i, (c, r) in
                            enumerate(zip(script, results)))
        with open(os.path.join(SCRIPT, HARNESS[kind] + ".ran"), "w") as f:
            f.write(ran)
        return ("text", ran)
    if not RUN_STATUS:
        return ("text", REPLY)
    results = tool_results(body, kind)
    if results:
        return ("text", SAID + results[0])
    tool = shell_tool(body, kind)
    if tool and TRIGGER in json.dumps(body):
        return ("tool",) + tool + (0,)
    return ("text", REPLY)


def sse(h, event, data):
    if event:
        h.wfile.write(f"event: {event}\n".encode())
    h.wfile.write(f"data: {json.dumps(data)}\n\n".encode())


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _record(self, body):
        with open(LOG, "a") as f:
            f.write(json.dumps({"t": time.time(), "method": self.command,
                                "path": self.path, "body": body}) + "\n")

    def _json(self, b):
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_HEAD(self):
        self._record(None)
        self.send_response(200)
        self.send_header("content-length", "0")
        self.end_headers()

    def do_GET(self):
        self._record(None)
        self._json(b'{"data":[{"id":"stub-model","object":"model"}],"object":"list"}')

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace")
        try:
            body = json.loads(raw)
        except ValueError:
            body = raw
        self._record(body)
        p = self.path.split("?")[0]
        if p.endswith("/count_tokens"):
            self._json(b'{"input_tokens":10}')
            return
        if isinstance(body, dict) and body.get("stream") is False and p.endswith("/messages"):
            m = {"id": "msg_1", "type": "message", "role": "assistant",
                 "model": body.get("model", "x"),
                 "content": [{"type": "text", "text": REPLY}], "stop_reason": "end_turn",
                 "usage": {"input_tokens": 10, "output_tokens": 1}}
            self._json(json.dumps(m).encode())
            return
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("connection", "close")
        self.end_headers()
        if p.endswith("/messages"):
            model = body.get("model", "x") if isinstance(body, dict) else "x"
            act = plan(body, "messages")
            m = {"id": "msg_1", "type": "message", "role": "assistant", "model": model,
                 "content": [], "stop_reason": None,
                 "usage": {"input_tokens": 10, "output_tokens": 0}}
            sse(self, "message_start", {"type": "message_start", "message": m})
            if act[0] == "tool":
                sse(self, "content_block_start", {"type": "content_block_start", "index": 0,
                                                  "content_block": {"type": "tool_use",
                                                                    "id": f"toolu_{act[3]}",
                                                                    "name": act[1], "input": {}}})
                sse(self, "content_block_delta", {"type": "content_block_delta", "index": 0,
                                                  "delta": {"type": "input_json_delta",
                                                            "partial_json": json.dumps(act[2])}})
                stop = "tool_use"
            else:
                sse(self, "content_block_start", {"type": "content_block_start", "index": 0,
                                                  "content_block": {"type": "text", "text": ""}})
                sse(self, "content_block_delta", {"type": "content_block_delta", "index": 0,
                                                  "delta": {"type": "text_delta",
                                                            "text": act[1]}})
                stop = "end_turn"
            sse(self, "content_block_stop", {"type": "content_block_stop", "index": 0})
            sse(self, "message_delta", {"type": "message_delta",
                                        "delta": {"stop_reason": stop},
                                        "usage": {"output_tokens": 1}})
            sse(self, "message_stop", {"type": "message_stop"})
        elif p.endswith("/responses"):
            act = plan(body, "responses")
            if act[0] == "tool":
                item = {"type": "function_call", "id": f"fc_{act[3]}", "call_id": f"call_{act[3]}",
                        "name": act[1], "arguments": json.dumps(act[2]), "status": "completed"}
            else:
                item = {"type": "message", "id": "m1", "role": "assistant",
                        "status": "completed",
                        "content": [{"type": "output_text", "text": act[1],
                                     "annotations": []}]}
            sse(self, "response.created", {"type": "response.created", "response": {"id": "r1"}})
            sse(self, "response.output_item.done", {"type": "response.output_item.done",
                                                    "output_index": 0, "item": item})
            sse(self, "response.completed", {"type": "response.completed", "response": {
                "id": "r1", "output": [item],
                "usage": {"input_tokens": 10, "input_tokens_details": {"cached_tokens": 0},
                          "output_tokens": 1, "output_tokens_details": {"reasoning_tokens": 0},
                          "total_tokens": 11}}})
        else:  # chat completions
            act = plan(body, "chat")
            if act[0] == "tool":
                delta = {"role": "assistant", "tool_calls": [{
                    "index": 0, "id": f"call_{act[3]}", "type": "function",
                    "function": {"name": act[1], "arguments": json.dumps(act[2])}}]}
                finish = "tool_calls"
            else:
                delta = {"role": "assistant", "content": act[1]}
                finish = "stop"
            sse(self, None, {"id": "c1", "object": "chat.completion.chunk", "created": 0,
                             "model": "stub-model",
                             "choices": [{"index": 0, "finish_reason": None,
                                          "delta": delta}]})
            sse(self, None, {"id": "c1", "object": "chat.completion.chunk", "created": 0,
                             "model": "stub-model",
                             "choices": [{"index": 0, "delta": {}, "finish_reason": finish}],
                             "usage": {"prompt_tokens": 10, "completion_tokens": 1,
                                       "total_tokens": 11}})
            self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()


server = ThreadingHTTPServer(("127.0.0.1", 0), H)
with open(PORT_FILE + ".new", "w") as f:
    f.write(str(server.server_address[1]))
# The rename makes the port file appear whole.
os.rename(PORT_FILE + ".new", PORT_FILE)
server.serve_forever()
