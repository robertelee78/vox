#!/usr/bin/env python3
"""A stand-in model server on loopback: no model, no network beyond 127.0.0.1.

It records every request a harness sends, as one JSON line, and answers each turn "ok".
It speaks just enough of Anthropic Messages (Claude Code), OpenAI Responses (Codex) and
OpenAI Chat Completions (OpenCode), all streamed, for a harness to finish its turn.

argv: <port file> <request log> [--run-status]. It binds 127.0.0.1:0 and writes the
port it got to the port file once it listens.

With --run-status it plays a model that does what the agent skill's description says at the
start of a session: when a turn offers a shell tool and the request carries the skill's
`vox agent status --harness` instruction, it answers with one call of that tool running
`vox agent status --harness <harness>`, the harness the endpoint names (Anthropic Messages:
claude, OpenAI Responses: codex, Chat Completions: opencode); when the turn carries that call's result, it answers
"VOX STATUS SAID:" and the result, word for word, so the harness prints it. Nothing else."""
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT_FILE, LOG = sys.argv[1], sys.argv[2]
RUN_STATUS = len(sys.argv) > 3 and sys.argv[3] == "--run-status"
REPLY = "ok"
TRIGGER = "vox agent status --harness"
SAID = "VOX STATUS SAID:\n"


def text_of(v):
    """Every string in v, joined."""
    if isinstance(v, str):
        return v
    if isinstance(v, list):
        return "\n".join(text_of(x) for x in v)
    if isinstance(v, dict):
        return "\n".join(text_of(x) for x in v.values())
    return ""


def tool_result(body, kind):
    """The text of the status call's result in this turn, or None."""
    if kind == "messages":
        for m in body.get("messages", []):
            c = m.get("content")
            if isinstance(c, list):
                for part in c:
                    if isinstance(part, dict) and part.get("type") == "tool_result":
                        return text_of(part.get("content"))
    elif kind == "responses":
        for item in body.get("input", []) if isinstance(body.get("input"), list) else []:
            if isinstance(item, dict) and item.get("type", "").endswith("_call_output"):
                return text_of(item.get("output"))
    else:
        for m in body.get("messages", []):
            if m.get("role") == "tool":
                return text_of(m.get("content"))
    return None


def shell_tool(body, kind):
    """The turn's shell tool: (name, arguments for the status command), or None."""
    harness = {"messages": "claude", "responses": "codex", "chat": "opencode"}[kind]
    cmd = f"vox agent status --harness {harness}"
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
        return "bash", {"command": cmd, "description": "Vox status"}
    return None


def plan(body, kind):
    """What this turn answers: ("text", words) or ("tool", name, arguments)."""
    if not RUN_STATUS or not isinstance(body, dict):
        return ("text", REPLY)
    result = tool_result(body, kind)
    if result is not None:
        return ("text", SAID + result)
    tool = shell_tool(body, kind)
    if tool and TRIGGER in json.dumps(body):
        return ("tool",) + tool
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
                                                                    "id": "toolu_status",
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
                item = {"type": "function_call", "id": "fc_status", "call_id": "call_status",
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
                    "index": 0, "id": "call_status", "type": "function",
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
