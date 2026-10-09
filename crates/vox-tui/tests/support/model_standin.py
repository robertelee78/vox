#!/usr/bin/env python3
"""A stand-in model server on loopback: no model, no network beyond 127.0.0.1.

It records every request a harness sends, as one JSON line, and answers each turn "ok".
It speaks just enough of Anthropic Messages (Claude Code), OpenAI Responses (Codex) and
OpenAI Chat Completions (OpenCode), all streamed, for a harness to finish its turn.

argv: <port file> <request log>. It binds 127.0.0.1:0 and writes the port it got to the
port file once it listens."""
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT_FILE, LOG = sys.argv[1], sys.argv[2]
REPLY = "ok"


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
            m = {"id": "msg_1", "type": "message", "role": "assistant", "model": model,
                 "content": [], "stop_reason": None,
                 "usage": {"input_tokens": 10, "output_tokens": 0}}
            sse(self, "message_start", {"type": "message_start", "message": m})
            sse(self, "content_block_start", {"type": "content_block_start", "index": 0,
                                              "content_block": {"type": "text", "text": ""}})
            sse(self, "content_block_delta", {"type": "content_block_delta", "index": 0,
                                              "delta": {"type": "text_delta", "text": REPLY}})
            sse(self, "content_block_stop", {"type": "content_block_stop", "index": 0})
            sse(self, "message_delta", {"type": "message_delta",
                                        "delta": {"stop_reason": "end_turn"},
                                        "usage": {"output_tokens": 1}})
            sse(self, "message_stop", {"type": "message_stop"})
        elif p.endswith("/responses"):
            item = {"type": "message", "id": "m1", "role": "assistant", "status": "completed",
                    "content": [{"type": "output_text", "text": REPLY, "annotations": []}]}
            sse(self, "response.created", {"type": "response.created", "response": {"id": "r1"}})
            sse(self, "response.output_item.done", {"type": "response.output_item.done",
                                                    "output_index": 0, "item": item})
            sse(self, "response.completed", {"type": "response.completed", "response": {
                "id": "r1", "output": [item],
                "usage": {"input_tokens": 10, "input_tokens_details": {"cached_tokens": 0},
                          "output_tokens": 1, "output_tokens_details": {"reasoning_tokens": 0},
                          "total_tokens": 11}}})
        else:  # chat completions
            sse(self, None, {"id": "c1", "object": "chat.completion.chunk", "created": 0,
                             "model": "stub-model",
                             "choices": [{"index": 0, "finish_reason": None,
                                          "delta": {"role": "assistant", "content": REPLY}}]})
            sse(self, None, {"id": "c1", "object": "chat.completion.chunk", "created": 0,
                             "model": "stub-model",
                             "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
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
