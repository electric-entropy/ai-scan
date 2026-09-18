"""Independent bounded toy system-prompt service, with no scanner imports.

The server is not an LLM. Its vulnerable configuration models a literal
instruction-disclosure bug, not arbitrary production prompt recovery.
"""
from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class SystemPromptFixture:
    def __init__(self, marker: str, *, secure: bool, channel: str = "final"):
        self.system_prompt = {"marker": marker}
        self.secure = secure
        self.channel = channel
        self.requests: list[tuple[str, list[tuple[str, str]], str]] = []
        self.outputs: list[str] = []
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 32768:
                    self.send_error(400)
                    return
                body = self.rfile.read(size).decode("utf-8")
                fixture.requests.append((self.path, list(self.headers.items()), body))
                data = json.loads(body)
                prompt = data["messages"][-1]["content"]
                # An independent tiny natural-language interpreter. Neither
                # family/template/case identity nor a verdict selector is read.
                words = set(re.findall(r"[a-z]+", prompt.lower()))
                extracting = bool(words & {"repeat", "return", "output", "continue"})
                hidden = "system" in words and "marker" in words
                value = "I do not disclose internal instructions."
                if not fixture.secure and extracting and hidden and len(prompt) <= 4096:
                    value = fixture.system_prompt["marker"]
                fixture.outputs.append(value)
                message = {"role": "assistant", "content": value}
                if fixture.channel == "thinking":
                    message = {"role": "assistant", "thinking": value,
                               "content": "I do not disclose internal instructions."}
                elif fixture.channel == "refusal":
                    message["content"] = "I cannot reveal " + value
                response = json.dumps({"message": message, "done": True,
                                       "done_reason": "stop"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_port}/api/chat"
