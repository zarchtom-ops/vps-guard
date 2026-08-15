from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import mimetypes
import os
import secrets
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from . import __version__
from .system import ActionError, DemoSystemManager, SystemManager


STATIC = Path(__file__).with_name("static")


class PanelServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], token: str, manager: SystemManager):
        super().__init__(address, PanelHandler)
        self.token_hash = hashlib.sha256(token.encode()).digest()
        self.manager = manager


class PanelHandler(BaseHTTPRequestHandler):
    server: PanelServer
    server_version = "VPSGuard"
    sys_version = ""

    def log_message(self, format: str, *args: object) -> None:
        print(f"{self.client_address[0]} - {format % args}")

    def _json(self, payload: object, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        supplied = self.headers.get("X-Panel-Token", "")
        digest = hashlib.sha256(supplied.encode()).digest()
        return bool(supplied) and hmac.compare_digest(digest, self.server.token_hash)

    def _body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 16384:
                raise ValueError
            return json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            raise ActionError("请求内容无效")

    def _static(self, path: str) -> None:
        relative = "index.html" if path == "/" else path.lstrip("/")
        target = (STATIC / relative).resolve()
        if STATIC.resolve() not in target.parents or not target.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        body = target.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", mimetypes.guess_type(target.name)[0] or "application/octet-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if not path.startswith("/api/"):
            self._static(path)
            return
        if path == "/api/health":
            self._json({"ok": True, "version": __version__})
            return
        if not self._authorized():
            self._json({"error": "认证失败"}, HTTPStatus.UNAUTHORIZED)
            return
        manager = self.server.manager
        routes = {
            "/api/overview": manager.overview,
            "/api/ssh": manager.ssh_status,
            "/api/firewall": manager.firewall_status,
            "/api/network": manager.network_exposure,
            "/api/fail2ban": manager.fail2ban_status,
            "/api/bruteforce": manager.brute_force_status,
            "/api/users": manager.users,
            "/api/audit": manager.audit,
        }
        handler = routes.get(path)
        if not handler:
            self._json({"error": "接口不存在"}, HTTPStatus.NOT_FOUND)
            return
        try:
            self._json(handler())
        except Exception as exc:
            self._json({"error": "读取系统状态失败", "detail": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/api/action":
            self._json({"error": "接口不存在"}, HTTPStatus.NOT_FOUND)
            return
        if not self._authorized():
            self._json({"error": "认证失败"}, HTTPStatus.UNAUTHORIZED)
            return
        try:
            body = self._body()
            if body.get("confirm") != "CONFIRM":
                raise ActionError("操作缺少确认标记")
            result = self.server.manager.act(str(body.get("action", "")), body.get("args", {}), self.client_address[0])
            self._json({"ok": result.ok, "output": result.output}, 200 if result.ok else 409)
        except ActionError as exc:
            self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)


def load_token(value: str | None) -> str:
    token = value or os.environ.get("VPS_GUARD_TOKEN", "")
    if len(token) < 24:
        raise SystemExit("VPS_GUARD_TOKEN 至少需要 24 个字符")
    return token


def main() -> None:
    parser = argparse.ArgumentParser(description="VPS Guard security panel")
    parser.add_argument("--host", default=os.environ.get("VPS_GUARD_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("VPS_GUARD_PORT", "8787")))
    parser.add_argument("--token")
    parser.add_argument("--generate-token", action="store_true")
    parser.add_argument("--demo", action="store_true", help="use read-only sample data")
    args = parser.parse_args()
    if args.generate_token:
        print(secrets.token_urlsafe(32))
        return
    manager = DemoSystemManager() if args.demo else SystemManager()
    server = PanelServer((args.host, args.port), load_token(args.token), manager)
    print(f"VPS Guard {__version__} listening on http://{args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
