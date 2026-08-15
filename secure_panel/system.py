from __future__ import annotations

import json
import ipaddress
import os
import platform
import re
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PORT_RE = re.compile(r"^(\d{1,5})/(tcp|udp)$")
IP_RE = re.compile(r"^[0-9a-fA-F:.]+$")
USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
SSH_FAILURE_PATTERNS = (
    re.compile(r"Failed \S+ for (?:invalid user )?(\S+) from ([0-9a-fA-F:.]+)"),
    re.compile(r"Invalid user \S+ from ([0-9a-fA-F:.]+)"),
    re.compile(r"authentication failure.*rhost=([0-9a-fA-F:.]+)"),
)
LISTENING_RE = re.compile(r"^(tcp|tcp6|udp|udp6)\s+LISTEN\s+\S+\s+\S+\s+(\S+)\s+\S+(?:\s+.*)?$")


class ActionError(RuntimeError):
    pass


@dataclass
class Result:
    ok: bool
    output: str


class SystemManager:
    def __init__(self, audit_path: Path | None = None) -> None:
        self.audit_path = audit_path or Path(os.environ.get("VPS_GUARD_AUDIT", "/var/log/vps-guard/audit.jsonl"))
        self.started = time.time()

    def run(self, command: list[str], timeout: int = 12) -> Result:
        try:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
            output = (proc.stdout + proc.stderr).strip()
            return Result(proc.returncode == 0, output[-12000:])
        except (OSError, subprocess.TimeoutExpired) as exc:
            return Result(False, str(exc))

    @staticmethod
    def _read(path: str, default: str = "") -> str:
        try:
            return Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return default

    @staticmethod
    def _service_state(name: str) -> str:
        if not shutil.which("systemctl"):
            return "unavailable"
        result = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True, check=False)
        return result.stdout.strip() or "inactive"

    def overview(self) -> dict[str, Any]:
        mem_total = mem_available = 0
        for line in self._read("/proc/meminfo").splitlines():
            if line.startswith("MemTotal:"):
                mem_total = int(line.split()[1]) * 1024
            elif line.startswith("MemAvailable:"):
                mem_available = int(line.split()[1]) * 1024
        memory = round((1 - mem_available / mem_total) * 100, 1) if mem_total else 0
        disk = shutil.disk_usage("/")
        try:
            loads = [round(value, 2) for value in os.getloadavg()]
        except (AttributeError, OSError):
            loads = [0, 0, 0]
        uptime = 0
        try:
            uptime = int(float(self._read("/proc/uptime", "0").split()[0]))
        except (ValueError, IndexError):
            pass
        cpu_count = os.cpu_count() or 1
        cpu_load = min(round(loads[0] / cpu_count * 100, 1), 100)
        sshd_state = self._service_state("sshd")
        return {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "kernel": platform.release(),
            "uptime": uptime,
            "cpu": cpu_load,
            "memory": memory,
            "disk": round(disk.used / disk.total * 100, 1),
            "load": loads,
            "services": {
                "ssh": self._service_state("ssh") if sshd_state != "active" else "active",
                "fail2ban": self._service_state("fail2ban"),
                "docker": self._service_state("docker"),
            },
            "panel_uptime": int(time.time() - self.started),
        }

    def ssh_status(self) -> dict[str, Any]:
        config = self._read("/etc/ssh/sshd_config")

        def value(key: str, fallback: str) -> str:
            matches = re.findall(rf"^\s*{re.escape(key)}\s+(\S+)", config, re.I | re.M)
            return matches[-1] if matches else fallback

        key_count = 0
        authorized = Path("/root/.ssh/authorized_keys")
        if authorized.exists():
            key_count = sum(1 for line in self._read(str(authorized)).splitlines() if line.strip() and not line.startswith("#"))
        sshd_state = self._service_state("sshd")
        return {
            "port": int(value("Port", "22")),
            "password_auth": value("PasswordAuthentication", "yes").lower() != "no",
            "root_login": value("PermitRootLogin", "prohibit-password"),
            "keys": key_count,
            "service": sshd_state if sshd_state == "active" else self._service_state("ssh"),
        }

    def firewall_status(self) -> dict[str, Any]:
        if shutil.which("ufw"):
            result = self.run(["ufw", "status", "numbered"])
            rules = [line.strip() for line in result.output.splitlines() if re.search(r"\bALLOW\b|\bDENY\b", line)]
            return {"provider": "ufw", "active": "Status: active" in result.output, "rules": rules}
        if shutil.which("firewall-cmd"):
            state = self.run(["firewall-cmd", "--state"])
            ports = self.run(["firewall-cmd", "--list-ports"])
            return {"provider": "firewalld", "active": state.ok, "rules": ports.output.split()}
        return {"provider": "none", "active": False, "rules": []}

    @staticmethod
    def _parse_listening_ports(output: str) -> list[dict[str, Any]]:
        ports: list[dict[str, Any]] = []
        seen: set[tuple[str, str, int]] = set()
        for line in output.splitlines():
            match = LISTENING_RE.match(line.strip())
            if not match:
                continue
            protocol, endpoint = match.groups()
            if endpoint.startswith("[") and "]:" in endpoint:
                address, port_text = endpoint.rsplit("]:", 1)
                address = address[1:]
            elif ":" in endpoint:
                address, port_text = endpoint.rsplit(":", 1)
            else:
                continue
            if not port_text.isdigit() or not 0 < int(port_text) <= 65535:
                continue
            port = int(port_text)
            key = (protocol, address, port)
            if key in seen:
                continue
            seen.add(key)
            public = address in {"0.0.0.0", "::", "*"} or address not in {"127.0.0.1", "::1", "localhost"}
            ports.append({"protocol": protocol.replace("6", ""), "address": address, "port": port, "public": public})
        return sorted(ports, key=lambda item: (not item["public"], item["port"], item["protocol"]))

    def network_exposure(self) -> dict[str, Any]:
        if not shutil.which("ss"):
            return {"available": False, "tool": "未找到 ss", "public_count": 0, "listening": [], "risk": "unknown"}
        result = self.run(["ss", "-lntuH"], 12)
        listening = self._parse_listening_ports(result.output)
        public_count = sum(1 for item in listening if item["public"])
        risk = "critical" if public_count >= 5 else "high" if public_count >= 2 else "medium" if public_count else "low"
        return {"available": result.ok, "tool": "ss", "public_count": public_count, "listening": listening, "risk": risk}

    def fail2ban_status(self) -> dict[str, Any]:
        if not shutil.which("fail2ban-client"):
            return {"installed": False, "active": False, "banned": [], "total": 0}
        result = self.run(["fail2ban-client", "status", "sshd"])
        match = re.search(r"Banned IP list:\s*(.*)", result.output)
        banned = match.group(1).split() if match else []
        return {"installed": True, "active": result.ok, "banned": banned, "total": len(banned)}

    def _auth_log_lines(self) -> tuple[list[str], str]:
        sources = ("/var/log/auth.log", "/var/log/secure")
        lines: list[str] = []
        used: list[str] = []
        for source in sources:
            content = self._read(source)
            if content:
                lines.extend(content.splitlines()[-20000:])
                used.append(source)
        if not lines and shutil.which("journalctl"):
            result = self.run(["journalctl", "--since", "-24 hours", "-u", "ssh", "-u", "sshd", "--no-pager", "-o", "short-iso"], 20)
            if result.output:
                lines = result.output.splitlines()[-20000:]
                used.append("journalctl")
        return lines, ", ".join(used) or "未找到 SSH 认证日志"

    def brute_force_status(self) -> dict[str, Any]:
        lines, source = self._auth_log_lines()
        attacks: dict[str, dict[str, Any]] = {}
        recent: list[dict[str, Any]] = []
        for line in lines:
            match = None
            username = "unknown"
            for pattern in SSH_FAILURE_PATTERNS:
                candidate = pattern.search(line)
                if candidate:
                    match = candidate
                    if len(candidate.groups()) == 2:
                        username = candidate.group(1)
                    break
            if not match:
                continue
            ip = match.group(2) if len(match.groups()) == 2 else match.group(1)
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            item = attacks.setdefault(ip, {"ip": ip, "attempts": 0, "usernames": set(), "last_seen": "未知"})
            item["attempts"] += 1
            item["usernames"].add(username)
            timestamp = line[:19].strip()
            if timestamp:
                item["last_seen"] = timestamp
            if len(recent) < 12:
                recent.append({"ip": ip, "username": username, "raw": line[:180]})
        top = []
        for item in sorted(attacks.values(), key=lambda value: value["attempts"], reverse=True):
            attempts = item["attempts"]
            risk = "critical" if attempts >= 50 else "high" if attempts >= 20 else "medium" if attempts >= 5 else "low"
            top.append({"ip": item["ip"], "attempts": attempts, "usernames": sorted(item["usernames"])[:8], "last_seen": item["last_seen"], "risk": risk})
        return {
            "available": bool(lines),
            "window_hours": 24,
            "log_source": source,
            "total_attempts": sum(item["attempts"] for item in attacks.values()),
            "unique_ips": len(top),
            "top_ips": top[:30],
            "recent": recent,
        }

    def users(self) -> list[dict[str, Any]]:
        users: list[dict[str, Any]] = []
        for line in self._read("/etc/passwd").splitlines():
            fields = line.split(":")
            if len(fields) >= 7 and fields[2].isdigit() and int(fields[2]) >= 1000 and fields[0] != "nobody":
                users.append({"name": fields[0], "uid": int(fields[2]), "home": fields[5], "shell": fields[6]})
        return users

    def audit(self, limit: int = 80) -> list[dict[str, Any]]:
        try:
            lines = self.audit_path.read_text(encoding="utf-8").splitlines()[-limit:]
        except OSError:
            return []
        entries = []
        for line in reversed(lines):
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return entries

    def record(self, action: str, actor: str, ok: bool, detail: str) -> None:
        entry = {"time": int(time.time()), "action": action, "actor": actor, "ok": ok, "detail": detail[:500]}
        try:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError:
            pass

    def act(self, action: str, args: dict[str, Any], actor: str) -> Result:
        if action == "restart_ssh":
            service = "sshd" if self._service_state("sshd") == "active" else "ssh"
            result = self.run(["systemctl", "restart", service], 25)
        elif action == "restart_fail2ban":
            result = self.run(["systemctl", "restart", "fail2ban"], 25)
        elif action == "reload_firewall":
            if shutil.which("ufw"):
                result = self.run(["ufw", "reload"], 25)
            elif shutil.which("firewall-cmd"):
                result = self.run(["firewall-cmd", "--reload"], 25)
            else:
                raise ActionError("未检测到 UFW 或 firewalld")
        elif action in {"allow_port", "deny_port"}:
            port = str(args.get("port", ""))
            if not PORT_RE.fullmatch(port) or int(port.split("/")[0]) > 65535:
                raise ActionError("端口格式应为 1-65535/tcp 或 1-65535/udp")
            if shutil.which("ufw"):
                verb = "allow" if action == "allow_port" else "deny"
                result = self.run(["ufw", verb, port], 25)
            elif shutil.which("firewall-cmd"):
                flag = "--add-port" if action == "allow_port" else "--remove-port"
                result = self.run(["firewall-cmd", "--permanent", f"{flag}={port}"], 25)
                if result.ok:
                    self.run(["firewall-cmd", "--reload"], 25)
            else:
                raise ActionError("未检测到 UFW 或 firewalld")
        elif action in {"unban_ip", "ban_ip"}:
            ip = str(args.get("ip", ""))
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                raise ActionError("IP 地址格式无效")
            operation = "unbanip" if action == "unban_ip" else "banip"
            result = self.run(["fail2ban-client", "set", "sshd", operation, ip])
        elif action == "lock_user":
            user = str(args.get("user", ""))
            if not USER_RE.fullmatch(user) or user == "root":
                raise ActionError("用户名无效或不允许锁定 root")
            result = self.run(["usermod", "--lock", user])
        else:
            raise ActionError("不支持的操作")
        self.record(action, actor, result.ok, result.output or ("完成" if result.ok else "失败"))
        return result


class DemoSystemManager(SystemManager):
    """Read-only data source used for screenshots and local UI development."""

    def overview(self) -> dict[str, Any]:
        return {
            "hostname": "edge-node-01",
            "platform": "Ubuntu 24.04.1 LTS",
            "kernel": "6.8.0-51-generic",
            "uptime": 1_324_920,
            "cpu": 18.4,
            "memory": 42.7,
            "disk": 36.2,
            "load": [0.37, 0.29, 0.21],
            "services": {"ssh": "active", "fail2ban": "active", "docker": "active"},
            "panel_uptime": 5832,
        }

    def ssh_status(self) -> dict[str, Any]:
        return {"port": 22022, "password_auth": False, "root_login": "prohibit-password", "keys": 2, "service": "active"}

    def firewall_status(self) -> dict[str, Any]:
        return {
            "provider": "ufw",
            "active": True,
            "rules": ["[ 1] 22022/tcp ALLOW IN Anywhere", "[ 2] 80/tcp ALLOW IN Anywhere", "[ 3] 443/tcp ALLOW IN Anywhere"],
        }

    def network_exposure(self) -> dict[str, Any]:
        return {
            "available": True,
            "tool": "ss",
            "public_count": 3,
            "risk": "high",
            "listening": [
                {"protocol": "tcp", "address": "0.0.0.0", "port": 22022, "public": True},
                {"protocol": "tcp", "address": "0.0.0.0", "port": 443, "public": True},
                {"protocol": "tcp", "address": "127.0.0.1", "port": 8787, "public": False},
                {"protocol": "udp", "address": "127.0.0.1", "port": 323, "public": False},
            ],
        }

    def fail2ban_status(self) -> dict[str, Any]:
        return {"installed": True, "active": True, "banned": ["198.51.100.24", "203.0.113.81"], "total": 2}

    def brute_force_status(self) -> dict[str, Any]:
        return {
            "available": True,
            "window_hours": 24,
            "log_source": "journalctl",
            "total_attempts": 87,
            "unique_ips": 4,
            "top_ips": [
                {"ip": "198.51.100.42", "attempts": 52, "usernames": ["root", "admin"], "last_seen": "2026-08-15 08:22:41", "risk": "critical"},
                {"ip": "203.0.113.77", "attempts": 21, "usernames": ["ubuntu"], "last_seen": "2026-08-15 07:48:10", "risk": "high"},
                {"ip": "192.0.2.19", "attempts": 9, "usernames": ["test"], "last_seen": "2026-08-15 06:13:02", "risk": "medium"},
            ],
            "recent": [],
        }

    def users(self) -> list[dict[str, Any]]:
        return [{"name": "operator", "uid": 1000, "home": "/home/operator", "shell": "/bin/bash"}]

    def audit(self, limit: int = 80) -> list[dict[str, Any]]:
        now = int(time.time())
        return [
            {"time": now - 420, "action": "reload_firewall", "actor": "127.0.0.1", "ok": True, "detail": "Firewall reloaded"},
            {"time": now - 3600, "action": "unban_ip", "actor": "127.0.0.1", "ok": True, "detail": "192.0.2.17"},
        ]

    def act(self, action: str, args: dict[str, Any], actor: str) -> Result:
        raise ActionError("演示模式不允许执行系统操作")
