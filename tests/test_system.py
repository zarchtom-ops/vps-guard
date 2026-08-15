import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from secure_panel.system import ActionError, Result, SystemManager


class FakeManager(SystemManager):
    def __init__(self, audit_path: Path):
        super().__init__(audit_path)
        self.commands = []

    def run(self, command, timeout=12):
        self.commands.append(command)
        return Result(True, "ok")


class SystemManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.audit = Path(self.temp.name) / "audit.jsonl"
        self.manager = FakeManager(self.audit)

    def tearDown(self):
        self.temp.cleanup()

    @patch("secure_panel.system.shutil.which", side_effect=lambda command: "/usr/sbin/ufw" if command == "ufw" else None)
    def test_allow_port_uses_argument_array(self, _which):
        result = self.manager.act("allow_port", {"port": "443/tcp"}, "127.0.0.1")
        self.assertTrue(result.ok)
        self.assertEqual(self.manager.commands[0], ["ufw", "allow", "443/tcp"])

    def test_rejects_shell_injection_in_port(self):
        with self.assertRaises(ActionError):
            self.manager.act("allow_port", {"port": "22/tcp;reboot"}, "127.0.0.1")
        self.assertEqual(self.manager.commands, [])

    def test_cannot_lock_root(self):
        with self.assertRaises(ActionError):
            self.manager.act("lock_user", {"user": "root"}, "127.0.0.1")

    @patch("secure_panel.system.shutil.which", return_value="/usr/sbin/ufw")
    def test_action_is_audited(self, _which):
        self.manager.act("deny_port", {"port": "53/udp"}, "10.0.0.2")
        entry = json.loads(self.audit.read_text(encoding="utf-8"))
        self.assertEqual(entry["action"], "deny_port")
        self.assertEqual(entry["actor"], "10.0.0.2")
        self.assertTrue(entry["ok"])

    @patch("secure_panel.system.shutil.which", return_value=None)
    @patch.object(SystemManager, "_read", side_effect=lambda path, default="": "Aug 15 08:20:01 host sshd[1]: Failed password for root from 198.51.100.8 port 22 ssh2\nAug 15 08:20:02 host sshd[1]: Invalid user admin from 198.51.100.8 port 22" if path == "/var/log/auth.log" else "")
    def test_brute_force_groups_failed_logins(self, _read, _which):
        result = self.manager.brute_force_status()
        self.assertTrue(result["available"])
        self.assertEqual(result["total_attempts"], 2)
        self.assertEqual(result["top_ips"][0]["ip"], "198.51.100.8")
        self.assertEqual(result["top_ips"][0]["attempts"], 2)

    def test_rejects_invalid_ban_ip(self):
        with self.assertRaises(ActionError):
            self.manager.act("ban_ip", {"ip": "198.51.100.1;reboot"}, "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
