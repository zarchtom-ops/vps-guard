#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "错误：请使用 root 权限运行卸载脚本。" >&2
  exit 1
fi

systemctl disable --now vps-guard 2>/dev/null || true
rm -f /etc/systemd/system/vps-guard.service
rm -rf /opt/vps-guard
systemctl daemon-reload

echo "程序已移除。令牌和审计日志仍保留在 /etc/vps-guard 与 /var/log/vps-guard。"
