#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "错误：请使用 root 权限运行安装脚本。" >&2
  exit 1
fi

SOURCE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
INSTALL_DIR=/opt/vps-guard
CONFIG_DIR=/etc/vps-guard
TOKEN_FILE=${CONFIG_DIR}/token

command -v python3 >/dev/null 2>&1 || {
  echo "错误：需要 Python 3.10 或更高版本。" >&2
  exit 1
}

install -d -m 0755 "${INSTALL_DIR}" "${CONFIG_DIR}"
install -d -m 0700 /var/log/vps-guard
cp -R "${SOURCE_DIR}/secure_panel" "${INSTALL_DIR}/"

if [[ ! -s ${TOKEN_FILE} ]]; then
  python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > "${TOKEN_FILE}"
  chmod 0600 "${TOKEN_FILE}"
fi

cat > /etc/systemd/system/vps-guard.service <<'EOF'
[Unit]
Description=VPS Guard Server Security Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/vps-guard
Environment=PYTHONUNBUFFERED=1
Environment=VPS_GUARD_HOST=127.0.0.1
Environment=VPS_GUARD_PORT=8787
Environment=VPS_GUARD_AUDIT=/var/log/vps-guard/audit.jsonl
ExecStart=/bin/sh -c 'exec python3 -m secure_panel.server --token "$(cat /etc/vps-guard/token)"'
Restart=on-failure
RestartSec=3
PrivateTmp=true
UMask=0077

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now vps-guard

echo
echo "VPS Guard 已安装并启动。"
echo "访问令牌：$(cat "${TOKEN_FILE}")"
echo "本机地址：http://127.0.0.1:8787"
echo "远程访问：ssh -L 8787:127.0.0.1:8787 root@服务器IP"
echo "然后在本地浏览器打开 http://127.0.0.1:8787"
