# VPS Guard 项目说明

## 项目定位

VPS Guard 是一个面向个人 VPS 和小型团队的本地优先服务器安全面板。它以安全状态可见、系统操作可控、部署路径清晰为核心目标。

## 当前结构

- `secure_panel/server.py`：零第三方依赖的 HTTP 服务、令牌认证和 API 路由。
- `secure_panel/system.py`：系统状态读取、参数校验、白名单操作和审计记录。
- `secure_panel/static/`：响应式 Web 控制台。
- `install.sh`：systemd 安装和初始化令牌。
- `uninstall.sh`：停止服务并移除程序，默认保留审计数据。
- `tests/`：令牌校验、命令边界和审计行为测试。

## 设计原则

1. 面板默认只绑定 `127.0.0.1`，远程访问使用 SSH 隧道。
2. 所有写操作都必须经过动作白名单和参数校验。
3. 不在仓库内保存令牌、服务器地址、密码或私钥。
4. 系统级操作应在执行前显示明确的二次确认。
5. 审计记录只追加，不因卸载而默认删除。
6. 产品文档、界面和部署脚本只呈现 VPS Guard 自身信息。

## 发布前检查

```bash
python -m unittest discover -s tests -v
python -m compileall -q secure_panel tests
node --check secure_panel/static/app.js
git diff --check
```

## 维护约定

- 新增系统动作时，必须同步增加参数校验和测试。
- 修改服务监听地址或认证方式时，必须同步更新 README 的部署说明。
- 修改版本时，同时更新 `secure_panel/__init__.py` 和健康检查返回值。
- 公开发布前检查仓库中没有令牌、私钥、真实服务器 IP 或个人设备信息。
