# 参与贡献

VPS Guard 欢迎围绕 Linux 主机网络安全的可验证改进。

提交代码前请运行：

```bash
python -m unittest discover -s tests -v
python -m compileall -q secure_panel tests
node --check secure_panel/static/app.js
git diff --check
```

新增系统动作必须同时提供参数校验、二次确认路径、审计记录和单元测试。新增读取能力应保持只读、明确数据来源，并避免把敏感日志或凭据返回给浏览器。请在 Pull Request 中说明威胁模型、兼容的发行版和回滚方式。
