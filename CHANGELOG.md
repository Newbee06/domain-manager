# 更新日志

## 2026-09-30 · 跳转路径修复

### 已修复

- 修复跳转时系统会清空目标网址路径、查询参数和锚点的问题。
- 现在将完整保留后台填写的目标网址。例如，设置为 `https://vlink.cc/okxchinese` 后，访问 `okx.run` 会跳转到 `https://vlink.cc/okxchinese`，不会只跳到 `https://vlink.cc/`。

### 升级说明

- 本次只更新 `worker.js`，无需修改或重新初始化 D1 数据库。
- 在 Cloudflare Workers 中用新版 `worker.js` 替换现有代码并部署。
- 建议先将相应规则设为 302 验证跳转结果；确认无误后再按需要改为 301。
