# 域名管理系统 v7.7

基于 Cloudflare Workers + D1 的多域名跳转管理系统。Worker 代码、数据库初始化 SQL、小白部署教程和后台使用说明都在本仓库中。

## 功能

- 多入口域名管理，支持备注、分组、搜索和筛选
- 301/302 跳转、启用/暂停、批量管理
- 访问统计、访问记录、目标网址修改历史和操作日志
- 目标网址健康检查，支持手动检查和 Cron 定时检查
- 自动清理旧访问记录和操作日志
- 单管理员登录，密码和会话密钥通过 Cloudflare Worker Secrets 保存
- 自适应明暗外观和移动设备布局

## 文件

| 文件 | 说明 |
| --- | --- |
| `worker.js` | Cloudflare Worker 完整代码 |
| `database/schema.sql` | 全新 D1 数据库的初始化结构，仅用于首次建库 |
| `小白部署教程.md` | 从 Cloudflare Dashboard 部署、绑定和配置 Cron 的图文式步骤说明 |
| `系统使用说明.md` | 登录、域名管理、统计、日志和常见操作说明 |

## 快速开始

1. 在 Cloudflare 创建 D1 数据库，并通过 D1 Console 执行 `database/schema.sql`。
2. 创建 Worker，将 `worker.js` 粘贴到在线编辑器并部署。
3. 为 Worker 添加 D1 Binding：变量名 `DB`，绑定到刚创建的数据库。
4. 设置 `ADMIN_HOST`，并添加 `ADMIN_PASSWORD`、`SESSION_SECRET` 两个 Secret。
5. 配置 Cron：`*/15 * * * *` 和 `10 3 * * *`。
6. 按照 [小白部署教程](小白部署教程.md) 绑定域名并验证；后台日常操作见 [系统使用说明](系统使用说明.md)。

详细操作和现有部署升级注意事项请阅读 [小白部署教程](小白部署教程.md)。如果你已经在运行旧版本，请先确认数据库结构，不要直接重新执行初始化 SQL。

## 安全提示

- 不要把 `ADMIN_PASSWORD`、`SESSION_SECRET` 或 Cloudflare API Token 写进代码、截图或公开仓库。
- 管理后台应使用 HTTPS，并把 `ADMIN_HOST` 设置为专用管理主机。
- 初次配置和验证跳转时使用 302；确认长期规则后再改成 301。
- 数据库初始化脚本只为新数据库设计；升级已有数据库应按对应版本的迁移步骤操作。
