# Egern 私有下载

使用已安装的 Wrangler、Node.js 和 Python 3.13（含 PyYAML）。在仓库根目录运行。

手动登录 Cloudflare：

```powershell
wrangler login --scopes account:read user:read workers:write workers_scripts:write
```

登录完成后部署：

```powershell
py -3.13 private-download/manage.py deploy
```

脚本创建独立 Worker 和私有 R2 存储，将根目录的 `Egern 精细分流.yaml` 上传。它不会自动登录，也不会启用 R2 公共访问。多账户时在部署命令后加 `--account-id <Account ID>`。

验证下载权限和文件内容后，脚本将导入链接保存到 `.private/download-link.txt`，并在本地 Egern 配置中写入 `auto_update`。新配置每 86400 秒检查更新；已有更新间隔会保留。复制文件中的链接到 Egern 的 URL 导入入口即可，无需网页登录。

修改本地 Egern 配置后上传更新，链接保持不变：

```powershell
py -3.13 private-download/manage.py update
```

完整链接包含下载密钥，持有链接的人都能下载。`.private/` 已被 Git 忽略，其中的状态、密钥和链接不得提交或分享。Worker 没有上传接口，缺少或错误的密钥返回 403，响应禁止缓存。

本地验证不需要登录或部署：

```powershell
node --test private-download/worker.test.mjs
py -3.13 private-download/test_manage.py
wrangler deploy --dry-run --config private-download/wrangler.json --outdir "$PWD/private-download/.private/build"
```
