# Ubuntu 部署说明（ChatRoom v5 服务器）

> 适用版本：v5.0.0 · 编写日期：2026-11-14 · 目标系统：Ubuntu 20.04 / 22.04 / 24.04 / 26.04（x86_64 / arm64 通用）
> 本文档同时会被打进部署包，包内文件名为 `DEPLOY-UBUNTU.md`，内容一致。
> 相关文档：`docs/09` 组件清单与跨平台说明 · `docs/11` 性能与容量（在线数结论） · `docs/15` v5 变更说明

---

## 1. 部署包

在工作区执行一次打包（也可在 Windows 上完成）：

```bash
cd D:/chatroom            # 或 Linux 上解压后的源码目录
node tools/package-server.js          # 产出 dist/chatroom-server-v5.0.0.tar.gz
node tools/package-server.js --zip    # 追加产出同名 .zip（Windows 无 tar 时用）
```

包内结构（顶层目录 `chatroom-server/`，约 33 MB）：

```text
chatroom-server/
├── src/               15 个服务端模块（含 protocol.js 副本，自包含）
├── admin/             管理台页面 + 本地 forge.min.js（非安全上下文可用）
├── public/            单文件客户端 chatroom.html + 门户页 welcome.html
├── node_modules/      ws / node-forge / sql.js —— 全部纯 JS 或 WASM，无原生编译
├── deploy/
│   ├── chatroom.service       systemd 单元模板（LimitNOFILE=65535 已配置）
│   └── install-ubuntu.sh      一键安装脚本
├── DEPLOY-UBUNTU.md   本文档副本
├── package.json / package-lock.json
```

**刻意排除**：`data/`（密钥、身份库、聊天归档）与 `logs/`——运行期数据绝不混入代码包，升级时数据独立保留。

三个依赖均为纯 JS 或 WASM（sql.js），**无 node-gyp / 原生模块**，因此 `node_modules` 可直接跨发行版、跨架构拷贝使用，目标机器**不需要执行 `npm install`、不需要联网**，只需 Node.js 22 运行时。

包完整性：`sha256sum chatroom-server-v5.0.0.tar.gz`，与打包机输出的哈希比对即可。

## 2. 前置条件

### 2.1 系统与网络

| 项 | 要求 |
|---|---|
| Ubuntu | 20.04 及以上（验证环境为 26.04 目标；systemd / ufw / curl 均为标配） |
| Node.js | **>= 22**（`package.json` engines 约束；Node 18 及以下无 `--experimental-` 缺失问题但未测试） |
| 端口 | 默认 `8080/TCP`，可在 `data/config.json`、`CHATROOM_PORT` 环境变量或 `--port` 参数修改 |
| 客户端 | 局域网内任意现代浏览器，直接访问 `http://<服务器IP>:8080/` |

### 2.2 安装 Node.js 22（三选一）

```bash
# 方式 A：NodeSource 仓库（有外网时推荐）
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo bash -
sudo apt-get install -y nodejs

# 方式 B：发行版自带（较新 Ubuntu 的 node 版本足够时）
sudo apt-get install -y nodejs

# 方式 C：离线机 —— 官方 .tar.xz 二进制解压即用，无需编译
#   在有网机器下载 node-v22.x-linux-x64.tar.xz，拷到服务器：
sudo mkdir -p /opt/node && sudo tar -xJf node-v22.x-linux-x64.tar.xz -C /opt/node --strip-components=1
echo 'export PATH=/opt/node/bin:$PATH' | sudo tee /etc/profile.d/node.sh
source /etc/profile.d/node.sh && node -v
```

验证：`node -v`（≥ 22）、`node -e "console.log(process.arch)"`。

## 3. 把包传到服务器

```bash
# scp（Windows 上可用 OpenSSH 自带的 scp）
scp dist/chatroom-server-v5.0.0.tar.gz user@192.168.1.20:/tmp/

# 或 U 盘 / 局域网共享拷贝，最终放到 /tmp/ 即可
```

## 4. 一键安装（推荐）

```bash
cd /tmp
sha256sum chatroom-server-v5.0.0.tar.gz        # 可选：核对完整性
tar -xzf chatroom-server-v5.0.0.tar.gz
cd chatroom-server
sudo bash deploy/install-ubuntu.sh             # 默认装到 /opt/chatroom-server
# 自定义目录：sudo bash deploy/install-ubuntu.sh /srv/chatroom
```

脚本会依次完成（内容见 `deploy/install-ubuntu.sh`，可先审阅）：

1. 校验 root 与 Node >= 22，记录实际 node 路径；
2. 若旧服务在运行则先 `systemctl stop chatroom`（数据不受影响）；
3. 创建系统用户 `chatroom`（`nologin` shell，无登录能力）；
4. 复制代码到 `/opt/chatroom-server`（剔除包内可能存在的 `data/`、`logs/`）；
5. 创建 `/var/lib/chatroom`（数据）与 `/var/log/chatroom`（日志），属主 `chatroom`，目录权限 0750；
6. 按实际路径替换 `deploy/chatroom.service` 中的占位符，写入 `/etc/systemd/system/chatroom.service`；
7. `systemctl enable --now chatroom` 并做健康检查。

### systemd 单元要点

```ini
LimitNOFILE=65535                                  # 容量关键项，见第 8 节
Environment=CHATROOM_DATA_DIR=/var/lib/chatroom    # 密钥/数据库/文件外置
Environment=CHATROOM_LOG_DIR=/var/log/chatroom
ProtectSystem=strict
ReadWritePaths=/var/lib/chatroom /var/log/chatroom # 其余文件系统只读（加固）
Restart=on-failure
```

代码目录对服务进程是**只读**的，运行期只写 `/var/lib/chatroom` 与 `/var/log/chatroom` —— 升级 = 换代码目录 + 保留 `/var/lib`。

## 5. 手工安装（不用脚本）

```bash
sudo useradd --system --home-dir /opt/chatroom-server --shell /usr/sbin/nologin chatroom
sudo mkdir -p /opt/chatroom-server /var/lib/chatroom /var/log/chatroom
sudo tar -xzf /tmp/chatroom-server-v5.0.0.tar.gz -C /opt/chatroom-server --strip-components=1
sudo chown -R chatroom:chatroom /opt/chatroom-server /var/lib/chatroom /var/log/chatroom
sudo cp /opt/chatroom-server/deploy/chatroom.service /etc/systemd/system/   # 按需改路径
sudo systemctl daemon-reload && sudo systemctl enable --now chatroom
```

前台调试（不经 systemd，日志直接看终端）：

```bash
sudo -u chatroom node src/main.js --verbose
```

## 6. 首次启动与管理员凭证

首次启动会自动生成（全部落在 `/var/lib/chatroom`）：

| 文件 | 内容 |
|---|---|
| `keys.json` | 服务器 RSA-2048 公私钥（注册 / 密钥封装 / 身份链签名） |
| `admin-keys.json` | 管理员 RSA 私钥（登录用）与口令哈希 |
| `chat.db` | sql.js(SQLite) 数据库：身份、房间、归档、机器人池 |
| `config.json` | 运行配置（名称、端口、房间限额、版权等） |

**管理员初始口令只在首次启动的日志里打印一次**：

```bash
sudo journalctl -u chatroom | grep -iA2 '口令\|password' | head -20
# 或直接看当天日志文件
sudo cat /var/log/chatroom/server-$(date +%F).log | head -40
```

两种登录方式（`http://<服务器IP>:8080/chat/admin/`）：

1. **口令登录**：首次登录后请在管理台「修改口令」；`admin-keys.json` 只存 PBKDF2 哈希，无法反推口令；
2. **私钥挑战签名登录**：下载并妥善保管 `admin-keys.json` 中的私钥，登录时对挑战码做 RSA-PSS 签名，口令都不需要输入。**`admin-keys.json` 视同服务器最高权限，请离线备份。**

## 7. 防火墙与访问验证

```bash
sudo ufw allow 8080/tcp comment 'ChatRoom'
sudo ufw status
ip -4 addr show | grep inet          # 确认局域网 IP
```

验证清单（在服务器或局域网任一机器上）：

```bash
curl http://127.0.0.1:8080/api/health        # {"ok":true,"version":"5.0.0"}
curl -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/welcome   # 200
curl -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/          # 200（在线客户端）
curl -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/chat/admin/     # 200（管理台）
```

浏览器验证：局域网设备打开 `http://192.168.x.x:8080/` → 输入用户名即可临时身份聊天；勾选「成为正式用户」可下载身份包长期复用。

## 8. 容量与性能要点（Ubuntu 2 核 4 G 参考）

来自 `docs/11` 的实测结论（Windows 实测推演，未在真实 Linux 实机复测）：

- 每用户约 210 KB RSS / 88 KB Heap；注册握手 CPU 约 107 ms（纯 JS `node-forge`）；
- **必须** `LimitNOFILE=65535`（systemd 单元已配置）：默认 1024 fd 在约 1000 连接即 `EMFILE`；
- 归档以 4～5 KB/条写入内存中的 sql.js 全库：**上线前请规划归档滚动清理**（P0，当前版本未实现，`chat.db` 会持续增长）；
- 2 核 4 G 调优后建议 **800～1200 稳态在线**（峰值 1500）；再往上参见 `docs/12`（Node 原地优化 / Go / Rust 三条路线）。

## 9. 日常运维

```bash
systemctl status chatroom                      # 状态
systemctl restart chatroom                     # 硬重启（换端口/升级代码后必须）
journalctl -u chatroom -f                      # 跟踪日志
ls -lh /var/log/chatroom/                      # 按天滚动的日志文件
sudo du -sh /var/lib/chatroom /var/lib/chatroom/files
```

- **管理台「重启」按钮是进程内软重启**（端口不变、连接断开由客户端自动重连），日常改配置用它即可；换端口或升级代码仍需 `systemctl restart`。
- 聊天室名称、版权、房间限额等在管理台「服务器配置」修改，保存后**立即广播**给在线客户端，无需重启。

### 备份与恢复

```bash
# 备份（数据库 + 密钥 + 上传文件，停服一致性最好）
sudo systemctl stop chatroom
sudo tar -czf /backup/chatroom-data-$(date +%F).tgz /var/lib/chatroom
sudo systemctl start chatroom

# 恢复：把 tgz 解回 /var/lib/chatroom 并修正属主即可
sudo tar -xzf /backup/chatroom-data-YYYY-MM-DD.tgz -C /
sudo chown -R chatroom:chatroom /var/lib/chatroom
```

`/var/lib/chatroom` 包含全部持久状态；丢 `keys.json` = 全部客户端身份失效、历史密文不可解，务必纳入备份。

### 升级到新版本

```bash
sudo systemctl stop chatroom
sudo mv /opt/chatroom-server /opt/chatroom-server.old        # 保留旧代码以便回滚
sudo tar -xzf /tmp/chatroom-server-vX.Y.Z.tar.gz -C /opt     # 生成 /opt/chatroom-server
sudo cp -a /opt/chatroom-server.old/deploy/chatroom.service /etc/systemd/system/  # 若单元有更新
sudo chown -R chatroom:chatroom /opt/chatroom-server
sudo systemctl daemon-reload && sudo systemctl start chatroom
curl http://127.0.0.1:8080/api/health                        # 确认新版本号
sudo rm -rf /opt/chatroom-server.old                         # 观察稳定后清理
```

数据在 `/var/lib/chatroom`，升级过程零触碰；回滚 = 把 `.old` 目录换回来。

## 10. 可选：nginx 反向代理与 HTTPS

内网直接 `http://IP:8080` 即可工作（客户端与管理页都用内联 forge，**不依赖安全上下文**）。如需统一域名/HTTPS：

```nginx
server {
    listen 443 ssl;
    server_name chat.lan;
    ssl_certificate     /etc/ssl/chat.lan.crt;
    ssl_certificate_key /etc/ssl/chat.lan.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;     # WebSocket 必需
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 3600s;                    # 长连接
        client_max_body_size 10m;                    # 附件上传上限（应用层限 8 MB）
    }
}
```

启用 HTTPS 后 `crypto.subtle` 变为可用，但客户端仍走 forge 实现，行为一致；证书可自签（内网分发根证书）或用内网 CA。

## 11. 故障排查

| 现象 | 排查 |
|---|---|
| `systemctl status` 显示 exited / failed | `journalctl -u chatroom -n 50`；常见为 Node 版本 < 22 或端口被占用 |
| 端口被占用 `EADDRINUSE` | `ss -ltnp | grep 8080` 找占用者；或改端口：管理台改 `config.json` 无效（属启动参数），用 `Environment=CHATROOM_PORT=8090`（systemd 单元）或 `--port` |
| 连接数到 ~1000 后报 `EMFILE` | 确认单元里 `LimitNOFILE=65535` 生效：`cat /proc/$(pidof node)/limits | grep open` |
| 局域网设备连不上 | `ufw status`；云/虚拟机检查安全组；确认监听 `0.0.0.0:8080`（`ss -ltn`） |
| 管理台打不开初始口令 | 口令只在**首次**启动打印：`journalctl -u chatroom | head -80`；或用 `admin-keys.json` 私钥登录后重置口令 |
| 磁盘增长快 | `du -sh /var/lib/chatroom/*`：`chat.db`（归档）与 `files/`（密文附件）是两个增长点，按第 9 节备份/清理 |
| 升级后客户端连不上 | 版本协商失败极少见；先 `curl /api/health` 确认版本，再让客户端刷新页面重新注册 |
| 内存持续上涨 | 归档常驻内存是已知特性（`docs/11` P0）；在线数大时按容量章节规划或加滚动清理 |

## 12. 验收（可选，完整回归）

把工作区 `tools/` 各脚本与 `server/data` 一起带上时，可对生产实例跑回归（注意会临时改服务器名称/版权并自动还原）：

```bash
CHATROOM_BASE=http://127.0.0.1:8080 \
CHATROOM_DATA_DIR=/var/lib/chatroom \
CHATROOM_ADMIN_KEYS=/var/lib/chatroom/admin-keys.json \
node tools/smoke-test.js && node tools/smoke-v5.js
```

不带入工具脚本时，以上第 7 节的 5 项 HTTP 检查 + 浏览器收发一条消息即视为验收通过。

---

**版权**：CJS flshw@126.com · ChatRoom v5 局域网加密聊天室 · 仅限随本发行包使用。
