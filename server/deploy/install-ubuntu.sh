#!/usr/bin/env bash
# Copyright (c) 2026 CJS flshw@126.com
# ChatRoom · LAN encrypted chat room. All rights reserved.
# Licensed for use with this ChatRoom distribution only.
#
# install-ubuntu.sh — ChatRoom v5 服务器 systemd 安装脚本（Ubuntu 20.04+）
#
# 用法（在解压后的包根目录内，即本脚本所在 deploy/ 的上级目录）：
#   sudo bash deploy/install-ubuntu.sh [安装目录]
#
# 默认安装目录 /opt/chatroom-server；数据目录 /var/lib/chatroom；
# 日志目录 /var/log/chatroom；以系统用户 chatroom 运行。
set -euo pipefail

SERVICE_NAME="chatroom"
RUN_USER="chatroom"
INSTALL_DIR="${1:-/opt/chatroom-server}"
DATA_DIR="/var/lib/chatroom"
LOG_DIR="/var/log/chatroom"

say() { printf '\033[1;32m[install]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "请以 root 运行：sudo bash deploy/install-ubuntu.sh [$INSTALL_DIR]"
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
[ -f "$SRC_DIR/src/main.js" ] || die "未找到 src/main.js，请在解压后的包根目录运行本脚本"

# 1. Node.js 检查（包内含 node_modules，离线机器只需 Node 运行时）
command -v node >/dev/null 2>&1 || die "未找到 node。请先安装 Node.js >= 22，见 DEPLOY-UBUNTU.md 第 2 节"
NODE_BIN="$(command -v node)"
NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
[ "$NODE_MAJOR" -ge 22 ] || die "Node 版本过低（当前 $(node -v)），需要 >= 22"
say "Node $(node -v) @ $NODE_BIN"

# 2. 升级场景：先停旧服务，保留数据
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
  say "停止正在运行的 $SERVICE_NAME 服务……"
  systemctl stop "$SERVICE_NAME"
fi

# 3. 系统用户
if ! id "$RUN_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$INSTALL_DIR" --shell /usr/sbin/nologin "$RUN_USER"
  say "创建系统用户 $RUN_USER"
fi

# 4. 复制代码（不含运行期 data/ 与 logs/，数据始终在 /var/lib、/var/log）
mkdir -p "$INSTALL_DIR"
cp -a "$SRC_DIR/." "$INSTALL_DIR/"
rm -rf "$INSTALL_DIR/data" "$INSTALL_DIR/logs"
chown -R "$RUN_USER:$RUN_USER" "$INSTALL_DIR"

# 5. 数据 / 日志目录（升级时保留既有内容）
install -d -m 0750 -o "$RUN_USER" -g "$RUN_USER" "$DATA_DIR" "$LOG_DIR"

# 6. 生成并安装 systemd 单元（按实际 Node 路径 / 安装目录替换占位符）
UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
sed -e "s#/opt/chatroom-server#$INSTALL_DIR#g" \
    -e "s#/usr/bin/node#$NODE_BIN#g" \
    "$SRC_DIR/deploy/chatroom.service" > "$UNIT_FILE"
say "已写入 $UNIT_FILE"

# 7. 开机自启并启动
systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null
systemctl start "$SERVICE_NAME"
sleep 2

# 8. 健康检查
if curl -fsS -m 5 http://127.0.0.1:8080/api/health; then
  echo
  say "安装完成：管理台 http://<本机IP>:8080/admin ，客户端 http://<本机IP>:8080/"
  say "首次启动的管理员初始口令与密钥在：journalctl -u $SERVICE_NAME | head -40"
  say "常用命令：systemctl status|restart|stop $SERVICE_NAME"
else
  say "服务未在 8080 就绪，查看日志：journalctl -u $SERVICE_NAME -n 50"
  exit 1
fi
