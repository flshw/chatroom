/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
'use strict';
/* Standalone server entry point v3 — supports in-place (soft) restart. */
const fs = require('fs');
const path = require('path');
const os = require('os');
const configMod = require('./config');
const C = require('./crypto');
const { Database } = require('./database');
const { IdentityLedger } = require('./ledger');
const { IdentityStore } = require('./identity');
const { AdminAuth } = require('./admin');
const { InviteCodec } = require('./invite');
const { FileStore } = require('./files');
const { Hub } = require('./hub');
const { BotManager } = require('./bots');
const { createHttpServer } = require('./http');
const { LOG_DIR } = require('./paths');

function logger(message) {
  const line = `[${new Date().toISOString()}] ${message}`;
  console.log(line);
  try {
    fs.mkdirSync(LOG_DIR, { recursive: true });
    fs.appendFileSync(path.join(LOG_DIR, `server-${new Date().toISOString().slice(0, 10)}.log`), line + '\n');
  } catch (e) { /* logging must never break the server */ }
}

function localIPv4List() {
  const out = [];
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name] || []) {
      if (net.family === 'IPv4' && !net.internal) out.push({ iface: name, address: net.address });
    }
  }
  return out;
}

let current = null;
let restarting = false;
let shuttingDown = false;
let bootCount = 0;

async function bootstrap(forcedPort) {
  const config = configMod.loadConfig();
  if (forcedPort) config.port = forcedPort;

  const keys = C.loadOrCreateKeys(logger);
  const db = await new Database().init();
  const ledger = new IdentityLedger({ db, keys, logger });
  const identity = new IdentityStore({ db, ledger, logger });
  const admin = new AdminAuth({ logger });
  const invite = new InviteCodec({ archiveKey: keys.archiveKey });
  const files = new FileStore({ db, logger });

  const ips = localIPv4List();
  const primaryIp = ips.length ? ips[0].address : '127.0.0.1';
  const hub = new Hub({
    keys, db, config, logger, identity, ledger, invite, files, admin,
    serverInfo: () => ({ host: primaryIp, port: config.port })
  });

  const bots = new BotManager({ hub, db, keys, ledger, logger });
  bots.start();

  const httpApp = createHttpServer({
    hub, config, logger, admin, identity, ledger, invite, files, bots,
    restart: () => { doRestart().catch(e => logger('重启异常: ' + e.stack)); }
  });
  const { server, wss, heartbeat } = httpApp;

  server.on('error', err => {
    logger('启动失败: ' + err.message);
    if (err.code === 'EADDRINUSE') logger(`端口 ${config.port} 已被占用，可用 --port 8081 指定其他端口`);
    process.exitCode = 1;
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(config.port, config.host, resolve);
  });

  bootCount++;
  if (bootCount === 1) {
    const lines = [
      '',
      '════════════════════════════════════════════════════════════',
      '  ChatRoom v5 · 局域网加密聊天室 · 服务端已启动',
      '────────────────────────────────────────────────────────────',
      `  监听地址   ${config.host}:${config.port}`,
      `  公钥指纹   ${keys.fingerprint}  (请与客户端核对)`,
      `  管理员指纹 ${admin.fingerprint}`,
      `  微型数据库 ${require('./database').DB_FILE}`,
      '────────────────────────────────────────────────────────────',
      '  客户端访问地址（局域网内任意浏览器）:'
    ];
    for (const ip of ips) lines.push(`    http://${ip.address}:${config.port}/        [${ip.iface}]`);
    lines.push(`    http://127.0.0.1:${config.port}/        [本机]`);
    lines.push(`  服务端管理界面:  http://127.0.0.1:${config.port}/admin`);
    lines.push(`  客户端下载/说明: http://127.0.0.1:${config.port}/welcome`);
    lines.push(`  WebSocket:       ws://${primaryIp}:${config.port}/ws`);
    lines.push(`  代理中继:        POST http://${primaryIp}:${config.port}/relay`);
    lines.push('────────────────────────────────────────────────────────────');
    lines.push('  新特性: 大厅直聊(不建房间) / 在线改名 / 名称与版权即时同步');
    lines.push('           正式用户身份链 / 多房间同开 / 身份库快切 / 拖拽上传');
    lines.push(`  版权信息: ${config.copyright || 'CJS flshw@126.com'}`);
    lines.push('  提示: 若其他机器无法访问，请放行本机防火墙的该端口');
    lines.push('        (Windows 防火墙 / Linux ufw 或 firewalld)');
    lines.push('  按 Ctrl+C 优雅退出（自动落盘加密归档数据）');
    lines.push('════════════════════════════════════════════════════════════', ''
    );
    console.log(lines.join('\n'));
  } else {
    logger(`服务端重载完成，监听 ${config.host}:${config.port}，第 ${bootCount} 次启动`);
  }
  logger(`服务端就绪，内网 IP: ${ips.map(i => i.address).join(', ') || '仅本机'}`);

  return { server, wss, heartbeat, db, hub, config, admin, ledger, bots };
}

/* In-place restart: rebuild config/keys/db/hub/listener without changing the
 * process. Connections drop and clients auto-reconnect; the port stays fixed so
 * the admin page remains reachable. A true process restart is available by
 * restarting `npm start` / the systemd service. */
async function doRestart() {
  if (restarting || shuttingDown) return;
  restarting = true;
  const port = current ? current.config.port : null;
  logger('正在重载服务端（关闭监听 → 落盘 → 重建状态）…');
  try {
    if (current) {
      clearInterval(current.heartbeat);
      if (current.bots) current.bots.dispose();
      for (const ws of current.wss.clients) { try { ws.close(); } catch (e) { /* noop */ } }
      try { current.wss.close(); } catch (e) { /* noop */ }
      await new Promise(resolve => {
        const timer = setTimeout(resolve, 1500);
        current.server.close(() => { clearTimeout(timer); resolve(); });
      });
      if (current.redirectServer) { try { current.redirectServer.close(); } catch (e) { /* noop */ } }
      current.db.close();
      logger('旧实例已关闭，加密数据已落盘');
    }
    current = await bootstrap(port);
    logger('重启完成');
  } finally {
    restarting = false;
  }
}

function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  logger('正在关闭服务端...');
  if (!current) { process.exit(0); return; }
  clearInterval(current.heartbeat);
  if (current.bots) current.bots.dispose();
  for (const ws of current.wss.clients) { try { ws.close(); } catch (e) { /* noop */ } }
  if (current.redirectServer) { try { current.redirectServer.close(); } catch (e) { /* noop */ } }
  current.server.close(() => {
    try { current.db.close(); logger('加密归档数据库已落盘'); }
    catch (e) { logger('落盘失败: ' + e.message); }
    process.exit(0);
  });
  setTimeout(() => {
    try { current.db.close(); } catch (e) { /* noop */ }
    process.exit(0);
  }, 3000).unref();
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
process.on('uncaughtException', err => logger('未捕获异常: ' + err.stack));

bootstrap().then(app => { current = app; }).catch(err => {
  console.error('启动异常:', err);
  process.exit(1);
});
