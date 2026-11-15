/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
'use strict';
/* HTTP v3: static hosting, admin API (token-protected), relay, files, WS upgrade. */
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const nodeCrypto = require('crypto');
const { WebSocketServer } = require('ws');
const P = require('./protocol');
const { WsSession } = require('./session');
const configMod = require('./config');

const ROOT = path.resolve(__dirname, '..');
const PUBLIC_DIR = path.join(ROOT, 'public');
const ADMIN_DIR = path.join(ROOT, 'admin');
const FALLBACK_CLIENT = path.resolve(__dirname, '..', '..', 'client', 'dist', 'chatroom.html');
const ADMIN_FILE = path.join(ADMIN_DIR, 'index.html');

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Token',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
};

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, Object.assign({
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store'
  }, CORS));
  res.end(body);
}

function sendText(res, status, text, type, headers) {
  const body = Buffer.from(text);
  res.writeHead(status, Object.assign({
    'Content-Type': type || 'text/plain; charset=utf-8',
    'Content-Length': body.length,
    'Cache-Control': 'no-store'
  }, headers || {}, CORS));
  res.end(body);
}

function sendFile(res, file) {
  fs.readFile(file, (err, buf) => {
    if (err) return sendText(res, 404, '404 Not Found: ' + path.basename(file));
    const ext = path.extname(file).toLowerCase();
    const types = {
      '.html': 'text/html; charset=utf-8',
      '.js': 'application/javascript; charset=utf-8',
      '.css': 'text/css; charset=utf-8',
      '.json': 'application/json; charset=utf-8',
      '.svg': 'image/svg+xml',
      '.pem': 'application/x-pem-file',
      '.wasm': 'application/wasm'
    };
    res.writeHead(200, Object.assign({
      'Content-Type': types[ext] || 'application/octet-stream',
      'Content-Length': buf.length,
      'Cache-Control': 'no-store'
    }, CORS));
    res.end(buf);
  });
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > P.LIMITS.MAX_HTTP_BODY_BYTES) {
        reject(new Error('body too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      try { resolve(body ? JSON.parse(body) : {}); }
      catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

function clientFile() {
  const hosted = path.join(PUBLIC_DIR, 'chatroom.html');
  if (fs.existsSync(hosted)) return hosted;
  if (fs.existsSync(FALLBACK_CLIENT)) return FALLBACK_CLIENT;
  return null;
}

/* TLS is opt-in: point CHATROOM_TLS_CERT / CHATROOM_TLS_KEY at a PEM pair
 * to serve HTTPS on the same port. Browsers only expose getUserMedia() in a
 * secure context, so voice recording needs this on non-localhost hosts. */
function makeServer(handler) {
  const certPath = process.env.CHATROOM_TLS_CERT;
  const keyPath = process.env.CHATROOM_TLS_KEY;
  if (certPath && keyPath) {
    try {
      return https.createServer({
        cert: fs.readFileSync(certPath),
        key: fs.readFileSync(keyPath)
      }, handler);
    } catch (e) {
      console.error('[chatroom] TLS 证书加载失败，回退 HTTP: ' + e.message);
    }
  }
  return http.createServer(handler);
}

function createHttpServer(options) {
  const { hub, config, logger, admin, identity, ledger, invite, files, restart, bots } = options;

  const server = makeServer(async (req, res) => {
    let pathname = '/';
    try { pathname = new URL(req.url, 'http://localhost').pathname; }
    catch (e) { pathname = req.url.split('?')[0]; }
    const url = new URL(req.url || '/', 'http://localhost');
    const token = req.headers['x-admin-token'] || url.searchParams.get('token') || '';
    const isAdmin = () => admin.verify(token);
    const deny = () => sendJson(res, 401, {
      ok: false, code: P.ERR.ADMIN_REQUIRED, error: '需要管理员登录或令牌已过期'
    });

    if (req.method === 'OPTIONS') { res.writeHead(204, CORS); return res.end(); }

    /* ---- public static + info ---- */

    if (pathname === '/' || pathname === '/index.html' || pathname === '/chatroom.html') {
      const f = clientFile();
      if (f) return sendFile(res, f);
      return sendText(res, 200,
        '<!doctype html><meta charset="utf-8"><h2>客户端尚未构建</h2><p>请运行 <code>node tools/build-client.js</code>。</p>',
        'text/html; charset=utf-8');
    }
    if (pathname === '/admin' || pathname === '/admin/' || pathname === '/admin/index.html') {
      return sendFile(res, ADMIN_FILE);
    }
    if (pathname === '/setup' || pathname === '/setup/' || pathname === '/setup.html') {
      return sendFile(res, path.join(ADMIN_DIR, 'setup.html'));
    }
    if (pathname === '/welcome' || pathname === '/welcome/' || pathname === '/welcome.html') {
      return sendFile(res, path.join(PUBLIC_DIR, 'welcome.html'));
    }
    /* Explicit attachment download of the single-file client. */
    if (pathname === '/download/chatroom.html') {
      const f = clientFile();
      if (!f) return sendText(res, 404, '客户端尚未构建，请运行 node tools/build-client.js');
      return fs.readFile(f, (err, buf) => {
        if (err) return sendText(res, 404, '404 Not Found');
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Length': buf.length,
          'Content-Disposition': 'attachment; filename="chatroom.html"',
          'Cache-Control': 'no-store'
        });
        res.end(buf);
      });
    }
    if (pathname.startsWith('/assets/')) {
      const f = path.join(ADMIN_DIR, 'assets', path.basename(pathname));
      if (fs.existsSync(f)) return sendFile(res, f);
      return sendText(res, 404, '404 Not Found');
    }
    if (pathname === '/api/health') {
      return sendJson(res, 200, { ok: true, ts: Date.now(), version: P.RELEASE_VERSION });
    }
    /* Lightweight runtime metrics. Public on purpose so LAN operators and the
     * benchmark tool can profile the process without an admin token; it exposes
     * no secrets, keys or message contents. */
    if (pathname === '/api/metrics' && req.method === 'GET') {
      const m = process.memoryUsage();
      const cpu = process.cpuUsage();
      const mb = n => Math.round(n / 1048576 * 100) / 100;
      const s = hub.stats();
      return sendJson(res, 200, {
        ok: true, ts: Date.now(), pid: process.pid, node: process.version,
        platform: process.platform, arch: process.arch,
        uptimeSec: Math.round(process.uptime()),
        memory: {
          rssMB: mb(m.rss), heapTotalMB: mb(m.heapTotal), heapUsedMB: mb(m.heapUsed),
          externalMB: mb(m.external), arrayBuffersMB: mb(m.arrayBuffers || 0),
          heapLimitMB: mb(require('v8').getHeapStatistics().heap_size_limit),
          rssBytes: m.rss, heapUsedBytes: m.heapUsed
        },
        cpu: {
          userSec: Math.round(cpu.user / 1000) / 1000,
          systemSec: Math.round(cpu.system / 1000) / 1000
        },
        hub: {
          clients: s.clients, users: s.users, rooms: s.rooms.length,
          identities: s.identities, archive: s.archive
        },
        bots: bots ? bots.stats() : null
      });
    }
    if (pathname === '/api/client-info' && req.method === 'GET') {
      const f = clientFile();
      if (!f) return sendJson(res, 404, { ok: false, error: '客户端尚未构建' });
      const buf = fs.readFileSync(f);
      const nets = os.networkInterfaces();
      const addresses = [];
      for (const name of Object.keys(nets)) {
        for (const n of nets[name] || []) {
          if (n.family === 'IPv4' && !n.internal) addresses.push(`http://${n.address}:${config.port}/`);
        }
      }
      return sendJson(res, 200, {
        ok: true, name: 'chatroom.html', version: P.RELEASE_VERSION, bytes: buf.length,
        sha256: nodeCrypto.createHash('sha256').update(buf).digest('hex'),
        fingerprint: hub.stats().fingerprint,
        serverName: config.name,
        copyright: config.copyright || P.DEFAULT_COPYRIGHT,
        copyrightLink: config.copyrightLink || '',
        port: config.port, addresses,
        chatUrl: '/', downloadUrl: '/download/chatroom.html', adminUrl: '/admin',
        features: ['multiRoom', 'identityVault', 'quickSwitch', 'dragDrop',
          'identityFile', 'e2eePrivate', 'inviteCodes', 'files', 'bots',
          'lobbyDirect', 'onlineRename', 'serverConfigSync', 'copyright']
      });
    }
    if (pathname === '/api/server-info') {
      const s = hub.stats();
      return sendJson(res, 200, {
        name: s.name, version: s.version, fingerprint: s.fingerprint,
        adminFingerprint: s.adminFingerprint,
        publicKey: s.publicKey, uptimeSec: s.uptimeSec,
        clients: s.clients, users: s.users, rooms: s.rooms.length,
        archive: s.archive, historyEnabled: config.historyEnabled,
        copyright: config.copyright || P.DEFAULT_COPYRIGHT,
        copyrightLink: config.copyrightLink || '',
        features: ['identityFile', 'e2eePrivate', 'inviteCodes', 'files', 'adminLogin',
          'lobbyDirect', 'onlineRename', 'serverConfigSync']
      });
    }
    if (pathname === '/api/config' && req.method === 'GET') {
      return sendJson(res, 200, configMod.loadConfig());
    }
    /* v5: field-level annotations for the admin configuration form. */
    if (pathname === '/api/config/notes' && req.method === 'GET') {
      return sendJson(res, 200, {
        ok: true, notes: configMod.FIELD_NOTES,
        readOnly: ['host', 'maxMessageBytes'],
        note: '只读字段由启动参数或进程环境决定，修改需重启进程'
      });
    }

    /* ---- administrator authentication ---- */

    if (pathname === '/api/admin/challenge' && req.method === 'GET') {
      return sendJson(res, 200, admin.challenge());
    }
    if (pathname === '/api/admin/login' && req.method === 'POST') {
      try {
        const b = await readJson(req);
        const mode = b.mode === 'signature' ? 'signature' : 'password';
        const tok = mode === 'password'
          ? admin.loginPassword(b.password, b.challenge, b.ts)
          : admin.loginSignature(b.challenge, b.ts, b.sig);
        return sendJson(res, 200, { ok: true, token: tok, mode, fingerprint: admin.fingerprint });
      } catch (e) {
        return sendJson(res, 401, { ok: false, code: P.ERR.ADMIN_AUTH_FAILED, error: e.message });
      }
    }
    if (pathname === '/api/admin/logout' && req.method === 'POST') {
      admin.logout(token);
      return sendJson(res, 200, { ok: true });
    }

    /* ---- first-run system deployment (no auth, only before deploy) ---- */

    if (pathname === '/api/setup/status' && req.method === 'GET') {
      return sendJson(res, 200, {
        ok: true,
        firstRun: admin.isFirstRun(),
        deployed: !admin.isFirstRun(),
        fingerprint: admin.fingerprint,
        pubKey: admin.data.publicKeyPem
      });
    }
    if (pathname === '/api/setup/password' && req.method === 'POST') {
      if (!admin.isFirstRun()) return sendJson(res, 403, { ok: false, error: '系统已完成部署，请到管理台用「修改口令」更换' });
      try {
        const b = await readJson(req);
        const tok = admin.setupPassword(b.password);
        return sendJson(res, 200, { ok: true, token: tok, fingerprint: admin.fingerprint });
      } catch (e) { return sendJson(res, 400, { ok: false, error: e.message }); }
    }
    if (pathname === '/api/setup/private-key' && req.method === 'GET') {
      if (!admin.isFirstRun()) return deny();
      return sendText(res, 200, admin.privateKeyPem(), 'application/x-pem-file; charset=utf-8', {
        'Content-Disposition': 'attachment; filename="chatroom-admin-key.pem"'
      });
    }
    if (pathname === '/api/setup/reset-db' && req.method === 'POST') {
      if (!admin.isFirstRun()) return deny();
      try {
        const counts = hub.db.resetChatData();
        logger('系统部署：聊天数据库已重置');
        return sendJson(res, 200, { ok: true, counts });
      } catch (e) { return sendJson(res, 500, { ok: false, error: e.message }); }
    }
    if (pathname === '/api/setup/reset-ledger' && req.method === 'POST') {
      if (!admin.isFirstRun()) return deny();
      try {
        const verify = ledger.reset();
        logger('系统部署：身份链已重置');
        return sendJson(res, 200, { ok: true, verify });
      } catch (e) { return sendJson(res, 500, { ok: false, error: e.message }); }
    }
    if (pathname === '/api/setup/finish' && req.method === 'POST') {
      if (!admin.isFirstRun()) return sendJson(res, 403, { ok: false, error: '系统已完成部署' });
      admin.markDeployed();
      return sendJson(res, 200, { ok: true });
    }
    if (pathname === '/api/admin/password' && req.method === 'POST') {
      if (!isAdmin()) return deny();
      try {
        const b = await readJson(req);
        admin.setPassword(b.oldPassword, b.newPassword);
        return sendJson(res, 200, { ok: true });
      } catch (e) { return sendJson(res, 400, { ok: false, error: e.message }); }
    }
    if (pathname === '/api/admin/private-key' && req.method === 'GET') {
      if (!isAdmin()) return deny();
      return sendText(res, 200, admin.privateKeyPem(), 'application/x-pem-file; charset=utf-8', {
        'Content-Disposition': 'attachment; filename="chatroom-admin-key.pem"'
      });
    }
    if (pathname === '/api/admin/restart' && req.method === 'POST') {
      if (!isAdmin()) return deny();
      logger('管理员请求重启服务端');
      ledger.append('server_restart', { by: 'admin', ts: Date.now() });
      sendJson(res, 200, { ok: true, note: '服务端正在重载配置与状态，约 1 秒后恢复，客户端会自动重连' });
      setTimeout(() => { try { restart(); } catch (e) { logger('重启失败: ' + e.message); } }, 120);
      return;
    }
    if (pathname === '/api/admin/reset-db' && req.method === 'POST') {
      if (!isAdmin()) return deny();
      try {
        const counts = hub.db.resetChatData();
        ledger.append('db_reset', { by: 'admin', ts: Date.now() });
        logger('管理员重置了聊天数据库');
        return sendJson(res, 200, { ok: true, counts });
      } catch (e) { return sendJson(res, 500, { ok: false, error: e.message }); }
    }
    if (pathname === '/api/admin/reset-ledger' && req.method === 'POST') {
      if (!isAdmin()) return deny();
      try {
        const verify = ledger.reset();
        logger('管理员重置了身份链');
        return sendJson(res, 200, { ok: true, verify });
      } catch (e) { return sendJson(res, 500, { ok: false, error: e.message }); }
    }

    /* ---- admin-protected state, identity ledger, rooms, users, invites ---- */

    if (pathname === '/api/state' && req.method === 'GET') {
      if (!isAdmin()) return deny();
      return sendJson(res, 200, hub.stats());
    }
    if (pathname === '/api/config' && req.method === 'POST') {
      if (!isAdmin()) return deny();
      try {
        const patch = await readJson(req);
        const saved = configMod.saveConfig(patch);
        const keysToApply = [
          'maxRooms', 'maxMembersPerRoom', 'historyEnabled', 'name',
          'copyright', 'copyrightLink'
        ];
        for (const k of keysToApply) {
          if (Object.prototype.hasOwnProperty.call(saved, k)) hub.config[k] = saved[k];
        }
        /* v5: push the new chatroom name / copyright to connected clients. */
        const broadcast = hub.broadcastServerConfig();
        logger('配置已更新并广播: ' + JSON.stringify(saved));
        return sendJson(res, 200, {
          ok: true, config: saved, server: broadcast,
          note: '名称与版权已即时同步到在线客户端；端口修改需进程级重启生效'
        });
      } catch (e) { return sendJson(res, 400, { ok: false, error: e.message }); }
    }
    if (pathname === '/api/archive/rooms' && req.method === 'GET') {
      if (!isAdmin()) return deny();
      return sendJson(res, 200, { rooms: hub.db.getArchivedRooms() });
    }
    if (pathname === '/api/archive/messages' && req.method === 'GET') {
      if (!isAdmin()) return deny();
      const room = url.searchParams.get('room') || P.LOBBY_ID;
      const limit = parseInt(url.searchParams.get('limit') || '50', 10);
      return sendJson(res, 200, { room, messages: hub.adminHistory(room, limit) });
    }
    if (pathname === '/api/admin/identities' && req.method === 'GET') {
      if (!isAdmin()) return deny();
      return sendJson(res, 200, {
        identities: identity.list(),
        onlineUids: Array.from(hub.users.keys()),
        chainPolicy: 'v5: 仅持久化的正式用户写入身份链；临时用户与机器人不写链'
      });
    }
    if (pathname === '/api/admin/identity' && req.method === 'POST') {
      if (!isAdmin()) return deny();
      try {
        const b = await readJson(req);
        const rec = hub.applyUserAction(String(b.uid || ''), String(b.action || ''), b.value);
        return sendJson(res, 200, { ok: true, identity: rec });
      } catch (e) { return sendJson(res, 400, { ok: false, error: e.message }); }
    }
    if (pathname === '/api/admin/ledger' && req.method === 'GET') {
      if (!isAdmin()) return deny();
      return sendJson(res, 200, { blocks: ledger.list(), verify: ledger.verify() });
    }
    if (pathname === '/api/admin/ledger/verify' && req.method === 'GET') {
      if (!isAdmin()) return deny();
      return sendJson(res, 200, ledger.verify());
    }
    if (pathname === '/api/admin/rooms' && req.method === 'GET') {
      if (!isAdmin()) return deny();
      return sendJson(res, 200, { rooms: hub.stats().rooms, archived: hub.db.getArchivedRooms() });
    }
    if (pathname === '/api/admin/room/delete' && req.method === 'POST') {
      if (!isAdmin()) return deny();
      try {
        const b = await readJson(req);
        return sendJson(res, 200, hub.deleteRoom(String(b.roomId || '')));
      } catch (e) { return sendJson(res, 400, { ok: false, error: e.message }); }
    }
    /* v5: rename a room / the lobby; change is broadcast to all clients. */
    if (pathname === '/api/admin/room/rename' && req.method === 'POST') {
      if (!isAdmin()) return deny();
      try {
        const b = await readJson(req);
        const room = hub.renameRoom(String(b.roomId || ''), String(b.name || ''));
        return sendJson(res, 200, {
          ok: true, room, note: '房间名称已广播给所有在线客户端'
        });
      } catch (e) { return sendJson(res, 400, { ok: false, error: e.message }); }
    }
    if (pathname === '/api/admin/room/messages' && req.method === 'GET') {
      if (!isAdmin()) return deny();
      const room = url.searchParams.get('room') || P.LOBBY_ID;
      const limit = parseInt(url.searchParams.get('limit') || '50', 10);
      return sendJson(res, 200, hub.adminRoomMessages(room, limit));
    }
    /* ---- bot pool management ---- */
    if (pathname === '/api/admin/bots' && req.method === 'GET') {
      if (!isAdmin()) return deny();
      return sendJson(res, 200, bots ? bots.stats() : { ok: false, error: '机器人模块未启用' });
    }
    if (pathname === '/api/admin/bots' && req.method === 'POST') {
      if (!isAdmin()) return deny();
      if (!bots) return sendJson(res, 400, { ok: false, error: '机器人模块未启用' });
      try {
        const b = await readJson(req);
        return sendJson(res, 200, { ok: true, bots: bots.configure(b) });
      } catch (e) { return sendJson(res, 400, { ok: false, error: e.message }); }
    }
    if (pathname === '/api/admin/bots/refresh' && req.method === 'POST') {
      if (!isAdmin()) return deny();
      if (!bots) return sendJson(res, 400, { ok: false, error: '机器人模块未启用' });
      return sendJson(res, 200, { ok: true, bots: bots.refresh() });
    }
    if (pathname === '/api/admin/bots/say' && req.method === 'POST') {
      if (!isAdmin()) return deny();
      if (!bots) return sendJson(res, 400, { ok: false, error: '机器人模块未启用' });
      try {
        const b = await readJson(req);
        const live = bots.stats().bots;
        const fallback = live[0] || null;
        /* Pick any online bot when the caller omits uid (or its bot just rotated out). */
        const uid = String(b.uid || '') || (fallback ? fallback.uid : '');
        const room = String(b.room || (fallback ? (fallback.rooms[0] || P.LOBBY_ID) : P.LOBBY_ID));
        const ok = bots.speak(room, uid, String(b.text || '这是一条机器人测试消息'));
        return sendJson(res, ok ? 200 : 400, { ok, room, uid, note: ok ? '已发送' : '机器人不在该房间或房间为 E2EE' });
      } catch (e) { return sendJson(res, 400, { ok: false, error: e.message }); }
    }
    if (pathname === '/api/admin/invite' && req.method === 'GET') {
      if (!isAdmin()) return deny();
      try {
        const code = hub.makeRoomInvite(
          url.searchParams.get('room') || P.LOBBY_ID,
          'admin', '管理员',
          url.searchParams.get('host') || null,
          parseInt(url.searchParams.get('port') || '0', 10) || null
        );
        return sendJson(res, 200, { ok: true, code, invite: invite.parse(code) });
      } catch (e) { return sendJson(res, 400, { ok: false, error: e.message }); }
    }

    /* ---- invite parsing (public, needed before login) ---- */

    if (pathname === '/api/invite/create' && req.method === 'POST') {
      try {
        const b = await readJson(req);
        const uid = String(b.uid || '');
        const roomId = String(b.room || '');
        if (!hub.isMember(uid, roomId)) {
          return sendJson(res, 403, { ok: false, error: '不是该房间成员，无法生成邀请码' });
        }
        const u = hub.users.get(uid);
        const code = hub.makeRoomInvite(roomId, uid, u ? u.username : uid,
          b.host || null, parseInt(b.port || '0', 10) || null);
        return sendJson(res, 200, { ok: true, code, invite: invite.parse(code) });
      } catch (e) { return sendJson(res, 400, { ok: false, error: e.message }); }
    }
    if (pathname === '/api/invite/parse' && req.method === 'POST') {
      try {
        const b = await readJson(req);
        const payload = invite.parse(String(b.code || ''));
        if (!payload) return sendJson(res, 400, { ok: false, error: '邀请码无法解析或已过期' });
        return sendJson(res, 200, {
          ok: true, invite: payload, valid: invite.verify(payload),
          note: invite.verify(payload) ? '服务器签名有效' : '签名无效，服务端会拒绝该邀请码'
        });
      } catch (e) { return sendJson(res, 400, { ok: false, error: e.message }); }
    }

    /* ---- encrypted file transfer (ciphertext only) ---- */

    if (pathname === '/api/file/upload' && req.method === 'POST') {
      try {
        const b = await readJson(req);
        const uid = String(b.uid || '');
        const roomId = String(b.room || '');
        /* v5.3: voice clips are a room-only feature. Enforce server-side too,
         * so a crafted client cannot publish voice into the lobby. Check the
         * policy before membership so it never leaks room state. */
        const uploadExt = String(b.ext || '').toLowerCase().replace(/^\./, '');
        if (roomId === P.LOBBY_ID && P.VOICE_EXTS.indexOf(uploadExt) !== -1) {
          return sendJson(res, 403, {
            ok: false, code: P.ERR.FORBIDDEN,
            error: '大厅不支持语音消息，请进入房间后发送'
          });
        }
        if (!hub.isMember(uid, roomId)) {
          return sendJson(res, 403, { ok: false, error: '不是该房间成员' });
        }
        if (!identity.canSpeak(uid)) {
          return sendJson(res, 403, { ok: false, code: P.ERR.MUTED, error: '您已被禁止发言/上传' });
        }
        const u = hub.users.get(uid);
        const room = hub.rooms.get(roomId);
        const rec = files.put(b, {
          room: roomId, uploader: uid, uploaderName: u ? u.username : uid,
          e2ee: room ? room.e2ee : false
        });
        hub.chainUserEvent(hub.users.get(uid), 'file_upload', {
          fileId: rec.id, room: roomId, uid, name: rec.name, ext: rec.ext, size: rec.size
        });
        return sendJson(res, 200, { ok: true, file: rec });
      } catch (e) {
        return sendJson(res, 400, { ok: false, code: e.code || P.ERR.BAD_ENVELOPE, error: e.message });
      }
    }
    if (pathname === '/api/file/get' && req.method === 'GET') {
      const id = url.searchParams.get('id') || '';
      const uid = url.searchParams.get('uid') || '';
      const rec = files.get(id);
      if (!rec) return sendJson(res, 404, { ok: false, code: P.ERR.FILE_NOT_FOUND, error: '文件不存在' });
      if (uid && !hub.isMember(uid, rec.room)) {
        return sendJson(res, 403, { ok: false, error: '无权访问该文件' });
      }
      return sendJson(res, 200, {
        ok: true,
        file: {
          id: rec.id, room: rec.room, name: rec.name, ext: rec.ext,
          size: rec.size, uploader: rec.uploader_name, ts: rec.ts, e2ee: !!rec.e2ee
        },
        blob: { iv: rec.iv, ct: rec.ct, tag: rec.tag, aad: rec.aad }
      });
    }

    /* ---- HTTP relay ---- */

    if (pathname === '/relay' && req.method === 'POST') {
      try {
        const body = await readJson(req);
        const clientId = String(body.clientId || '').slice(0, 64);
        if (!clientId) return sendJson(res, 400, { error: 'clientId required' });
        const messages = hub.handleRelay(clientId, body.envelope || null);
        return sendJson(res, 200, { messages, ts: Date.now() });
      } catch (e) { return sendJson(res, 400, { error: e.message }); }
    }

    return sendText(res, 404, '404 Not Found');
  });

  const wss = new WebSocketServer({ server, path: '/ws', maxPayload: P.LIMITS.MAX_FRAME_BYTES });
  wss.on('connection', ws => {
    const session = hub.attach(new WsSession(ws));
    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; session.touch(); });
    ws.on('message', raw => {
      try { hub.handleEnvelope(session, JSON.parse(raw.toString())); }
      catch (e) { session.error(P.ERR.BAD_ENVELOPE, 'JSON 解析失败'); }
    });
    ws.on('close', () => hub.detach(session));
    ws.on('error', () => { /* handled by close */ });
  });

  const heartbeat = setInterval(() => {
    for (const ws of wss.clients) {
      if (ws.isAlive === false) { try { ws.terminate(); } catch (e) { /* noop */ } continue; }
      ws.isAlive = false;
      try { ws.ping(); } catch (e) { /* noop */ }
    }
    hub.sweep();
  }, P.LIMITS.HEARTBEAT_MS);

  return { server, wss, heartbeat };
}

module.exports = { createHttpServer };
