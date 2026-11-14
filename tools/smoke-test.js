/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
'use strict';
/*
 * End-to-end smoke test against a running server (default http://127.0.0.1:8080).
 * Verifies: hybrid-encrypted registration, challenge/response, per-room key
 * delivery, AES-256-GCM messaging, encrypted archive, and the HTTP relay path.
 *
 *   node tools/smoke-test.js
 */
const WebSocket = require('../server/node_modules/ws');
const forge = require('../server/node_modules/node-forge');
const fs = require('fs');
const path = require('path');
const P = require('../shared/protocol');
const C = require('../server/src/crypto');

const BASE = process.env.CHATROOM_BASE || 'http://127.0.0.1:8080';
const WS_URL = BASE.replace(/^http/, 'ws') + '/ws';
// v4: relay sessions are keyed by clientId and live in the server. Reusing a
// fixed id makes a second run against the same server fail with "bad state".
const RELAY_ID = 'smoke_relay_' + Date.now().toString(36) + '_' +
  Math.random().toString(36).slice(2, 8);

let passed = 0;
let failed = 0;
function check(name, condition, detail) {
  if (condition) { passed++; console.log('  PASS  ' + name); }
  else { failed++; console.log('  FAIL  ' + name + (detail ? ' -> ' + detail : '')); }
}

class TestClient {
  constructor(name) {
    this.name = name;
    this.inbox = [];
    this.waiters = [];
    this.ws = null;
  }
  connect() {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(WS_URL);
      this.ws = ws;
      ws.on('open', resolve);
      ws.on('error', reject);
      ws.on('message', raw => {
        let env;
        try { env = JSON.parse(raw.toString()); } catch (e) { return; }
        this.inbox.push(env);
        for (let i = this.waiters.length - 1; i >= 0; i--) {
          const w = this.waiters[i];
          if (w.pred(env)) {
            this.waiters.splice(i, 1);
            clearTimeout(w.timer);
            w.resolve(env);
          }
        }
      });
    });
  }
  send(type, data) { this.ws.send(JSON.stringify(P.makeEnvelope(type, data))); }
  wait(type, extra, timeout) {
    const pred = typeof extra === 'function'
      ? env => env.type === type && extra(env.data || {})
      : env => env.type === type;
    const ms = timeout || 10000;
    const existing = this.inbox.find(pred);
    if (existing) return Promise.resolve(existing);
    return new Promise((resolve, reject) => {
      const w = {
        pred, resolve,
        timer: setTimeout(() => {
          const i = this.waiters.indexOf(w);
          if (i >= 0) this.waiters.splice(i, 1);
          reject(new Error(`${this.name} 等待 ${type} 超时`));
        }, ms)
      };
      this.waiters.push(w);
    });
  }
  close() { try { this.ws.close(); } catch (e) { /* noop */ } }
}

async function register(client, welcome) {
  const pub = forge.pki.publicKeyFromPem(welcome.pubKey);
  const kp = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const inner = {
    v: P.PROTOCOL_VERSION,
    username: client.name,
    browserId: 'smoke_' + client.name + '_' + C.b64(C.randomBytes(8)),
    ts: Date.now(),
    nonce: C.b64(C.randomBytes(16)),
    challenge: welcome.challenge,
    clientPub: forge.pki.publicKeyToPem(kp.publicKey),
    sig: ''
  };
  inner.sig = C.signCanonical(kp.privateKey, C.canonicalRegister(inner));
  const blob = C.hybridEncrypt(pub, JSON.stringify(inner));
  client.privateKey = kp.privateKey;
  client.send(P.MSG.REGISTER, { blob });
  const done = await client.wait(P.MSG.REGISTERED);
  check(client.name + ' 非对称注册通过', !!done.data.uid, JSON.stringify(done.data).slice(0, 120));
  client.uid = done.data.uid;
  client.lobbyKey = C.unwrapKey(kp.privateKey, done.data.wrappedLobbyKey);
  check(client.name + ' 大厅密钥解封成功', client.lobbyKey.length === 32);
  return done.data;
}

async function httpJson(url, options) {
  const r = await fetch(url, options);
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return r.json();
}

/* v3: admin pages are token-protected. Tests sign a challenge with the local
 * administrator private key — this also exercises the asymmetric login path. */
async function adminToken() {
  // v4: allow testing an isolated deployment that generated its own admin keys.
  const file = process.env.CHATROOM_ADMIN_KEYS || path.join(
    process.env.CHATROOM_DATA_DIR || path.join(__dirname, '..', 'server', 'data'),
    'admin-keys.json');
  const stored = JSON.parse(fs.readFileSync(file, 'utf8'));
  const ch = await httpJson(BASE + '/api/admin/challenge');
  const priv = forge.pki.privateKeyFromPem(stored.privateKeyPem);
  const sig = C.signCanonical(priv, ['admin', ch.challenge, ch.ts].join('|'));
  const r = await fetch(BASE + '/api/admin/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mode: 'signature', challenge: ch.challenge, ts: ch.ts, sig })
  });
  const j = await r.json();
  if (!j.ok) throw new Error('管理员非对称登录失败: ' + j.error);
  return j.token;
}

async function main() {
  console.log('\n=== ChatRoom 端到端冒烟测试 ===');
  console.log('目标服务端: ' + BASE + '\n');

  const health = await httpJson(BASE + '/api/health');
  check('服务端健康检查', health.ok === true);

  /* ---- relay / proxy path ---- */
  const hello = P.makeEnvelope(P.MSG.HELLO, {});
  const relay = await httpJson(BASE + '/relay', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ clientId: RELAY_ID, envelope: hello })
  });
  check('HTTP 代理中继返回 WELCOME',
    relay.messages.some(m => m.type === P.MSG.WELCOME && !!m.data.pubKey));

  /* ---- full registration over the relay/proxy path ---- */
  const relayWelcome = relay.messages.find(m => m.type === P.MSG.WELCOME).data;
  const relayPub = forge.pki.publicKeyFromPem(relayWelcome.pubKey);
  const relayKp = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const relayInner = {
    v: P.PROTOCOL_VERSION, username: 'RelayUser', browserId: 'smoke_relay_browser',
    ts: Date.now(), nonce: C.b64(C.randomBytes(16)), challenge: relayWelcome.challenge,
    clientPub: forge.pki.publicKeyToPem(relayKp.publicKey), sig: ''
  };
  relayInner.sig = C.signCanonical(relayKp.privateKey, C.canonicalRegister(relayInner));
  const relayReg = await httpJson(BASE + '/relay', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      clientId: RELAY_ID,
      envelope: P.makeEnvelope(P.MSG.REGISTER, {
        blob: C.hybridEncrypt(relayPub, JSON.stringify(relayInner))
      })
    })
  });
  check('代理中继完成完整非对称身份认证',
    relayReg.messages.some(m => m.type === P.MSG.REGISTERED),
    JSON.stringify(relayReg.messages.map(m => m.type)));

  /* ---- two WebSocket clients ---- */
  const a = new TestClient('Alice');
  const b = new TestClient('Bob');
  await Promise.all([a.connect(), b.connect()]);
  check('两个 WebSocket 客户端已连接', a.ws.readyState === 1 && b.ws.readyState === 1);

  a.send(P.MSG.HELLO, {});
  b.send(P.MSG.HELLO, {});
  const [wa, wb] = await Promise.all([a.wait(P.MSG.WELCOME), b.wait(P.MSG.WELCOME)]);
  check('服务器公钥与挑战码下发',
    /BEGIN PUBLIC KEY/.test(wa.data.pubKey) && !!wa.data.challenge && !!wb.data.challenge);
  check('挑战码每次不同', wa.data.challenge !== wb.data.challenge);

  const [ra, rb] = await Promise.all([
    register(a, wa.data),
    register(b, wb.data)
  ]);
  check('每次登录生成全新身份码', ra.uid !== rb.uid);
  check('全新 UID 为 64 位十六进制', /^[0-9a-f]{64}$/.test(ra.uid));

  /* ---- room creation & key delivery ---- */
  a.send(P.MSG.ROOM_CREATE, { name: '冒烟测试房间', private: false });
  const joinedA = await a.wait(P.MSG.ROOM_JOINED, d => d.room && d.room.name === '冒烟测试房间');
  const roomId = joinedA.data.room.id;
  const keyA = C.unwrapKey(a.privateKey, joinedA.data.wrappedKey);
  check('创建者收到房间会话密钥', keyA.length === 32);

  b.send(P.MSG.ROOM_JOIN, { roomId });
  const joinedB = await b.wait(P.MSG.ROOM_JOINED, d => d.room && d.room.id === roomId);
  const keyB = C.unwrapKey(b.privateKey, joinedB.data.wrappedKey);
  check('加入者收到同一房间会话密钥', keyB.length === 32 && keyA === keyB);
  check('成员列表包含两人', joinedB.data.members.length === 2);

  /* ---- encrypted message ---- */
  const text = '你好，加密世界 123 · AES-256-GCM';
  const seq = 1;
  const ts = Date.now();
  const aad = C.messageAad ? C.messageAad(roomId, a.uid, seq, ts) : [roomId, a.uid, seq, ts].join('|');
  const enc = C.aesEncrypt(keyA, JSON.stringify({ text, kind: 'text' }), aad);
  a.send(P.MSG.MESSAGE, Object.assign({ room: roomId, seq, ts }, enc));

  const got = await b.wait(P.MSG.MESSAGE_BROADCAST, d => d.room === roomId && d.seq === seq);
  check('转发报文为密文（无明文字段）', !JSON.stringify(got.data).includes(text));
  const recvAad = [roomId, got.data.from, got.data.seq, got.data.ts].join('|');
  const plain = JSON.parse(C.aesDecrypt(keyB, got.data, recvAad));
  check('接收方解密得到原文', plain.text === text, plain.text);

  /* ---- replay rejection ---- */
  a.send(P.MSG.MESSAGE, Object.assign({ room: roomId, seq, ts }, enc));
  const replay = await a.wait(P.MSG.ERROR, d => d.code === P.ERR.REPLAY, 3000).catch(() => null);
  check('重复序号被拒绝（防重放）', !!replay);

  /* ---- encrypted archive (admin token required in v3) ---- */
  await new Promise(r => setTimeout(r, 700));
  const token = await adminToken();
  const auth = { headers: { 'X-Admin-Token': token } };
  check('管理员 RSA 私钥挑战签名登录成功', !!token && token.length >= 32);
  const archive = await httpJson(BASE + '/api/archive/messages?room=' + encodeURIComponent(roomId) + '&limit=20', auth);
  check('服务端归档可解密查看', archive.messages.some(m => m.text === text),
    JSON.stringify(archive.messages).slice(0, 200));
  const state = await httpJson(BASE + '/api/state', auth);
  check('在线用户数正确', state.users >= 2, 'users=' + state.users);
  check('归档消息计数增长', state.archive.messages >= 1);
  check('身份链已生成区块', state.ledger.blocks >= 1);

  /* ---- admin config endpoint ---- */
  const cfg = await httpJson(BASE + '/api/config');
  check('配置接口可读', typeof cfg.port === 'number');

  a.close(); b.close();
  console.log(`\n=== 结果: ${passed} 通过 / ${failed} 失败 ===\n`);
  process.exit(failed ? 1 : 0);
}

main().catch(err => {
  console.error('\n测试异常:', err.message);
  process.exit(1);
});
