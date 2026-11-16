/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
'use strict';
/*
 * v4 end-to-end tests: portal/download page, metrics, bot pool + auto-reply,
 * simultaneous multi-room membership, room limit, client static capabilities,
 * and persistence across a soft restart.
 *
 *   node tools/smoke-v4.js
 *   CHATROOM_BASE=http://127.0.0.1:8099 node tools/smoke-v4.js
 */
const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');
const WebSocket = require('../server/node_modules/ws');
const forge = require('../server/node_modules/node-forge');
const P = require('../shared/protocol');
const C = require('../server/src/crypto');

const BASE = process.env.CHATROOM_BASE || 'http://127.0.0.1:8080';
const WS_URL = BASE.replace(/^http/, 'ws') + '/ws';
const sleep = ms => new Promise(r => setTimeout(r, ms));

let passed = 0, failed = 0;
function check(name, ok, detail) {
  if (ok) { passed++; console.log('  PASS  ' + name); }
  else { failed++; console.log('  FAIL  ' + name + (detail ? ' -> ' + detail : '')); }
}

async function httpRaw(url, opts) {
  const r = await fetch(BASE + url, opts || {});
  const text = await r.text();
  return { status: r.status, headers: r.headers, text };
}
async function httpJson(url, opts) {
  const r = await httpRaw(url, opts);
  let j = null;
  try { j = JSON.parse(r.text); } catch (e) { /* not json */ }
  return { status: r.status, body: j, headers: r.headers };
}
function post(pathname, body, token) {
  return httpJson(pathname, {
    method: 'POST',
    headers: Object.assign({ 'Content-Type': 'application/json' },
      token ? { 'X-Admin-Token': token } : {}),
    body: JSON.stringify(body || {})
  });
}

async function adminToken() {
  // v4: allow testing an isolated deployment that generated its own admin keys.
  const file = process.env.CHATROOM_ADMIN_KEYS || path.join(
    process.env.CHATROOM_DATA_DIR || path.join(__dirname, '..', 'server', 'data'),
    'admin-keys.json');
  const stored = JSON.parse(fs.readFileSync(file, 'utf8'));
  const ch = (await httpJson('/api/admin/challenge')).body;
  const priv = forge.pki.privateKeyFromPem(stored.privateKeyPem);
  const sig = C.signCanonical(priv, ['admin', ch.challenge, ch.ts].join('|'));
  const r = await post('/api/admin/login',
    { mode: 'signature', challenge: ch.challenge, ts: ch.ts, sig });
  if (!r.body || !r.body.ok) throw new Error('管理员非对称登录失败: ' + JSON.stringify(r.body));
  return r.body.token;
}

class Client {
  constructor(name) {
    this.name = name;
    this.inbox = [];
    this.ws = null;
    this.keys = {};
    this.seqMap = {};
    this.uid = '';
  }
  connect() {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(WS_URL);
      this.ws = ws;
      ws.on('open', resolve);
      ws.on('error', reject);
      ws.on('message', raw => {
        try { this.inbox.push(JSON.parse(raw.toString())); } catch (e) { /* noop */ }
      });
    });
  }
  send(type, data) {
    if (this.ws && this.ws.readyState === 1) this.ws.send(JSON.stringify(P.makeEnvelope(type, data)));
  }
  clear() { this.inbox.length = 0; }
  async wait(type, pred, ms) {
    const end = Date.now() + (ms || 6000);
    while (Date.now() < end) {
      const hit = this.inbox.find(e => e.type === type && (!pred || pred(e.data || {})));
      if (hit) return hit;
      await sleep(25);
    }
    throw new Error(`${this.name} 等待 ${type} 超时`);
  }
  close() { try { this.ws.close(); } catch (e) { /* noop */ } }
}

async function register(cl) {
  const kp = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  cl.privateKey = kp.privateKey;
  cl.publicKeyPem = forge.pki.publicKeyToPem(kp.publicKey);
  cl.clear();
  cl.send(P.MSG.HELLO, {});
  const w = await cl.wait(P.MSG.WELCOME);
  const inner = {
    v: P.PROTOCOL_VERSION, username: cl.name,
    browserId: 'v4_' + cl.name + '_' + nodeCrypto.randomBytes(6).toString('hex'),
    ts: Date.now(), nonce: C.b64(C.randomBytes(16)),
    challenge: w.data.challenge, clientPub: cl.publicKeyPem, sig: ''
  };
  inner.sig = C.signCanonical(kp.privateKey, C.canonicalRegister(inner));
  cl.send(P.MSG.REGISTER, {
    blob: C.hybridEncrypt(forge.pki.publicKeyFromPem(w.data.pubKey), JSON.stringify(inner))
  });
  const reg = await cl.wait(P.MSG.REGISTERED);
  cl.uid = reg.data.uid;
  cl.keys[reg.data.room.id] = C.unwrapKey(kp.privateKey, reg.data.wrappedLobbyKey);
  return reg.data;
}

async function createRoom(cl, name) {
  cl.clear();
  cl.send(P.MSG.ROOM_CREATE, { name, private: false });
  const j = await cl.wait(P.MSG.ROOM_JOINED, d => d.room && d.room.name === name, 8000);
  cl.keys[j.data.room.id] = C.unwrapKey(cl.privateKey, j.data.wrappedKey);
  return j.data.room.id;
}

function sendText(cl, roomId, text) {
  const seq = (cl.seqMap[roomId] || 0) + 1;
  const ts = Date.now();
  const aad = [roomId, cl.uid, seq, ts].join('|');
  const enc = C.aesEncrypt(cl.keys[roomId], JSON.stringify({ text, kind: 'text' }), aad);
  cl.send(P.MSG.MESSAGE, { room: roomId, seq, ts, iv: enc.iv, ct: enc.ct, tag: enc.tag });
  cl.seqMap[roomId] = seq;
  return { seq, ts };
}
function decryptBroadcast(cl, d) {
  const aad = [d.room, d.from, d.seq, d.ts].join('|');
  return JSON.parse(C.aesDecrypt(cl.keys[d.room], d, aad));
}

async function main() {
  console.log('\n=== ChatRoom v4 新功能端到端测试 ===');
  console.log('目标服务端: ' + BASE + '\n');

  /* ---------- A. portal, download, metrics ---------- */
  const health = await httpJson('/api/health');
  check('健康检查返回 v5 版本', health.body.ok === true && /^5\./.test(health.body.version || '') && health.body.version === P.RELEASE_VERSION,
    JSON.stringify(health.body));
  const metrics = await httpJson('/api/metrics');
  check('/api/metrics 暴露内存/CPU/Hub/机器人指标',
    metrics.status === 200 && metrics.body.memory && metrics.body.cpu &&
    metrics.body.hub && metrics.body.bots && metrics.body.memory.heapLimitMB > 0);
  const welcome = await httpRaw('/welcome');
  check('客户端下载/说明页可访问且含关键说明',
    welcome.status === 200 && /身份文件/.test(welcome.text) && /SHA-256/.test(welcome.text));
  const download = await httpRaw('/download/chatroom.html');
  check('单文件客户端下载带 attachment 头',
    download.status === 200 && /attachment/.test(download.headers.get('content-disposition') || '') &&
    download.text.indexOf('ChatRoom') !== -1);
  const info = await httpJson('/api/client-info');
  const localFile = fs.readFileSync(path.join(__dirname, '..', 'client', 'dist', 'chatroom.html'));
  const localSha = nodeCrypto.createHash('sha256').update(localFile).digest('hex');
  check('client-info 的 SHA-256 与实际文件一致',
    info.body.ok === true && info.body.sha256 === localSha &&
    info.body.bytes === localFile.length);
  check('client-info 声明 v4 能力集',
    ['multiRoom', 'identityVault', 'quickSwitch', 'dragDrop', 'bots']
      .every(f => info.body.features.indexOf(f) !== -1));
  const adminPage = await httpRaw('/chat/admin/');
  check('管理台含机器人与客户端入口',
    adminPage.status === 200 && /data-view="bots"/.test(adminPage.text) &&
    /btn-welcome/.test(adminPage.text));

  /* ---------- B. protocol constants ---------- */
  check('协议声明最多同时打开 3 个房间', P.LIMITS.MAX_ACTIVE_ROOMS === 3);
  check('协议含房间上限错误码与身份库键',
    P.ERR.ROOM_LIMIT === 'E_ROOM_LIMIT' && !!P.IDENTITY_VAULT_KEY);

  const token = await adminToken();
  const H = { 'X-Admin-Token': token };

  /* ---------- C. bot pool ---------- */
  const bots0 = (await httpJson('/api/admin/bots', { headers: H })).body;
  check('机器人池至少 1000 个持久身份', bots0.records >= 1000, 'records=' + bots0.records);
  check('在线机器人维持 10~20 个',
    bots0.online >= 10 && bots0.online <= 20, 'online=' + bots0.online);
  check('机器人配置默认开启自动回复', bots0.enabled === true && bots0.autoReply === true);
  const state0 = (await httpJson('/api/state', { headers: H })).body;
  check('在线统计区分真人与机器人',
    typeof state0.bots === 'number' && state0.bots === bots0.online);
  check('成员列表带 bot 标记',
    state0.rooms.length >= 1);
  const identities = (await httpJson('/api/admin/identities', { headers: H })).body.identities;
  check('机器人身份在数据库标记 isBot',
    identities.filter(x => x.isBot).length >= 1000);

  /* freeze rotation during reply tests */
  const cfg = (await post('/api/admin/bots', {
    refreshMs: 600000, replyProbability: 1, autoReply: true,
    minOnline: 10, maxOnline: 20
  }, token)).body.bots;
  check('机器人配置接口可调整参数并立即生效',
    cfg.refreshMs === 600000 && cfg.replyProbability === 1);

  const a = new Client('v4_alice');
  await a.connect();
  const regA = await register(a);
  check('真人客户端注册成功（房间含机器人成员）',
    !!a.uid && regA.members.length > 1, 'members=' + regA.members.length);
  check('机器人成员带 bot 标记',
    regA.members.some(m => m.bot === true && String(m.uid).indexOf('bot_') === 0));

  /* manual bot speech */
  a.clear();
  const say = (await post('/api/admin/bots/say',
    { room: P.LOBBY_ID, text: '管理端手动触发发言' }, token)).body;
  check('管理端可让机器人发言', say.ok === true);
  let botBroadcast = null;
  try { botBroadcast = await a.wait(P.MSG.MESSAGE_BROADCAST, d => String(d.from).indexOf('bot_') === 0, 5000); }
  catch (e) { /* noop */ }
  check('机器人消息以标准加密广播送达客户端', !!botBroadcast);
  if (botBroadcast) {
    check('客户端可解密机器人发言内容',
      decryptBroadcast(a, botBroadcast.data).text === '管理端手动触发发言');
  }

  /* auto reply to a real human message */
  a.clear();
  sendText(a, P.LOBBY_ID, '你好，有人在吗？');
  let autoReply = null;
  try {
    autoReply = await a.wait(P.MSG.MESSAGE_BROADCAST,
      d => String(d.from).indexOf('bot_') === 0 && d.ts > Date.now() - 15000, 7000);
  } catch (e) { /* noop */ }
  check('真人发言后机器人自动回复', !!autoReply);
  if (autoReply) {
    const txt = decryptBroadcast(a, autoReply.data).text;
    check('自动回复为可解密的中文内容', typeof txt === 'string' && txt.length > 0, txt);
  }

  /* bots never join E2EE rooms */
  const e2eeRooms = state0.rooms.filter(r => r.e2ee).map(r => r.id);
  const botsNow = (await httpJson('/api/admin/bots', { headers: H })).body;
  check('机器人不加入端到端加密房间',
    e2eeRooms.length === 0 || botsNow.bots.every(b => b.rooms.every(r => e2eeRooms.indexOf(r) === -1)));

  /* refresh rotation */
  const refreshed = (await post('/api/admin/bots/refresh', {}, token)).body.bots;
  check('立即轮换后在线数量仍在 10~20',
    refreshed.online >= 10 && refreshed.online <= 20, 'online=' + refreshed.online);
  const disabled = (await post('/api/admin/bots', { enabled: false }, token)).body.bots;
  check('可一键停用全部机器人', disabled.online === 0);

  /* ---------- D. multi-room simultaneous membership ---------- */
  const b = new Client('v4_bob');
  await b.connect();
  await register(b);

  const r1 = await createRoom(a, 'v4-房间A');
  const r2 = await createRoom(a, 'v4-房间B');
  check('同一客户端可同时持有大厅 + 两个房间', !!r1 && !!r2 && r1 !== r2);
  const stateMid = (await httpJson('/api/state', { headers: H })).body;
  const aRow = stateMid.usersList.find(u => u.uid === a.uid);
  check('服务端记录该用户同时加入 3 个房间', !!aRow && aRow.rooms === 3,
    aRow ? 'rooms=' + aRow.rooms : 'user not found');

  a.clear();
  a.send(P.MSG.ROOM_CREATE, { name: 'v4-房间C' });
  let limitErr = null;
  try { limitErr = await a.wait(P.MSG.ERROR, d => d.code === P.ERR.ROOM_LIMIT, 4000); }
  catch (e) { /* noop */ }
  check('第 4 个房间被 E_ROOM_LIMIT 拒绝', !!limitErr);

  /* room isolation: Bob is only in the lobby, so he must not see room A traffic */
  b.clear();
  sendText(a, r1, '房间A 的密文消息');
  await sleep(400);
  check('非成员收不到该房间的广播',
    !b.inbox.some(e => e.type === P.MSG.MESSAGE_BROADCAST && e.data.room === r1));

  /* Bob joins room A and can then decrypt its traffic */
  b.clear();
  b.send(P.MSG.ROOM_JOIN, { roomId: r1 });
  const joinedB = await b.wait(P.MSG.ROOM_JOINED, d => d.room.id === r1, 6000);
  b.keys[r1] = C.unwrapKey(b.privateKey, joinedB.data.wrappedKey);
  b.clear();
  sendText(a, r1, '房间A 第二条');
  const gotA = await b.wait(P.MSG.MESSAGE_BROADCAST, d => d.room === r1, 6000);
  check('同房间成员可收到并解密消息',
    decryptBroadcast(b, gotA.data).text === '房间A 第二条');
  check('广播携带正确的房间 ID', gotA.data.room === r1);

  /* leave frees a slot */
  a.send(P.MSG.ROOM_LEAVE, { roomId: r1 });
  await sleep(250);
  const r3 = await createRoom(a, 'v4-房间C2');
  check('离开房间后可重新创建新房间', !!r3);

  /* history per room */
  a.clear();
  a.send(P.MSG.HISTORY, { roomId: r2, limit: 20 });
  const histR2 = await a.wait(P.MSG.HISTORY_DATA, d => d.room === r2, 6000);
  check('可按房间分别读取加密归档历史', Array.isArray(histR2.data.messages));
  a.clear();
  sendText(a, r2, '房间B 的消息');
  await sleep(300);
  a.send(P.MSG.HISTORY, { roomId: r2, limit: 20 });
  const histR2b = await a.wait(P.MSG.HISTORY_DATA, d => d.room === r2, 6000);
  const decR2 = histR2b.data.messages.map(m => {
    try { return decryptBroadcast(a, m).text; } catch (e) { return null; }
  });
  check('历史消息按房间隔离且可解密',
    histR2b.data.messages.length >= 1 && decR2.indexOf('房间B 的消息') !== -1,
    JSON.stringify(decR2));

  /* ---------- E. restore defaults + soft restart persistence ---------- */
  const restored = (await post('/api/admin/bots', {
    enabled: true, autoReply: true, replyProbability: 0.6, refreshMs: 25000,
    poolSize: 1000, minOnline: 10, maxOnline: 20
  }, token)).body.bots;
  check('机器人配置可恢复默认值',
    restored.enabled && restored.autoReply && restored.replyProbability === 0.6 &&
    restored.refreshMs === 25000);

  const chainBefore = (await httpJson('/api/admin/ledger/verify', { headers: H })).body;
  check('身份链在 v4 操作后仍完整', chainBefore.ok === true,
    JSON.stringify(chainBefore));

  const restart = await post('/api/admin/restart', {}, token);
  check('管理端软重启请求被接受', restart.body.ok === true);
  await sleep(1800);
  const after = await httpJson('/api/health');
  check('软重启后服务恢复', after.body.ok === true && /^5\./.test(after.body.version || '') && after.body.version === P.RELEASE_VERSION);
  const token2 = await adminToken();
  const botsAfter = (await httpJson('/api/admin/bots', { headers: { 'X-Admin-Token': token2 } })).body;
  check('软重启后机器人池与配置持久化',
    botsAfter.records >= 1000 && botsAfter.online >= 10 && botsAfter.online <= 20 &&
    botsAfter.refreshMs === 25000, JSON.stringify({ records: botsAfter.records, online: botsAfter.online }));

  a.close(); b.close();
  console.log(`\n=== 结果: ${passed} 通过 / ${failed} 失败 ===\n`);
  process.exit(failed ? 1 : 0);
}

main().catch(e => { console.error('v4 测试异常:', e.stack || e.message); process.exit(1); });
