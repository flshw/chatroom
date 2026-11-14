/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
'use strict';
/*
 * v5 end-to-end tests: formal-user-only identity chain, annotated config,
 * copyright management + live broadcast, room rename sync, online rename,
 * lobby direct E2EE chat, online-user filter and client UI capabilities.
 *
 *   node tools/smoke-v5.js
 *   CHATROOM_BASE=http://127.0.0.1:8099 node tools/smoke-v5.js
 *
 * Requires a running v5 server. Config edits made by this test are restored.
 */
const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');
const WebSocket = require('../server/node_modules/ws');
const forge = require('../server/node_modules/node-forge');
const P = require('../shared/protocol');
const C = require('../server/src/crypto');

const ROOT = path.resolve(__dirname, '..');
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
  return { status: r.status, headers: r.headers, text: await r.text() };
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
  const file = process.env.CHATROOM_ADMIN_KEYS || path.join(
    process.env.CHATROOM_DATA_DIR || path.join(ROOT, 'server', 'data'), 'admin-keys.json');
  const stored = JSON.parse(fs.readFileSync(file, 'utf8'));
  const ch = (await httpJson('/api/admin/challenge')).body;
  const priv = forge.pki.privateKeyFromPem(stored.privateKeyPem);
  const sig = C.signCanonical(priv, ['admin', ch.challenge, ch.ts].join('|'));
  const r = await post('/api/admin/login',
    { mode: 'signature', challenge: ch.challenge, ts: ch.ts, sig });
  if (!r.body || !r.body.ok) throw new Error('管理员登录失败: ' + JSON.stringify(r.body));
  return r.body.token;
}

class Client {
  constructor(name) {
    this.name = name; this.inbox = []; this.ws = null;
    this.keys = {}; this.seqMap = {}; this.dmSeqMap = {};
    this.uid = ''; this.permanent = false;
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
    const end = Date.now() + (ms || 7000);
    while (Date.now() < end) {
      const hit = this.inbox.find(e => e.type === type && (!pred || pred(e.data || {})));
      if (hit) return hit;
      await sleep(25);
    }
    throw new Error(`${this.name} 等待 ${type} 超时`);
  }
  has(type, pred) {
    return this.inbox.some(e => e.type === type && (!pred || pred(e.data || {})));
  }
  close() { try { this.ws.close(); } catch (e) { /* noop */ } }
}

async function register(cl, permanent) {
  const kp = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  cl.privateKey = kp.privateKey;
  cl.publicKeyPem = forge.pki.publicKeyToPem(kp.publicKey);
  cl.clear();
  cl.send(P.MSG.HELLO, {});
  const w = await cl.wait(P.MSG.WELCOME);
  const inner = {
    v: P.PROTOCOL_VERSION, username: cl.name,
    browserId: 'v5_' + cl.name + '_' + nodeCrypto.randomBytes(6).toString('hex'),
    ts: Date.now(), nonce: C.b64(C.randomBytes(16)),
    challenge: w.data.challenge, clientPub: cl.publicKeyPem, sig: '',
    permanent: !!permanent
  };
  inner.sig = C.signCanonical(kp.privateKey, C.canonicalRegister(inner));
  cl.send(P.MSG.REGISTER, {
    blob: C.hybridEncrypt(forge.pki.publicKeyFromPem(w.data.pubKey), JSON.stringify(inner))
  });
  const reg = await cl.wait(P.MSG.REGISTERED);
  cl.uid = reg.data.uid;
  cl.permanent = !!reg.data.permanent;
  cl.server = reg.data.server;
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

const directAad = (room, uid, seq, ts) => ['dm', room, uid, seq, ts].join('|');

function sendDirect(from, to, roomId, text, seqOverride) {
  const seq = seqOverride || ((from.dmSeqMap[roomId] || 0) + 1);
  const ts = Date.now();
  const key = C.randomBytes(32);
  const wrappedKey = C.wrapKey(forge.pki.publicKeyFromPem(to.publicKeyPem), key);
  const enc = C.aesEncrypt(key, JSON.stringify({ text, kind: 'text' }),
    directAad(roomId, from.uid, seq, ts));
  from.send(P.MSG.DIRECT_MESSAGE, {
    room: roomId, to: to.uid, seq, ts,
    iv: enc.iv, ct: enc.ct, tag: enc.tag, wrappedKey
  });
  from.dmSeqMap[roomId] = seq;
  return { seq, ts, wrappedKey, key };
}

function decryptDirect(to, d) {
  const key = C.unwrapKey(to.privateKey, d.wrappedKey);
  return JSON.parse(C.aesDecrypt(key, d, directAad(d.room, d.from, d.seq, d.ts)));
}

async function main() {
  console.log('\n=== ChatRoom v5 新功能端到端测试 ===');
  console.log('目标服务端: ' + BASE + '\n');

  /* ---------- A. version, feature flags, config annotations ---------- */
  const health = (await httpJson('/api/health')).body;
  check('健康检查返回 v5.0.0', health.ok === true && health.version === '5.0.0');
  check('协议常量为 5.0.0', P.RELEASE_VERSION === '5.0.0');
  check('默认版权常量为 CJS flshw@126.com', P.DEFAULT_COPYRIGHT === 'CJS flshw@126.com');
  check('临时昵称分隔符已定义', P.TEMP_NAME_SEPARATOR === '·');

  const serverInfo = (await httpJson('/api/server-info')).body;
  check('服务端能力标记包含大厅直聊/在线改名/配置同步/版权',
    ['lobbyDirect', 'onlineRename', 'serverConfigSync'].every(f => serverInfo.features.indexOf(f) !== -1),
    JSON.stringify(serverInfo.features));
  const clientInfo = (await httpJson('/api/client-info')).body;
  check('客户端能力标记包含 v5 新特性',
    ['lobbyDirect', 'onlineRename', 'serverConfigSync', 'copyright']
      .every(f => clientInfo.features.indexOf(f) !== -1), JSON.stringify(clientInfo.features));

  const notes = (await httpJson('/api/config/notes')).body;
  const noteKeys = Object.keys(notes.notes || {});
  check('配置字段注释覆盖全部可编辑项 (>= 8)', noteKeys.length >= 8,
    '实际 ' + noteKeys.length + ' 项');
  check('每项注释含 label / note / scope 三段说明',
    noteKeys.every(k => notes.notes[k].label && notes.notes[k].note && notes.notes[k].scope));
  check('只读字段被明确标注', (notes.readOnly || []).indexOf('host') !== -1 &&
    (notes.readOnly || []).indexOf('maxMessageBytes') !== -1);

  const token = await adminToken();
  check('管理员 RSA 挑战签名登录成功', typeof token === 'string' && token.length > 20);

  /* ---------- B. identity chain: formal users only ---------- */
  const ledgerBefore = (await httpJson('/api/admin/ledger', {
    headers: { 'X-Admin-Token': token }
  })).body;
  const blocksBefore = (ledgerBefore.blocks || []).length;

  const alice = new Client('v5正式Alice');
  const temp = new Client('v5临时Bob');
  const carol = new Client('v5旁听Carol');
  await Promise.all([alice.connect(), temp.connect(), carol.connect()]);
  const regA = await register(alice, true);
  const regT = await register(temp, false);
  await register(carol, false);
  check('正式用户注册回执 permanent=true', regA.permanent === true && alice.permanent === true);
  check('临时用户注册回执 permanent=false', regT.permanent === false && temp.permanent === false);
  check('注册回执下发服务器名称与版权',
    !!regA.server.name && regA.server.copyright === P.DEFAULT_COPYRIGHT,
    JSON.stringify(regA.server && regA.server.copyright));

  const ledgerAfter = (await httpJson('/api/admin/ledger', {
    headers: { 'X-Admin-Token': token }
  })).body;
  const newBlocks = (ledgerAfter.blocks || []).slice(blocksBefore);
  const payloads = newBlocks.map(b => String(b.payload || '')).join(' | ');
  check('正式用户写入身份链', payloads.indexOf(alice.uid) !== -1,
    '新增区块 ' + newBlocks.length + ' 个');
  check('临时用户不写入身份链', payloads.indexOf(temp.uid) === -1 && payloads.indexOf(carol.uid) === -1);
  check('身份链完整性校验通过', ledgerAfter.verify && ledgerAfter.verify.ok === true,
    JSON.stringify(ledgerAfter.verify));
  const identities = (await httpJson('/api/admin/identities', {
    headers: { 'X-Admin-Token': token }
  })).body;
  check('身份链策略声明为仅正式用户', /正式用户/.test(identities.chainPolicy || ''));
  check('在线用户列表可用于「只看在线」筛选',
    Array.isArray(identities.onlineUids) && identities.onlineUids.indexOf(alice.uid) !== -1);
  const state = (await httpJson('/api/state', { headers: { 'X-Admin-Token': token } })).body;
  check('在线状态接口返回 permanent 标记与 chainPolicy',
    state.chainPolicy === 'formal-users-only' &&
    (state.usersList || []).some(u => u.uid === alice.uid && u.permanent === true && u.online === true));

  /* ---------- C. copyright + chatroom name sync ---------- */
  const originalConfig = (await httpJson('/api/config')).body;
  const testName = 'v5测试聊天室';
  const testCopyright = 'CJS v5-test flshw@126.com';
  alice.clear(); temp.clear();
  const cfg = await post('/api/config', {
    name: testName, copyright: testCopyright, copyrightLink: 'mailto:flshw@126.com'
  }, token);
  check('保存配置返回即时广播的服务器信息',
    cfg.body.ok === true && cfg.body.server.name === testName &&
    cfg.body.server.copyright === testCopyright);
  const cfgPushA = await alice.wait(P.MSG.SERVER_CONFIG_UPDATE,
    d => d.server && d.server.name === testName);
  const cfgPushT = await temp.wait(P.MSG.SERVER_CONFIG_UPDATE,
    d => d.server && d.server.copyright === testCopyright);
  check('聊天室名称修改后所有在线客户端同步',
    cfgPushA.data.server.name === testName && cfgPushT.data.server.name === testName);
  check('版权文字/链接修改后同步给客户端',
    cfgPushA.data.server.copyright === testCopyright &&
    cfgPushA.data.server.copyrightLink === 'mailto:flshw@126.com');
  const infoAfter = (await httpJson('/api/server-info')).body;
  check('公开服务器信息反映新名称与版权',
    infoAfter.name === testName && infoAfter.copyright === testCopyright);

  /* ---------- D. room rename sync ---------- */
  const roomId = await createRoom(alice, 'v5待改名房间');
  alice.clear(); temp.clear();
  const renamed = await post('/api/admin/room/rename', { roomId, name: 'v5已改名房间' }, token);
  check('管理端房间改名接口返回成功', renamed.body.ok === true && renamed.body.room.name === 'v5已改名房间');
  const roomPush = await alice.wait(P.MSG.ROOM_UPDATED,
    d => d.room && d.room.id === roomId && d.room.name === 'v5已改名房间');
  check('房间改名广播到在线客户端', !!roomPush.data.room);
  const roomPushT = await temp.wait(P.MSG.ROOM_UPDATED, d => d.room && d.room.id === roomId);
  check('非房间成员也收到房间名同步（大厅标签可刷新）', !!roomPushT.data.room);

  /* ---------- E. online rename (temp keeps random stamp) ---------- */
  temp.clear();
  const newTempName = '改名后的Bob·AB12CD';
  temp.send(P.MSG.NICKNAME_CHANGE, { nickname: newTempName });
  const nick = await temp.wait(P.MSG.NICKNAME_UPDATED);
  check('临时用户在线改名保留随机时间戳',
    nick.data.nickname === newTempName && nick.data.permanent === false &&
    /·[A-Z0-9]{4,6}$/.test(nick.data.nickname));
  alice.clear();
  alice.send(P.MSG.NICKNAME_CHANGE, { nickname: '正式Alice新名' });
  const nickA = await alice.wait(P.MSG.NICKNAME_UPDATED);
  check('正式用户在线改名不带时间戳且 permanent=true',
    nickA.data.nickname === '正式Alice新名' && nickA.data.permanent === true);

  /* ---------- F. lobby direct E2EE chat, no room created ---------- */
  const roomsBefore = (await httpJson('/api/admin/rooms', {
    headers: { 'X-Admin-Token': token }
  })).body.rooms.length;
  alice.clear(); temp.clear(); carol.clear();
  const sent = sendDirect(alice, temp, P.LOBBY_ID, '这是一条只有 Bob 能读的私聊');
  const got = await temp.wait(P.MSG.DIRECT_MESSAGE_BROADCAST, d => d.seq === sent.seq);
  const plain = decryptDirect(temp, got.data);
  check('大厅私聊密文可被接收方私钥解封并解密', plain.text === '这是一条只有 Bob 能读的私聊');
  check('私聊使用 dm 命名空间 AAD，公聊密钥无法解密', (() => {
    try {
      C.aesDecrypt(alice.keys[P.LOBBY_ID], got.data, directAad(P.LOBBY_ID, alice.uid, sent.seq, sent.ts));
      return false;
    } catch (e) { return true; }
  })());
  check('篡改 AAD（换成公聊命名空间）会被 GCM 拒绝', (() => {
    try {
      const key = C.unwrapKey(temp.privateKey, got.data.wrappedKey);
      C.aesDecrypt(key, got.data, [P.LOBBY_ID, alice.uid, sent.seq, sent.ts].join('|'));
      return false;
    } catch (e) { return true; }
  })());
  check('第三方不会收到私聊密文', !carol.has(P.MSG.DIRECT_MESSAGE_BROADCAST));
  check('发送方不会收到自己的私聊广播', !alice.has(P.MSG.DIRECT_MESSAGE_BROADCAST));
  const roomsAfter = (await httpJson('/api/admin/rooms', {
    headers: { 'X-Admin-Token': token }
  })).body.rooms.length;
  check('大厅私聊不创建任何新房间', roomsAfter === roomsBefore,
    roomsBefore + ' -> ' + roomsAfter);

  const archive = (await httpJson('/api/admin/room/messages?room=' + P.LOBBY_ID + '&limit=50', {
    headers: { 'X-Admin-Token': token }
  })).body;
  const e2eeRow = (archive.messages || []).find(m => m.text && m.text.indexOf('端到端加密') !== -1);
  check('服务端归档私聊仅保留不可解密标记', !!e2eeRow);
  /* history replies must not try to decrypt E2EE rows with the room key */
  temp.send(P.MSG.HISTORY, { roomId: P.LOBBY_ID, limit: 50 });
  const histEnv = await temp.wait(P.MSG.HISTORY_DATA, d => d.room === P.LOBBY_ID);
  check('历史消息中私聊以 e2ee 标记返回，不混入可解密公聊',
    (histEnv.data.messages || []).filter(m => m.e2ee).length >= 1);

  /* replay protection for direct messages */
  const replay = await (async () => {
    alice.clear();
    sendDirect(alice, temp, P.LOBBY_ID, '重放消息', sent.seq);
    try { return await alice.wait(P.MSG.ERROR, null, 1500); }
    catch (e) { return null; }
  })();
  check('私聊消息序号重放被拒绝', !!replay, replay ? JSON.stringify(replay.data) : '未收到错误');

  /* ---------- F2. v5.2 drag-to-room invite (member list -> room tab) ---------- */
  alice.clear(); temp.clear(); carol.clear();
  carol.send(P.MSG.ROOM_DRAG_INVITE, { room: roomId, to: temp.uid });
  const errNotMember = await carol.wait(P.MSG.ERROR, d => d.code === 'E_FORBIDDEN');
  check('非房间成员不能拖拽邀请他人入房', errNotMember.data.code === 'E_FORBIDDEN');

  alice.send(P.MSG.ROOM_DRAG_INVITE, { room: P.LOBBY_ID, to: temp.uid });
  const errLobby = await alice.wait(P.MSG.ERROR, d => d.code === 'E_DRAG_INVITE_INVALID');
  check('拖拽到大厅被拒绝（大厅无需邀请）', errLobby.data.code === 'E_DRAG_INVITE_INVALID');

  alice.clear();
  alice.send(P.MSG.ROOM_DRAG_INVITE, { room: roomId, to: temp.uid });
  const offer = await temp.wait(P.MSG.ROOM_INVITE_OFFER, d => d.token && d.roomId === roomId);
  check('被拖拽方收到房间邀请（含邀请人/房间名/令牌）',
    offer.data.inviterName.indexOf('Alice') !== -1 &&
    offer.data.roomName === 'v5已改名房间' && offer.data.token.length >= 12,
    JSON.stringify(offer.data));
  const noticeSent = await alice.wait(P.MSG.NOTICE, d => (d.text || '').indexOf('邀请') !== -1);
  check('邀请方收到「邀请已发送，等待确认」提示', (noticeSent.data.text || '').indexOf('等待') !== -1);

  temp.clear();
  temp.send(P.MSG.ROOM_INVITE_REPLY, { token: offer.data.token, accept: true });
  const joined = await temp.wait(P.MSG.ROOM_JOINED, d => d.room && d.room.id === roomId);
  const dragKey = C.unwrapKey(temp.privateKey, joined.data.wrappedKey);
  check('同意后直接进入房间并成功解封会话密钥',
    typeof dragKey === 'string' && dragKey.length >= 32);
  const noticeOk = await alice.wait(P.MSG.NOTICE, d => (d.text || '').indexOf('接受') !== -1);
  check('邀请方收到对方已接受并进房的通知', (noticeOk.data.text || '').indexOf('接受') !== -1);

  carol.clear(); alice.clear();
  alice.send(P.MSG.ROOM_DRAG_INVITE, { room: roomId, to: carol.uid });
  const offer2 = await carol.wait(P.MSG.ROOM_INVITE_OFFER, d => d.roomId === roomId);
  carol.send(P.MSG.ROOM_INVITE_REPLY, { token: offer2.data.token, accept: false });
  const noticeDecline = await alice.wait(P.MSG.NOTICE, d => (d.text || '').indexOf('拒绝') !== -1);
  check('拒绝邀请会通知邀请方', !!noticeDecline.data.text);
  let carolJoined = false;
  try {
    await carol.wait(P.MSG.ROOM_JOINED, d => d.room && d.room.id === roomId, 1200);
    carolJoined = true;
  } catch (e) { /* expected timeout */ }
  check('拒绝后不会收到房间加入回执', carolJoined === false);

  carol.clear();
  carol.send(P.MSG.ROOM_INVITE_REPLY, { token: 'faketoken123456', accept: true });
  const errToken = await carol.wait(P.MSG.ERROR, d => d.code === 'E_INVITE_INVALID');
  check('伪造/过期邀请令牌被拒绝', errToken.data.code === 'E_INVITE_INVALID');

  /* ---------- G. client static capabilities & copyright headers ---------- */
  const tpl = fs.readFileSync(path.join(ROOT, 'client', 'src', 'index.html'), 'utf8');
  const app = fs.readFileSync(path.join(ROOT, 'client', 'src', 'app.js'), 'utf8');
  const css = fs.readFileSync(path.join(ROOT, 'client', 'src', 'style.css'), 'utf8');
  const admin = fs.readFileSync(path.join(ROOT, 'server', 'admin', 'index.html'), 'utf8');
  check('登录页身份信息包导入/注册两个入口都外置（无折叠）',
    /identity-panel/.test(tpl) && /f-identity/.test(tpl) && /f-save-identity/.test(tpl) &&
    !/identity-panel[^>]*>\s*<details/.test(tpl));
  check('客户端实现临时用户随机时间戳与正式/临时昵称区分',
    /makeTempStamp/.test(app) && /composeNickname/.test(app) &&
    /msg-author ' \+ \(m\.formal/.test(app) && /msg-author\.formal/.test(css) && /msg-author\.temp/.test(css));
  check('客户端实现在线改名并保留时间戳',
    /NICKNAME_CHANGE/.test(app) && /rename-modal/.test(tpl) && /renamePreview|updateRenamePreview/.test(app));
  check('客户端实现大厅直聊与公聊/私聊快速切换',
    /DIRECT_MESSAGE/.test(app) && /mode-bar/.test(tpl) && /mode-btn/.test(css) &&
    /dm-chip/.test(css) && /msg-row\.direct/.test(css));
  check('客户端实现服务器名称与版权同步及底栏',
    /applyServerBrand/.test(app) && /SERVER_CONFIG_UPDATE/.test(app) &&
    /app-foot/.test(tpl) && /app-foot/.test(css) && /login-copyright/.test(css));
  check('协议定义拖拽邀请消息类型与 60 秒有效期',
    P.MSG.ROOM_DRAG_INVITE === 'room_drag_invite' &&
    P.MSG.ROOM_INVITE_OFFER === 'room_invite_offer' &&
    P.MSG.ROOM_INVITE_REPLY === 'room_invite_reply' &&
    P.LIMITS.DRAG_INVITE_TTL_MS === 60000);
  check('客户端实现成员拖拽到房间标签发起邀请',
    /draggable/.test(app) && /wireDropTarget/.test(app) &&
    /ROOM_DRAG_INVITE/.test(app) && /ROOM_INVITE_OFFER/.test(app) &&
    /invite-modal/.test(tpl) && /drop-ok/.test(css) && /invite-av/.test(css));
  check('被邀请方弹窗支持同意/拒绝且支持排队',
    /inviteQueue/.test(app) && /answerInvite/.test(app) &&
    /btn-invite-accept/.test(tpl) && /btn-invite-decline/.test(tpl));
  check('客户端整体 UI 美化（渐变背景/卡片阴影/响应式）',
    /radial-gradient/.test(css) && /v5-shadow-lg/.test(css) &&
    /backdrop-filter/.test(css) && /@media\(max-width:760px\)/.test(css));
  check('管理页具备配置注释、版权管理与只看在线用户',
    /FIELD_NOTES|cfg-note/.test(admin) && /cfg-copyright/.test(admin) &&
    /users-online-only/.test(admin));

  const sourceFiles = [];
  const walk = dir => {
    for (const n of fs.readdirSync(dir)) {
      if (n === 'node_modules' || n === 'data' || n === 'dist' || n === 'public') continue;
      const p = path.join(dir, n);
      const st = fs.statSync(p);
      if (st.isDirectory()) walk(p);
      else if (/\.(js|css|html)$/.test(n)) sourceFiles.push(p);
    }
  };
  walk(path.join(ROOT, 'client', 'src'));
  walk(path.join(ROOT, 'server', 'src'));
  walk(path.join(ROOT, 'tools'));
  const missing = sourceFiles.filter(f => fs.readFileSync(f, 'utf8').indexOf('CJS flshw@126.com') === -1);
  check('全部源码文件含版权信息 CJS flshw@126.com',
    missing.length === 0, '缺少 ' + missing.length + ' 个: ' + missing.slice(0, 3).join(', '));

  /* ---------- cleanup: restore config and temporary room ---------- */
  await post('/api/config', {
    name: originalConfig.name, copyright: originalConfig.copyright,
    copyrightLink: originalConfig.copyrightLink
  }, token);
  await post('/api/admin/room/delete', { roomId }, token);
  [alice, temp, carol].forEach(c => c.close());

  console.log(`\n=== 结果: ${passed} 通过 / ${failed} 失败 ===\n`);
  process.exit(failed ? 1 : 0);
}

main().catch(e => {
  console.error('\n测试异常: ' + (e && e.stack || e));
  process.exit(1);
});
