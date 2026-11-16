/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
'use strict';
/*
 * v3 end-to-end test: admin login, identity ledger, persistent identity,
 * access control, invite-only rooms, private E2EE chat, encrypted files,
 * room deletion and soft restart.
 *
 *   CHATROOM_BASE=http://127.0.0.1:8080 node tools/smoke-v3.js
 */
const WebSocket = require('../server/node_modules/ws');
const forge = require('../server/node_modules/node-forge');
const fs = require('fs');
const path = require('path');
const P = require('../shared/protocol');
const C = require('../server/src/crypto');

const BASE = process.env.CHATROOM_BASE || 'http://127.0.0.1:8080';
const BASE_URL = new URL(BASE);
const BASE_PORT = parseInt(BASE_URL.port || (BASE_URL.protocol === 'https:' ? '443' : '80'), 10);
const WS_URL = BASE.replace(/^http/, 'ws') + '/ws';
// v4: allow testing an isolated deployment that generated its own admin keys.
const ADMIN_KEYS = process.env.CHATROOM_ADMIN_KEYS || path.join(
  process.env.CHATROOM_DATA_DIR || path.join(__dirname, '..', 'server', 'data'),
  'admin-keys.json');

let passed = 0, failed = 0;
function check(name, ok, detail) {
  if (ok) { passed++; console.log('  PASS  ' + name); }
  else { failed++; console.log('  FAIL  ' + name + (detail ? ' -> ' + detail : '')); }
}
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function api(pathname, opts, token) {
  const headers = Object.assign({ 'Content-Type': 'application/json' },
    token ? { 'X-Admin-Token': token } : {});
  const r = await fetch(BASE + pathname, Object.assign({ headers }, opts || {}));
  let body;
  try { body = await r.json(); } catch (e) { body = {}; }
  return { status: r.status, body };
}
const post = (p, b, t) => api(p, { method: 'POST', body: JSON.stringify(b || {}) }, t);
const get = (p, t) => api(p, { method: 'GET' }, t);

class Client {
  constructor(name) { this.name = name; this.inbox = []; this.waiters = []; this.ws = null; }
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
  wait(type, extra, ms) {
    const pred = typeof extra === 'function'
      ? env => env.type === type && extra(env.data || {})
      : env => env.type === type;
    const existing = this.inbox.find(pred);
    if (existing) return Promise.resolve(existing);
    return new Promise((resolve, reject) => {
      const w = {
        pred, resolve,
        timer: setTimeout(() => {
          const i = this.waiters.indexOf(w);
          if (i >= 0) this.waiters.splice(i, 1);
          reject(new Error(this.name + ' 等待 ' + type + ' 超时'));
        }, ms || 6000)
      };
      this.waiters.push(w);
    });
  }
  close() { try { this.ws.close(); } catch (e) { /* noop */ } }
}

async function hello(cl) {
  cl.send(P.MSG.HELLO, {});
  return (await cl.wait(P.MSG.WELCOME)).data;
}

async function register(cl, welcome, opts) {
  opts = opts || {};
  let priv, pubPem;
  if (opts.identity) {
    priv = opts.identity.privateKey;
    pubPem = opts.identity.publicKeyPem;
  } else {
    const kp = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
    priv = kp.privateKey;
    pubPem = forge.pki.publicKeyToPem(kp.publicKey);
  }
  const inner = {
    v: P.PROTOCOL_VERSION,
    username: opts.username || cl.name,
    browserId: 'v3_' + cl.name + '_' + C.b64(C.randomBytes(8)),
    ts: Date.now(),
    nonce: C.b64(C.randomBytes(16)),
    challenge: welcome.challenge,
    clientPub: pubPem,
    permanent: !!opts.permanent || !!opts.identity,
    sig: ''
  };
  if (opts.identity) {
    const proofKey = opts.badProof
      ? forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 }).privateKey : priv;
    inner.resume = {
      uid: opts.identity.uid,
      proof: C.signCanonical(proofKey,
        [opts.identity.uid, inner.ts, welcome.challenge].join('|'))
    };
  }
  inner.sig = C.signCanonical(priv, C.canonicalRegister(inner));
  const blob = C.hybridEncrypt(forge.pki.publicKeyFromPem(welcome.pubKey), JSON.stringify(inner));
  cl.send(P.MSG.REGISTER, { blob });
  const done = await cl.wait(P.MSG.REGISTERED, null, 8000).catch(() => null);
  if (done) {
    cl.uid = done.data.uid;
    cl.lobbyKey = C.unwrapKey(priv, done.data.wrappedLobbyKey);
    cl.privateKey = priv;
    cl.publicKeyPem = pubPem;
  }
  return { done, inner };
}

async function adminLogin() {
  const stored = JSON.parse(fs.readFileSync(ADMIN_KEYS, 'utf8'));
  const ch = (await get('/api/admin/challenge')).body;
  const priv = forge.pki.privateKeyFromPem(stored.privateKeyPem);
  const sig = C.signCanonical(priv, ['admin', ch.challenge, ch.ts].join('|'));
  return post('/api/admin/login',
    { mode: 'signature', challenge: ch.challenge, ts: ch.ts, sig });
}

function sendText(cl, roomId, key, text, seq) {
  const ts = Date.now();
  const aad = [roomId, cl.uid, seq, ts].join('|');
  const enc = C.aesEncrypt(key, JSON.stringify({ text, kind: 'text' }), aad);
  cl.send(P.MSG.MESSAGE, Object.assign({ room: roomId, seq, ts }, enc));
  return { ts, aad, enc };
}

async function main() {
  console.log('\n=== ChatRoom v3 功能回归测试（运行于 v5 服务端） ===');
  console.log('目标服务端: ' + BASE + '\n');

  /* ---- 1. admin authentication ---- */
  const health = (await get('/api/health')).body;
  check('健康检查返回 v5', health.ok === true && /^5\./.test(health.version || '') && health.version === P.RELEASE_VERSION);
  check('未登录访问 /api/state 被拒绝', (await get('/api/state')).status === 401);
  const login = await adminLogin();
  check('管理员 RSA 私钥挑战签名登录成功', login.body.ok === true && !!login.body.token);
  const token = login.body.token;
  const badPwd = await post('/api/admin/login', { mode: 'password', password: 'definitely-wrong', challenge: 'x', ts: Date.now() });
  check('错误口令登录被拒绝', badPwd.status === 401);
  check('管理员令牌可访问 /api/state', (await get('/api/state', token)).status === 200);

  /* ---- 2. identity ledger ---- */
  const chain = (await get('/api/admin/ledger', token)).body;
  check('身份链完整性校验通过', chain.verify && chain.verify.ok === true, JSON.stringify(chain.verify));
  check('身份链含创世区块', chain.blocks.length >= 1 && chain.blocks[0].action === 'genesis');

  const { IdentityLedger } = require('../server/src/ledger.js');
  const fakeBlocks = chain.blocks.map(b => ({
    idx: b.idx, prev_hash: b.prevHash, ts: b.ts, action: b.action,
    payload: b.payload, nonce: b.nonce, hash: b.hash, sig: b.sig
  }));
  const fakeDb = {
    blockCount: () => fakeBlocks.length,
    lastBlock: () => fakeBlocks[fakeBlocks.length - 1],
    allBlocks: () => fakeBlocks,
    appendBlock: b => fakeBlocks.push(b)
  };
  const fakeKeys = {
    publicKey: forge.pki.publicKeyFromPem((await get('/api/server-info')).body.publicKey)
  };
  const tamper = new IdentityLedger({ db: fakeDb, keys: fakeKeys, logger: () => {} });
  fakeBlocks[0].payload = '{"tampered":true}';
  const tamperResult = tamper.verify();
  check('身份链可检出内容篡改', tamperResult.ok === false && tamperResult.reason.indexOf('哈希') >= 0);

  /* ---- 3. persistent identity + resume ---- */
  const a = new Client('Alice_v3');
  await a.connect();
  const wa = await hello(a);
  const regA = await register(a, wa, { username: 'Alice_v3', permanent: true });
  check('持久身份注册成功', !!regA.done && !!a.uid);
  check('REGISTERED 标记为持久身份', !!(regA.done && regA.done.data.permanent));
  const ids = (await get('/api/admin/identities', token)).body.identities || [];
  check('身份记录已保存公钥与昵称',
    ids.some(x => x.uid === a.uid && x.nickname === 'Alice_v3' && /BEGIN PUBLIC KEY/.test(x.pubkey)));
  check('身份记录不含私钥', !JSON.stringify(ids).includes('BEGIN RSA PRIVATE KEY'));

  const b = new Client('Bob_v3');
  await b.connect();
  const wb = await hello(b);
  const regB = await register(b, wb, { username: 'Bob_v3', permanent: true });
  check('第二个持久身份注册成功', !!regB.done && b.uid !== a.uid);

  /* Use a dedicated identity for resume tests so Alice/Bob stay online. */
  const d = new Client('Dave_v3');
  await d.connect();
  const wd = await hello(d);
  await register(d, wd, { username: 'Dave_v3', permanent: true });
  d.close();
  await sleep(120);

  const resume = new Client('Dave_resume');
  await resume.connect();
  const wr = await hello(resume);
  const regR = await register(resume, wr, {
    username: 'Dave_v3',
    identity: { uid: d.uid, privateKey: d.privateKey, publicKeyPem: d.publicKeyPem }
  });
  check('身份文件可恢复同一 UID', !!regR.done && resume.uid === d.uid,
    regR.done ? resume.uid + ' vs ' + d.uid : 'no REGISTERED');

  const bad = new Client('Bad_proof');
  await bad.connect();
  const wbad = await hello(bad);
  await register(bad, wbad, {
    username: 'Dave_v3', badProof: true,
    identity: { uid: d.uid, privateKey: d.privateKey, publicKeyPem: d.publicKeyPem }
  });
  const badErr = await bad.wait(P.MSG.ERROR, d => d.code === P.ERR.IDENTITY_INVALID, 5000).catch(() => null);
  check('伪造身份恢复证明被拒绝', !!badErr);
  bad.close(); resume.close();

  /* ---- 4. invite-only room ---- */
  a.send(P.MSG.ROOM_CREATE, { name: '私密会议室', private: true });
  const secretJoined = await a.wait(P.MSG.ROOM_JOINED, d => d.room.private === true);
  const secret = secretJoined.data.room;
  const secretKey = C.unwrapKey(a.privateKey, secretJoined.data.wrappedKey);
  check('私密房间创建并生成邀请短码', !!secret.invite && /^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(secret.invite));
  b.send(P.MSG.ROOM_JOIN, { roomId: secret.id });
  const forbidden = await b.wait(P.MSG.ERROR, d => d.code === P.ERR.FORBIDDEN, 4000).catch(() => null);
  check('私密房间不能凭房间 ID 直接进入', !!forbidden);
  b.send(P.MSG.ROOM_JOIN, { invite: secret.invite });
  const bJoined = await b.wait(P.MSG.ROOM_JOINED, d => d.room.id === secret.id);
  check('凭邀请短码可进入私密房间', !!bJoined);

  /* ---- 5. full invite code ---- */
  const invRes = await get('/api/admin/invite?room=' + encodeURIComponent(secret.id), token);
  const code = invRes.body.code;
  check('管理端生成完整邀请码', invRes.body.ok === true && code.slice(0, 4) === 'CR1.');
  check('邀请码含 IP/端口/邀请人/房间信息',
    !!invRes.body.invite.host && invRes.body.invite.port === BASE_PORT &&
    invRes.body.invite.inviterName === '管理员' && invRes.body.invite.roomName === '私密会议室');
  const parsed = await post('/api/invite/parse', { code });
  check('服务端可解析并验证邀请码签名', parsed.body.ok === true && parsed.body.valid === true);
  const forged = await post('/api/invite/parse', { code: code.slice(0, -8) + 'AAAAAAAA' });
  check('篡改的邀请码被拒绝', forged.body.ok === false || forged.body.valid === false);

  const clientInvite = await post('/api/invite/create',
    { uid: a.uid, room: secret.id, host: '127.0.0.1', port: BASE_PORT });
  check('客户端可为所在房间生成完整邀请码',
    clientInvite.body.ok === true && clientInvite.body.invite.host === '127.0.0.1');
  const outsider = await post('/api/invite/create',
    { uid: 'not_a_member', room: secret.id });
  check('非房间成员无法生成邀请码', outsider.status === 403);

  const viaCode = new Client('Carol_v3');
  await viaCode.connect();
  const wc = await hello(viaCode);
  await register(viaCode, wc, { username: 'Carol_v3' });
  viaCode.send(P.MSG.ROOM_JOIN, { invite: code });
  const carolJoined = await viaCode.wait(P.MSG.ROOM_JOINED, d => d.room.id === secret.id, 5000).catch(() => null);
  check('完整邀请码可直接进入指定房间', !!carolJoined);

  /* ---- 6. private E2EE chat ---- */
  const e2eeKey = C.randomBytes(32);
  const wrapped = {};
  wrapped[a.uid] = C.wrapKey(forge.pki.publicKeyFromPem(a.publicKeyPem), e2eeKey);
  wrapped[b.uid] = C.wrapKey(forge.pki.publicKeyFromPem(b.publicKeyPem), e2eeKey);
  a.send(P.MSG.ROOM_CREATE, {
    name: 'Alice ↔ Bob', private: true, e2ee: true,
    wrappedKeys: wrapped, members: [b.uid]
  });
  const ea = await a.wait(P.MSG.ROOM_JOINED, d => d.room.e2ee === true);
  const eb = await b.wait(P.MSG.ROOM_JOINED, d => d.room.e2ee === true);
  const keyA = C.unwrapKey(a.privateKey, ea.data.wrappedKey);
  const keyB = C.unwrapKey(b.privateKey, eb.data.wrappedKey);
  check('E2EE 私聊房间建立成功', !!ea.data.room.id && ea.data.room.e2ee === true);
  check('双方解封得到同一把客户端生成的密钥', keyA === keyB && keyA === e2eeKey);

  const e2eeRoom = ea.data.room.id;
  sendText(a, e2eeRoom, e2eeKey, '这句话只有 Alice 和 Bob 能解密', 1);
  const bc = await b.wait(P.MSG.MESSAGE_BROADCAST, d => d.room === e2eeRoom);
  const plain = JSON.parse(C.aesDecrypt(e2eeKey, bc.data,
    [e2eeRoom, bc.data.from, bc.data.seq, bc.data.ts].join('|')));
  check('E2EE 私聊消息可端到端解密', plain.text === '这句话只有 Alice 和 Bob 能解密');
  check('转发报文不含明文', !JSON.stringify(bc.data).includes('只有 Alice'));

  await sleep(600);
  const adminView = (await get('/api/admin/room/messages?room=' + encodeURIComponent(e2eeRoom) + '&limit=20', token)).body;
  check('管理员查看私聊只得到元数据', adminView.e2ee === true &&
    adminView.messages.length >= 1 && adminView.messages[0].text.indexOf('不可解密') >= 0,
    JSON.stringify(adminView).slice(0, 200));
  check('管理员无法看到私聊明文', !JSON.stringify(adminView).includes('只有 Alice'));

  /* ---- 7. user management ---- */
  const muteRes = await post('/api/admin/identity', { uid: a.uid, action: 'mute' }, token);
  check('禁止发言指令生效', muteRes.body.ok === true && muteRes.body.identity.muted === true);
  sendText(a, secret.id, secretKey, '被禁言后不该发出', 50);
  const mutedErr = await a.wait(P.MSG.ERROR, d => d.code === P.ERR.MUTED, 4000).catch(() => null);
  check('被禁言用户发送消息被拒绝', !!mutedErr);
  await post('/api/admin/identity', { uid: a.uid, action: 'unmute' }, token);
  sendText(a, secret.id, secretKey, '恢复发言后的消息', 51);
  const afterUnmute = await b.wait(P.MSG.MESSAGE_BROADCAST,
    d => d.room === secret.id && d.seq === 51, 5000).catch(() => null);
  check('解除禁言后可正常发言', !!afterUnmute);

  const grantRes = await post('/api/admin/identity',
    { uid: b.uid, action: 'grant', value: secret.id }, token);
  check('可授予指定房间权限', grantRes.body.ok === true &&
    grantRes.body.identity.grants.indexOf(secret.id) >= 0);
  await post('/api/admin/identity', { uid: b.uid, action: 'clearGrants' }, token);

  /* ---- 8. encrypted file transfer ---- */
  const fileAad = ['file', secret.id, b.uid, Date.now()].join('|');
  const fileBytes = '\x89PNG\r\n\x1a\nFAKE-PNG-BYTES';
  const fileEnc = C.aesEncrypt(C.sha256Hex(fileAad).slice(0, 32), fileBytes, fileAad);
  const up = await post('/api/file/upload', {
    uid: b.uid, room: secret.id, name: '示例图片.png', ext: 'png',
    size: fileBytes.length, iv: fileEnc.iv, ct: fileEnc.ct, tag: fileEnc.tag, aad: fileAad
  });
  check('png 文件密文上传成功', up.body.ok === true && !!up.body.file.id);
  const fileId = up.body.file && up.body.file.id;
  const dl = await get('/api/file/get?id=' + encodeURIComponent(fileId) + '&uid=' + encodeURIComponent(b.uid));
  check('下载的密文与上传一致', dl.body.ok === true && dl.body.blob.ct === fileEnc.ct);
  check('文件元数据不含明文内容', !JSON.stringify(dl.body.file).includes('FAKE-PNG'));
  const badExt = await post('/api/file/upload', {
    uid: b.uid, room: secret.id, name: 'virus.exe', ext: 'exe',
    size: 100, iv: fileEnc.iv, ct: fileEnc.ct, tag: fileEnc.tag, aad: fileAad
  });
  check('非 png/pdf/zip 扩展名被拒绝', badExt.body.code === P.ERR.BAD_FILE_TYPE);
  const tooBig = await post('/api/file/upload', {
    uid: b.uid, room: secret.id, name: 'huge.pdf', ext: 'pdf',
    size: P.LIMITS.MAX_FILE_BYTES + 1, iv: fileEnc.iv, ct: fileEnc.ct,
    tag: fileEnc.tag, aad: fileAad
  });
  check('超大文件被拒绝', tooBig.body.code === P.ERR.FILE_TOO_LARGE);
  for (const ext of ['pdf', 'zip']) {
    const r = await post('/api/file/upload', {
      uid: b.uid, room: secret.id, name: 'doc.' + ext, ext,
      size: 100, iv: fileEnc.iv, ct: fileEnc.ct, tag: fileEnc.tag, aad: fileAad
    });
    check(ext + ' 格式允许上传', r.body.ok === true);
  }
  const st = (await get('/api/state', token)).body;
  check('文件计数已增长到 3 以上', st.archive.files >= 3, 'files=' + st.archive.files);

  /* ---- 9. ban / unban ---- */
  await post('/api/admin/identity', { uid: b.uid, action: 'ban' }, token);
  await sleep(150);
  const bannedClient = new Client('Bob_banned');
  await bannedClient.connect();
  const wbb = await hello(bannedClient);
  await register(bannedClient, wbb, {
    username: 'Bob_v3',
    identity: { uid: b.uid, privateKey: b.privateKey, publicKeyPem: b.publicKeyPem }
  });
  const banErr = await bannedClient.wait(P.MSG.ERROR,
    d => d.code === P.ERR.IDENTITY_INVALID || d.code === P.ERR.BANNED, 5000).catch(() => null);
  check('被禁止登录的身份无法重新登录', !!banErr);
  await post('/api/admin/identity', { uid: b.uid, action: 'unban' }, token);
  bannedClient.close();

  /* ---- 10. room deletion ---- */
  const del = await post('/api/admin/room/delete', { roomId: secret.id }, token);
  check('管理端可删除房间', del.body.ok === true);
  const roomsAfter = (await get('/api/admin/rooms', token)).body.rooms || [];
  check('房间已从列表移除', !roomsAfter.some(r => r.id === secret.id));
  const deletedNotice = await a.wait(P.MSG.ROOM_DELETED, d => d.room === secret.id, 4000).catch(() => null);
  check('房间成员收到删除通知', !!deletedNotice);

  /* ---- 11. soft restart ---- */
  const restart = await post('/api/admin/restart', {}, token);
  check('管理端重启请求被接受', restart.body.ok === true);
  await sleep(1800);
  const afterHealth = (await get('/api/health')).body;
  check('重启后服务恢复正常', afterHealth.ok === true);
  const reLogin = await adminLogin();
  check('重启后可重新以管理员私钥登录', reLogin.body.ok === true);
  const finalChain = (await get('/api/admin/ledger/verify', reLogin.body.token)).body;
  check('重启后身份链仍完整', finalChain.ok === true, JSON.stringify(finalChain));

  [a, b, viaCode].forEach(c => c.close());
  console.log(`\n=== 结果: ${passed} 通过 / ${failed} 失败 ===\n`);
  process.exit(failed ? 1 : 0);
}

main().catch(err => {
  console.error('\n测试异常:', err.stack || err.message);
  process.exit(1);
});
