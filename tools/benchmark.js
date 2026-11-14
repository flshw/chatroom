/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
'use strict';
/*
 * ChatRoom server capacity benchmark.
 *
 * Measures, against a running server:
 *   1. idle baseline RSS / heap
 *   2. per-connection + registration memory cost  (linear regression over N users)
 *   3. registration throughput and CPU cost      (RSA-OAEP + RSA-PSS handshake)
 *   4. per-archived-message memory cost          (sql.js grows in RAM)
 *   5. broadcast fan-out cost                   (lobby broadcast is O(N^2))
 *
 *   CHATROOM_BASE=http://127.0.0.1:8099 node tools/benchmark.js
 *   CHATROOM_BASE=... node tools/benchmark.js --users 150 --messages 300
 *
 * Recommended: point this at a DISPOSABLE instance started with its own
 * CHATROOM_DATA_DIR so the generated archive rows do not pollute production.
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
const argv = process.argv.slice(2);
const arg = (name, dflt) => {
  const i = argv.indexOf('--' + name);
  return i === -1 ? dflt : Number(argv[i + 1]) || dflt;
};
const USER_STEPS = [0, 25, 50, 100, 150, 200].filter(n => n <= arg('users', 150));
const MESSAGE_COUNT = arg('messages', 300);

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function metrics() {
  const r = await fetch(BASE + '/api/metrics');
  if (!r.ok) throw new Error('GET /api/metrics -> HTTP ' + r.status);
  return r.json();
}

/* Linear least squares: returns slope (bytes per unit) and R^2. */
function regress(points) {
  const n = points.length;
  if (n < 2) return { slope: 0, r2: 0 };
  const sx = points.reduce((a, p) => a + p[0], 0);
  const sy = points.reduce((a, p) => a + p[1], 0);
  const sxx = points.reduce((a, p) => a + p[0] * p[0], 0);
  const sxy = points.reduce((a, p) => a + p[0] * p[1], 0);
  const den = n * sxx - sx * sx;
  const slope = den ? (n * sxy - sx * sy) / den : 0;
  const mean = sy / n;
  const sst = points.reduce((a, p) => a + (p[1] - mean) ** 2, 0);
  const ssr = points.reduce((a, p) => a + (p[1] - (mean + slope * (p[0] - sx / n))) ** 2, 0);
  return { slope, r2: sst ? 1 - ssr / sst : 1 };
}

class BenchClient {
  constructor(index) {
    this.index = index;
    this.ws = null;
    this.inbox = [];
    this.waiters = [];
    this.uid = '';
    this.lobbyKey = null;
    this.room = P.LOBBY_ID;
    this.seq = 0;
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
        /* Keep only control-plane envelopes; broadcast traffic is discarded so
         * the benchmark driver's own memory does not distort the picture. */
        if (this.inbox.length > 40) this.inbox.shift();
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
  send(type, data) { if (this.ws && this.ws.readyState === 1) this.ws.send(JSON.stringify(P.makeEnvelope(type, data))); }
  wait(type, pred, ms) {
    const test = pred || (() => true);
    const match = e => e.type === type && test(e.data || {});
    const existing = this.inbox.find(match);
    if (existing) return Promise.resolve(existing);
    return new Promise((resolve, reject) => {
      const w = {
        pred: match, resolve,
        timer: setTimeout(() => {
          const i = this.waiters.indexOf(w);
          if (i >= 0) this.waiters.splice(i, 1);
          reject(new Error(`client#${this.index} 等待 ${type} 超时`));
        }, ms || 20000)
      };
      this.waiters.push(w);
    });
  }
  close() { try { this.ws.close(); } catch (e) { /* noop */ } }
}

let serverPubKey = null;
let clientPrivateKey = null;
let clientPublicPem = '';

async function register(cl) {
  cl.send(P.MSG.HELLO, {});
  const w = await cl.wait(P.MSG.WELCOME);
  if (!serverPubKey) serverPubKey = forge.pki.publicKeyFromPem(w.data.pubKey);
  const inner = {
    v: P.PROTOCOL_VERSION,
    username: 'bench_' + cl.index,
    browserId: 'bench_' + cl.index + '_' + nodeCrypto.randomBytes(6).toString('hex'),
    ts: Date.now(),
    nonce: C.b64(C.randomBytes(P.CRYPTO.NONCE_BYTES)),
    challenge: w.data.challenge,
    clientPub: clientPublicPem,
    sig: ''
  };
  inner.sig = C.signCanonical(clientPrivateKey, C.canonicalRegister(inner));
  const blob = C.hybridEncrypt(serverPubKey, JSON.stringify(inner));
  cl.send(P.MSG.REGISTER, { blob });
  const reg = await cl.wait(P.MSG.REGISTERED);
  cl.uid = reg.data.uid;
  cl.lobbyKey = C.unwrapKey(clientPrivateKey, reg.data.wrappedLobbyKey);
  cl.room = reg.data.room.id;
  return reg.data;
}

async function newClient(i) {
  const cl = new BenchClient(i);
  await cl.connect();
  await register(cl);
  return cl;
}

function sendText(cl, text) {
  const seq = ++cl.seq;
  const ts = Date.now();
  const aad = [cl.room, cl.uid, seq, ts].join('|');
  const enc = C.aesEncrypt(cl.lobbyKey, JSON.stringify({ text, kind: 'text' }), aad);
  cl.send(P.MSG.MESSAGE, { room: cl.room, seq, ts, iv: enc.iv, ct: enc.ct, tag: enc.tag });
}

async function main() {
  console.log('\n=== ChatRoom 服务端容量压测 ===');
  console.log('目标: ' + BASE);
  console.log('连接梯度: ' + USER_STEPS.join(', ') + ' 用户；归档消息样本: ' + MESSAGE_COUNT + ' 条\n');

  const base = await metrics();
  console.log(`基线: RSS ${base.memory.rssMB} MB / Heap ${base.memory.heapUsedMB} MB / 堆上限 ${base.memory.heapLimitMB} MB`);
  console.log(`运行时: Node ${base.node} ${base.platform}/${base.arch}  (进程 ${base.pid})\n`);

  /* One client key pair is reused: the server does not require globally unique
   * client public keys, and this isolates SERVER-side RSA cost from the
   * benchmark driver's own key generation time. */
  const kp = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  clientPrivateKey = kp.privateKey;
  clientPublicPem = forge.pki.publicKeyToPem(kp.publicKey);

  const clients = [];
  const samples = [];
  const regTimings = [];

  for (const target of USER_STEPS) {
    while (clients.length < target) {
      const t0 = Date.now();
      const cl = await newClient(clients.length + 1);
      regTimings.push(Date.now() - t0);
      clients.push(cl);
    }
    await sleep(350);            /* let V8 settle before sampling */
    const m = await metrics();
    samples.push({ users: target, rssBytes: m.memory.rssBytes, heapBytes: m.memory.heapUsedBytes,
      rssMB: m.memory.rssMB, heapMB: m.memory.heapUsedMB, clients: m.hub.clients });
    console.log(`  连接 ${String(target).padStart(3)}  RSS ${String(m.memory.rssMB).padStart(7)} MB  ` +
      `Heap ${String(m.memory.heapUsedMB).padStart(7)} MB  在线连接 ${m.hub.clients}`);
  }

  const fitRss = regress(samples.map(s => [s.users, s.rssBytes]));
  const fitHeap = regress(samples.map(s => [s.users, s.heapBytes]));
  const perUserRssKB = fitRss.slope / 1024;
  const perUserHeapKB = fitHeap.slope / 1024;

  const regCpuBefore = await metrics();
  const regBatch = [];
  const regT0 = Date.now();
  for (let i = 0; i < 30; i++) regBatch.push(await newClient(10000 + i));
  const regElapsed = Date.now() - regT0;
  const regCpuAfter = await metrics();
  const regCpuMs = Math.round(
    (regCpuAfter.cpu.userSec + regCpuAfter.cpu.systemSec -
     regCpuBefore.cpu.userSec - regCpuBefore.cpu.systemSec) * 1000
  );
  const perRegMs = regElapsed / regBatch.length;
  const perRegCpuMs = regCpuMs / regBatch.length;
  clients.push(...regBatch);

  /* ---- archive growth: sample repeatedly and fit a line, because a single
   * before/after RSS delta is easily distorted by V8 GC timing. ---- */
  const beforeArchive = await metrics();
  const archiveSamples = [[beforeArchive.hub.archive.messages, beforeArchive.memory.rssBytes]];
  const senders = clients.slice(0, Math.min(10, clients.length));
  const msgT0 = Date.now();
  const checkpointEvery = Math.max(1, Math.floor(MESSAGE_COUNT / 6));
  let sent = 0;
  while (sent < MESSAGE_COUNT) {
    for (const cl of senders) {
      if (sent >= MESSAGE_COUNT) break;
      sendText(cl, '压测消息 #' + sent + ' ' + nodeCrypto.randomBytes(12).toString('hex'));
      sent++;
      if (sent % checkpointEvery === 0) {
        await sleep(250);
        const m = await metrics();
        archiveSamples.push([m.hub.archive.messages, m.memory.rssBytes]);
      }
    }
    await sleep(45);             /* keep each session below 30 msg/s rate limit */
  }
  await sleep(900);
  const afterArchive = await metrics();
  archiveSamples.push([afterArchive.hub.archive.messages, afterArchive.memory.rssBytes]);
  const msgElapsed = Date.now() - msgT0;
  const archiveRows = afterArchive.hub.archive.messages - beforeArchive.hub.archive.messages;
  const archiveFit = regress(archiveSamples);
  const rssPerMessageKB = archiveFit.slope / 1024;

  /* ---- lobby broadcast fan-out (poll until the server persisted every frame) ---- */
  const fanBefore = await metrics();
  const fanClients = clients.slice(0, 100);
  const fanExpected = fanBefore.hub.archive.messages + fanClients.length;
  const fanT0 = Date.now();
  for (const cl of fanClients) sendText(cl, 'fanout');
  let fanElapsed = 0;
  let fanAfter = fanBefore;
  for (let i = 0; i < 60; i++) {
    await sleep(50);
    fanAfter = await metrics();
    if (fanAfter.hub.archive.messages >= fanExpected) { fanElapsed = Date.now() - fanT0; break; }
  }
  if (!fanElapsed) fanElapsed = Date.now() - fanT0;
  const fanFrames = fanClients.length * Math.max(1, clients.length - 1);
  const fanCpuMs = Math.round(
    (fanAfter.cpu.userSec + fanAfter.cpu.systemSec - fanBefore.cpu.userSec - fanBefore.cpu.systemSec) * 1000
  );

  /* ---- disconnect ---- */
  for (const cl of clients) cl.close();
  await sleep(1500);
  const afterDisconnect = await metrics();

  const totalUsers = clients.length;
  const report = {
    timestamp: new Date().toISOString(),
    target: BASE,
    runtime: { node: base.node, platform: base.platform, arch: base.arch,
      heapLimitMB: base.memory.heapLimitMB },
    baseline: { rssMB: base.memory.rssMB, heapUsedMB: base.memory.heapUsedMB,
      archiveMessages: base.hub.archive.messages },
    perUser: {
      rssKB: Math.round(perUserRssKB * 100) / 100,
      heapKB: Math.round(perUserHeapKB * 100) / 100,
      fitR2: Math.round(fitRss.r2 * 1000) / 1000,
      measurement: 'linear fit over ' + samples.map(s => s.users).join('/') + ' online users'
    },
    registration: {
      sample: 30, elapsedMs: regElapsed,
      perRegisterWallMs: Math.round(perRegMs * 100) / 100,
      perRegisterServerCpuMs: Math.round(perRegCpuMs * 100) / 100,
      registrationsPerSecSingleCore: Math.round(1000 / perRegCpuMs)
    },
    archive: {
      sent: MESSAGE_COUNT, persistedRows: archiveRows,
      rssKBPerMessage: Math.round(rssPerMessageKB * 1000) / 1000,
      fitR2: Math.round(archiveFit.r2 * 1000) / 1000,
      elapsedMs: msgElapsed,
      samples: archiveSamples.map(s => ({ rows: s[0], rssMB: Math.round(s[1] / 1048576 * 100) / 100 }))
    },
    broadcast: {
      onlineUsers: totalUsers, senderCount: fanClients.length,
      fanoutFrames: fanFrames, elapsedMs: fanElapsed,
      cpuMs: fanCpuMs, framesPerSec: fanElapsed > 0 ? Math.round(fanFrames / (fanElapsed / 1000)) : 0
    },
    afterDisconnect: { rssMB: afterDisconnect.memory.rssMB, heapUsedMB: afterDisconnect.memory.heapUsedMB },
    samples
  };

  const outDir = path.join(__dirname, '..', 'logs');
  fs.mkdirSync(outDir, { recursive: true });
  const outFile = path.join(outDir, 'benchmark-' + new Date().toISOString().slice(0, 10) + '.json');
  fs.writeFileSync(outFile, JSON.stringify(report, null, 2));

  console.log('\n=== 实测结果 ===');
  console.log(`每在线用户内存增量      RSS ${report.perUser.rssKB} KB / Heap ${report.perUser.heapKB} KB  (拟合 R²=${report.perUser.fitR2})`);
  console.log(`单次注册                墙钟 ${report.registration.perRegisterWallMs} ms / 服务端 CPU ${report.registration.perRegisterServerCpuMs} ms`);
  console.log(`单核注册吞吐上限        ${report.registration.registrationsPerSecSingleCore} 次/秒`);
  console.log(`每条归档消息内存增量    ${report.archive.rssKBPerMessage} KB  (落库 ${report.archive.persistedRows} 条)`);
  console.log(`大厅广播                ${report.broadcast.onlineUsers} 在线 / ${report.broadcast.fanoutFrames} 帧 / ${report.broadcast.elapsedMs} ms / CPU ${report.broadcast.cpuMs} ms`);
  console.log(`断开全部连接后          RSS ${report.afterDisconnect.rssMB} MB (基线 ${base.memory.rssMB} MB)`);
  console.log('\n报告已写入: ' + outFile + '\n');
}

main().catch(e => { console.error('压测失败:', e.stack || e.message); process.exit(1); });
