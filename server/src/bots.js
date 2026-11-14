/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
'use strict';
/*
 * Bot pool v4.
 *
 * - 1000 bot identities are persisted in the same `identities` table (is_bot=1).
 * - Only 10-20 bots are online at any moment; a timer rotates them in/out.
 * - Bots hold NO private key: they live inside the server process, use the room
 *   session key directly to produce exactly the same AES-256-GCM ciphertext a
 *   real client would, and are pushed through Hub's normal message path so
 *   archiving / rate-limit / broadcasting all behave identically.
 * - Auto-reply observes plaintext ONLY in non-E2EE rooms (E2EE rooms are never
 *   hooked, so private chats remain unreadable to the server and its bots).
 */
const P = require('./protocol');
const C = require('./crypto');
const { Session } = require('./session');

const DEFAULTS = {
  enabled: true,
  poolSize: 1000,
  minOnline: 10,
  maxOnline: 20,
  refreshMs: 25000,
  autoReply: true,
  replyProbability: 0.6,
  ambientProbability: 0.35
};

const NAMES = [
  '小云', '阿泽', '星野', '南风', '柚子', '青山', '木木', '知夏', '北辰', '初晴',
  '栗子', '一诺', '清和', '子衿', '远山', '白露', '若水', '临风', '言午', '听澜',
  '半夏', '既明', '望舒', '思远', '安然', '拾光', '云舟', '景行', '澄澈', '松月',
  '朝雨', '未央', '青禾', '晚舟', '问渠', '如晦', '长风', '霁月', '折桂', '鹿鸣'
];

const REPLY_RULES = [
  { re: /你好|您好|hi|hello|大家好|来了|在吗/i, lines: ['你好呀，欢迎进来聊～', '嗨！正好在，聊点什么？', '欢迎欢迎，随便坐～'] },
  { re: /机器人|bot|自动|陪聊/i, lines: ['在呢，我是常驻机器人，有问题可以问我', '对，我是机器人，负责陪聊和暖场～'] },
  { re: /文件|附件|图片|截图|pdf|zip|下载/i, lines: ['文件我看到了，稍等我看一下', '收到，附件我这边也存一份～'] },
  { re: /\?|？|怎么|为什么|能否|可以吗|如何|求助/i, lines: ['这个我得想想…你先说说背景？', '好问题，我觉得可以分两步看', '我这边也没把握，要不大家一起捋一捋？'] },
  { re: /谢谢|感谢|辛苦|多谢/i, lines: ['不客气～', '举手之劳，有事再喊我'] },
  { re: /哈哈|笑|233|hhh|有趣/i, lines: ['哈哈哈，这个有意思', '笑死，继续说～'] }
];
const CHATTER = [
  '有道理', '+1', '这个点挺有意思', '嗯嗯，我在听', '记下了，回头再聊',
  '要不要展开说说？', '同感，刚才也想到这个', '先这样，我消化一下',
  '好嘞', '继续呀，我跟着看', '我这边也差不多是这么想的'
];
const AMBIENT = [
  '刚进来，有人在线吗？', '下午好呀，随便聊聊～', '这个房间挺安静的',
  '有人试过发文件吗？', '我在，随时可以搭话', '刚看完消息，跟上一下'
];

function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function shuffle(arr) {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    const t = a[i]; a[i] = a[j]; a[j] = t;
  }
  return a;
}
function replyFor(text) {
  const s = String(text || '');
  for (const rule of REPLY_RULES) if (rule.re.test(s)) return pick(rule.lines);
  return pick(CHATTER);
}
function clamp(v, lo, hi, dflt) {
  const n = Number(v);
  return Number.isFinite(n) ? Math.max(lo, Math.min(hi, Math.round(n))) : dflt;
}

class BotSession extends Session {
  constructor(uid) {
    super('bot');
    this.uid = uid;
    this.authenticated = true;   /* bots skip registration; they are local to the Hub */
  }
  send() { /* bots do not consume server pushes */ }
  close() {}
  get isOpen() { return true; }
}

class BotManager {
  constructor(options) {
    this.hub = options.hub;
    this.db = options.db;
    this.keys = options.keys;
    this.ledger = options.ledger;
    this.log = options.logger || (() => {});
    this.online = new Map();
    this.timer = null;
    this.disposed = false;
    this.lastRefresh = 0;
    this.cfg = Object.assign({}, DEFAULTS, this.readConfig());
    this.ensurePool(this.cfg.poolSize);
  }

  readConfig() {
    try {
      const raw = this.db.getMeta('bots');
      return raw ? JSON.parse(raw) : {};
    } catch (e) { return {}; }
  }

  /* Create the persistent identity pool. One ledger block summarises the whole
   * batch — writing one signed block per bot would cost ~29 ms x 1000. */
  ensurePool(n) {
    const have = new Set(this.db.botIdentities().map(r => r.uid));
    let added = 0;
    const now = Date.now();
    for (let i = 1; i <= n; i++) {
      const uid = 'bot_' + String(i).padStart(4, '0');
      if (have.has(uid)) continue;
      this.db.insertBot({
        uid,
        nickname: NAMES[(i - 1) % NAMES.length] + String(i).padStart(3, '0'),
        pubkey: this.keys.publicKeyPem,  /* valid PEM placeholder; bots hold no private key */
        createdAt: now + i
      });
      added++;
    }
    if (added > 0) {
      this.ledger.append('bot_pool_init', { poolSize: n, added, ts: now });
      this.log(`机器人身份池初始化：新增 ${added} 条，共 ${n} 条`);
    }
    return this.db.countBots();
  }

  start() {
    this.hub.registerMessageHook(info => this.onMessage(info));
    this.restartTimer();
    this.refresh();
    this.log(`机器人系统已启动：池 ${this.cfg.poolSize}，在线 ${this.cfg.minOnline}~${this.cfg.maxOnline}，自动回复=${this.cfg.autoReply}`);
    return this;
  }

  restartTimer() {
    if (this.timer) clearInterval(this.timer);
    this.timer = setInterval(() => this.refresh(), this.cfg.refreshMs);
    if (this.timer.unref) this.timer.unref();
  }

  dispose() {
    this.disposed = true;
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    for (const uid of Array.from(this.online.keys())) this.despawn(uid);
  }

  /* ---------- online rotation ---------- */

  refresh() {
    if (this.disposed) return;
    if (!this.cfg.enabled) { this.despawnAll(); return; }
    const pool = this.db.botIdentities().filter(r => !r.banned && !r.muted);
    const target = this.cfg.maxOnline > this.cfg.minOnline
      ? this.cfg.minOnline + Math.floor(Math.random() * (this.cfg.maxOnline - this.cfg.minOnline + 1))
      : this.cfg.minOnline;
    const wanted = Math.min(target, pool.length);

    /* rotate ~40% of the current bots so the roster feels alive */
    const current = shuffle(Array.from(this.online.keys()));
    const rotate = Math.floor(this.online.size * 0.4);
    for (const uid of current.slice(0, rotate)) this.despawn(uid);

    for (const rec of shuffle(pool)) {
      if (this.online.size >= wanted) break;
      if (this.online.has(rec.uid)) continue;
      this.spawn(rec);
    }
    this.lastRefresh = Date.now();

    if (this.cfg.autoReply && this.online.size > 0 && Math.random() < this.cfg.ambientProbability) {
      const bot = pick(Array.from(this.online.values()));
      const roomId = bot.rooms[Math.floor(Math.random() * bot.rooms.length)];
      setTimeout(() => {
        if (!this.disposed && this.online.has(bot.uid)) this.speak(roomId, bot.uid, pick(AMBIENT));
      }, 500 + Math.random() * 1500);
    }
    return this.stats();
  }

  spawn(rec) {
    if (this.online.has(rec.uid)) return;
    const session = new BotSession(rec.uid);
    session.username = rec.nickname;
    session.clientPubPem = rec.pubkey;
    const user = {
      uid: rec.uid, username: rec.nickname, clientPubPem: rec.pubkey, session,
      rooms: new Set(), lastSeq: new Map(), joinedAt: Date.now(),
      permanent: true, isBot: true
    };
    const publicRooms = Array.from(this.hub.rooms.values())
      .filter(r => !r.e2ee && r.members.size < this.hub.config.maxMembersPerRoom);
    const roomIds = [P.LOBBY_ID];
    const extras = publicRooms.filter(r => r.id !== P.LOBBY_ID);
    if (extras.length && Math.random() < 0.5) roomIds.push(pick(extras).id);
    this.hub.attachBotUser(user, roomIds);
    this.online.set(rec.uid, {
      uid: rec.uid, nickname: rec.nickname, rooms: Array.from(user.rooms)
    });
  }

  despawn(uid) {
    this.hub.detachBotUser(uid);
    this.online.delete(uid);
  }

  despawnAll() {
    for (const uid of Array.from(this.online.keys())) this.despawn(uid);
  }

  /* ---------- speaking ---------- */

  speak(roomId, uid, text) {
    const room = this.hub.rooms.get(roomId);
    const user = this.hub.users.get(uid);
    if (!room || !user || !user.isBot || room.e2ee || !room.key || !user.rooms.has(roomId)) return false;
    try {
      const seq = (user.lastSeq.get(roomId) || 0) + 1;
      const ts = Date.now();
      const aad = [roomId, uid, seq, ts].join('|');
      const enc = C.aesEncrypt(room.key, JSON.stringify({ text: String(text).slice(0, 4000), kind: 'text' }), aad);
      this.hub.handleEnvelope(user.session, P.makeEnvelope(P.MSG.MESSAGE, {
        room: roomId, seq, ts, iv: enc.iv, ct: enc.ct, tag: enc.tag
      }));
      return true;
    } catch (e) {
      this.log(`机器人发言失败: ${e.message}`);
      return false;
    }
  }

  onMessage(info) {
    if (this.disposed || !this.cfg.enabled || !this.cfg.autoReply || info.isBot) return;
    if (Math.random() > this.cfg.replyProbability) return;
    const candidates = Array.from(this.online.values())
      .filter(b => b.rooms.indexOf(info.room.id) !== -1);
    if (!candidates.length) return;
    const bot = pick(candidates);
    const reply = replyFor(info.text);
    const roomId = info.room.id;
    setTimeout(() => {
      if (this.disposed || !this.online.has(bot.uid) || !this.hub.users.has(bot.uid)) return;
      this.speak(roomId, bot.uid, reply);
    }, 700 + Math.random() * 1900);
  }

  /* ---------- admin ---------- */

  configure(patch) {
    const c = Object.assign({}, this.cfg);
    if (Object.prototype.hasOwnProperty.call(patch, 'enabled')) c.enabled = !!patch.enabled;
    if (Object.prototype.hasOwnProperty.call(patch, 'autoReply')) c.autoReply = !!patch.autoReply;
    if (patch.poolSize !== undefined) c.poolSize = clamp(patch.poolSize, 0, 5000, c.poolSize);
    if (patch.minOnline !== undefined) c.minOnline = clamp(patch.minOnline, 0, 200, c.minOnline);
    if (patch.maxOnline !== undefined) c.maxOnline = clamp(patch.maxOnline, 0, 200, c.maxOnline);
    if (patch.refreshMs !== undefined) c.refreshMs = clamp(patch.refreshMs, 5000, 600000, c.refreshMs);
    if (patch.replyProbability !== undefined) {
      c.replyProbability = Math.max(0, Math.min(1, Number(patch.replyProbability)));
      if (!Number.isFinite(c.replyProbability)) c.replyProbability = DEFAULTS.replyProbability;
    }
    c.maxOnline = Math.max(c.minOnline, Math.min(c.maxOnline, 200));
    c.minOnline = Math.min(c.minOnline, c.poolSize);
    c.maxOnline = Math.min(c.maxOnline, c.poolSize);
    this.cfg = c;
    this.db.setMeta('bots', JSON.stringify(c));
    this.ledger.append('bot_config', Object.assign({ ts: Date.now() }, c));

    if (c.poolSize > this.db.countBots()) this.ensurePool(c.poolSize);
    else if (c.poolSize < this.db.countBots()) {
      /* prune from OFFLINE bots first, then take down online ones */
      const all = this.db.botIdentities();
      const keep = new Set(all.slice(0, c.poolSize).map(r => r.uid));
      for (const b of Array.from(this.online.values())) {
        if (!keep.has(b.uid)) this.despawn(b.uid);
      }
      for (const r of all) {
        if (!keep.has(r.uid)) this.db.run('DELETE FROM identities WHERE uid=?', [r.uid]);
      }
    }
    this.restartTimer();
    this.refresh();
    this.log(`机器人配置已更新: ${JSON.stringify(c)}`);
    return this.stats();
  }

  stats() {
    return {
      enabled: this.cfg.enabled,
      poolSize: this.cfg.poolSize,
      records: this.db.countBots(),
      online: this.online.size,
      minOnline: this.cfg.minOnline,
      maxOnline: this.cfg.maxOnline,
      refreshMs: this.cfg.refreshMs,
      autoReply: this.cfg.autoReply,
      replyProbability: this.cfg.replyProbability,
      ambientProbability: this.cfg.ambientProbability,
      lastRefresh: this.lastRefresh,
      bots: Array.from(this.online.values())
    };
  }
}

module.exports = { BotManager, DEFAULTS, replyFor };
