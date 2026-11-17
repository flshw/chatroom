/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
'use strict';
/*
 * Guestbook module: anonymous visitor messages with admin replies.
 *
 * Design notes:
 *  - No login required to post or read. Replies are public to everyone.
 *  - The raw visitor IP is NEVER stored. A one-way salted digest (rotated daily)
 *    is kept in memory only, purely for per-IP rate limiting.
 *  - All text is stored as plain text and MUST be HTML-escaped by every client
 *    before rendering. We also strip control characters server-side.
 *  - `contact` is intentionally omitted from the public list — it is visible
 *    only to the administrator, so anonymous visitors can leave a way to be
 *    reached without publishing it to the whole site.
 */
const nodeCrypto = require('crypto');

const MAX_NICKNAME = 24;
const MAX_CONTENT = 1200;
const MAX_CONTACT = 120;
const MAX_REPLY = 1200;
const RATE_WINDOW_MS = 15 * 1000;   // at most 1 post per IP per 15s
const MAX_BUCKET = 4096;

function clean(text, max) {
  let s = String(text == null ? '' : text);
  // Reject control characters (incl. NUL, newlines are collapsed to spaces).
  s = s.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim();
  if (s.length > max) s = s.slice(0, max);
  return s;
}

class Guestbook {
  constructor(options) {
    const opts = options || {};
    this.db = opts.db;
    this.logger = opts.logger || function () {};
    // A stable per-process secret for the rate-limit digest. Never persisted,
    // never exposed — it only needs to be consistent within one process life.
    this._secret = opts.secret || nodeCrypto.randomBytes(24).toString('hex');
    this._buckets = new Map();   // ipHash -> last post timestamp
    this._daySalt = this._todaySalt();
    this._day = new Date().toISOString().slice(0, 10);
  }

  _todaySalt() {
    return nodeCrypto.createHash('sha256')
      .update(this._secret + '|' + new Date().toISOString().slice(0, 10))
      .digest('hex');
  }

  _hashIp(ip) {
    if (!ip) return null;
    if (new Date().toISOString().slice(0, 10) !== this._day) {
      this._day = new Date().toISOString().slice(0, 10);
      this._daySalt = this._todaySalt();
      this._buckets.clear();
    }
    return nodeCrypto.createHash('sha256').update(this._daySalt + '|' + ip).digest('hex');
  }

  /* Rate limit per IP. Returns remaining wait in seconds, or 0 when allowed. */
  _rateWait(ipHash) {
    if (!ipHash) return 0;
    const now = Date.now();
    const last = this._buckets.get(ipHash) || 0;
    const wait = Math.ceil((last + RATE_WINDOW_MS - now) / 1000);
    if (wait > 0) return wait;
    if (this._buckets.size > MAX_BUCKET) this._buckets.clear();
    this._buckets.set(ipHash, now);
    return 0;
  }

  /* ---- public ---- */

  submit(body, ip) {
    const nickname = clean(body.nickname, MAX_NICKNAME) || '匿名用户';
    const content = clean(body.content, MAX_CONTENT);
    const contact = clean(body.contact, MAX_CONTACT);
    if (!content) return { ok: false, error: '留言内容不能为空' };
    const ipHash = this._hashIp(ip);
    const wait = this._rateWait(ipHash);
    if (wait > 0) return { ok: false, error: '提交太频繁，请 ' + wait + ' 秒后再试', retryAfter: wait };
    const id = this.db.insertGuestbook({
      nickname, content, contact, ts: Date.now(), ipHash, visible: 1
    });
    this.logger('留言板：收到匿名留言 #' + id);
    return { ok: true, id, ts: Date.now() };
  }

  list(limit) {
    return this.db.listGuestbook(limit, false).map(row => ({
      id: row.id, nickname: row.nickname, content: row.content,
      reply: row.reply || '', replyAt: row.reply_at || 0, ts: row.ts
    }));
  }

  stats() {
    return { total: this.db.countGuestbook() };
  }

  /* ---- admin ---- */

  adminList(limit) {
    return this.db.listGuestbook(limit, true).map(row => ({
      id: row.id, nickname: row.nickname, content: row.content,
      contact: row.contact || '', reply: row.reply || '',
      replyAt: row.reply_at || 0, ts: row.ts, visible: !!row.visible
    }));
  }

  reply(id, text) {
    const reply = clean(text, MAX_REPLY);
    if (!reply) return { ok: false, error: '回复内容不能为空' };
    const row = this.db.replyGuestbook(Number(id) || 0, reply);
    if (!row) return { ok: false, error: '留言不存在' };
    this.logger('留言板：管理员回复了 #' + id);
    return { ok: true, entry: this._adminRow(row) };
  }

  setVisible(id, visible) {
    const row = this.db.setGuestbookVisible(Number(id) || 0, !!visible);
    if (!row) return { ok: false, error: '留言不存在' };
    return { ok: true, entry: row };
  }

  remove(id) {
    this.db.deleteGuestbook(Number(id) || 0);
    this.logger('留言板：删除了 #' + id);
    return { ok: true };
  }

  _adminRow(row) {
    return {
      id: row.id, nickname: row.nickname, content: row.content,
      contact: row.contact || '', reply: row.reply || '',
      replyAt: row.reply_at || 0, ts: row.ts, visible: !!row.visible
    };
  }
}

module.exports = { Guestbook, MAX_CONTENT, MAX_REPLY };
