/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
'use strict';
/*
 * Embedded micro database: SQLite via sql.js (WASM, no native build).
 * The in-memory database is exported to a single file after changes (debounced).
 * Every message body stored here is already encrypted with the archive master key,
 * except E2EE private-chat rows whose ciphertext the server cannot decrypt.
 * v3 adds identities, the hash-chained ledger, file metadata and admin metadata.
 */
const fs = require('fs');
const path = require('path');
const initSqlJs = require('sql.js');

const { DATA_DIR } = require('./paths');
const DB_FILE = path.join(DATA_DIR, 'chat.db');

const SCHEMA = `
CREATE TABLE IF NOT EXISTS rooms (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, private INTEGER NOT NULL DEFAULT 0,
  invite TEXT, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  room TEXT NOT NULL, from_uid TEXT NOT NULL, from_name TEXT NOT NULL,
  seq INTEGER NOT NULL, iv TEXT NOT NULL, ct TEXT NOT NULL, tag TEXT NOT NULL,
  aad TEXT NOT NULL, ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room, id DESC);
CREATE TABLE IF NOT EXISTS server_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS identities (
  uid TEXT PRIMARY KEY, nickname TEXT NOT NULL, pubkey TEXT NOT NULL,
  browser_id TEXT, created_at INTEGER NOT NULL, last_login INTEGER,
  banned INTEGER NOT NULL DEFAULT 0, muted INTEGER NOT NULL DEFAULT 0,
  grants TEXT NOT NULL DEFAULT '[]', permanent INTEGER NOT NULL DEFAULT 0,
  is_bot INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ledger_blocks (
  idx INTEGER PRIMARY KEY, prev_hash TEXT NOT NULL, ts INTEGER NOT NULL,
  action TEXT NOT NULL, payload TEXT NOT NULL, nonce TEXT NOT NULL,
  hash TEXT NOT NULL, sig TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS files (
  id TEXT PRIMARY KEY, room TEXT NOT NULL, name TEXT NOT NULL, ext TEXT NOT NULL,
  size INTEGER NOT NULL, iv TEXT NOT NULL, ct TEXT NOT NULL, tag TEXT NOT NULL,
  aad TEXT NOT NULL, uploader TEXT NOT NULL, uploader_name TEXT NOT NULL,
  e2ee INTEGER NOT NULL DEFAULT 0, ts INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS admin_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
`;

/* Additive migrations for databases created by v2. */
const MIGRATIONS = [
  'ALTER TABLE rooms ADD COLUMN e2ee INTEGER NOT NULL DEFAULT 0',
  'ALTER TABLE rooms ADD COLUMN pin TEXT',
  'ALTER TABLE messages ADD COLUMN e2ee INTEGER NOT NULL DEFAULT 0',
  'ALTER TABLE identities ADD COLUMN is_bot INTEGER NOT NULL DEFAULT 0'
];

class Database {
  constructor() {
    this.db = null;
    this.flushTimer = null;
    this.dirty = false;
  }

  async init() {
    const SQL = await initSqlJs();
    fs.mkdirSync(DATA_DIR, { recursive: true });
    if (fs.existsSync(DB_FILE)) {
      this.db = new SQL.Database(fs.readFileSync(DB_FILE));
    } else {
      this.db = new SQL.Database();
    }
    this.db.run(SCHEMA);
    for (const sql of MIGRATIONS) {
      try { this.db.run(sql); } catch (e) { /* column already exists */ }
    }
    return this;
  }

  markDirty() {
    this.dirty = true;
    if (this.flushTimer) clearTimeout(this.flushTimer);
    this.flushTimer = setTimeout(() => this.flush(), 400);
  }

  flush() {
    if (!this.db || !this.dirty) return;
    const bytes = Buffer.from(this.db.export());
    const tmp = DB_FILE + '.tmp';
    fs.writeFileSync(tmp, bytes);
    fs.renameSync(tmp, DB_FILE);
    this.dirty = false;
  }

  /* ---------- generic helpers ---------- */

  run(sql, params) { this.db.run(sql, params || []); this.markDirty(); }

  query(sql, params) {
    const stmt = this.db.prepare(sql);
    const rows = [];
    try {
      if (params && params.length) stmt.bind(params);
      while (stmt.step()) rows.push(stmt.getAsObject());
    } finally { stmt.free(); }
    return rows;
  }

  scalar(sql) {
    const r = this.db.exec(sql);
    return r.length && r[0].values.length ? r[0].values[0][0] : 0;
  }

  /* ---------- rooms ---------- */

  upsertRoom(room) {
    this.run(
      'INSERT OR REPLACE INTO rooms(id,name,private,invite,created_at,e2ee,pin) VALUES(?,?,?,?,?,?,?)',
      [room.id, room.name, room.private ? 1 : 0, room.invite || null, room.createdAt,
       room.e2ee ? 1 : 0, room.pin || null]
    );
  }

  deleteRoom(roomId) {
    this.run('DELETE FROM rooms WHERE id=?', [roomId]);
    this.run('DELETE FROM messages WHERE room=?', [roomId]);
    this.run('DELETE FROM files WHERE room=?', [roomId]);
  }

  /* ---------- messages ---------- */

  insertArchived(row) {
    this.run(
      'INSERT INTO messages(room,from_uid,from_name,seq,iv,ct,tag,aad,ts,e2ee) VALUES(?,?,?,?,?,?,?,?,?,?)',
      [row.room, row.fromUid, row.fromName, row.seq, row.iv, row.ct, row.tag, row.aad, row.ts,
       row.e2ee ? 1 : 0]
    );
  }

  getHistory(room, limit) {
    const n = Math.max(1, Math.min(200, Number(limit) || 50));
    return this.query(
      'SELECT room,from_uid,from_name,seq,iv,ct,tag,aad,ts,e2ee FROM messages WHERE room=? ORDER BY id DESC LIMIT ?',
      [room, n]
    ).reverse();
  }

  getArchivedRooms() {
    const res = this.db.exec(
      'SELECT r.id, r.name, r.private, r.created_at, r.e2ee, COUNT(m.id) AS cnt FROM rooms r LEFT JOIN messages m ON m.room=r.id GROUP BY r.id ORDER BY r.created_at DESC'
    );
    if (!res.length) return [];
    const cols = res[0].columns;
    return res[0].values.map(v => {
      const o = {};
      cols.forEach((c, i) => { o[c] = v[i]; });
      return o;
    });
  }

  /* ---------- identities ---------- */

  upsertIdentity(rec) {
    this.run(
      `INSERT INTO identities(uid,nickname,pubkey,browser_id,created_at,last_login,banned,muted,grants,permanent,is_bot)
       VALUES(?,?,?,?,?,?,?,?,?,?,?)
       ON CONFLICT(uid) DO UPDATE SET nickname=excluded.nickname, pubkey=excluded.pubkey,
         browser_id=excluded.browser_id, last_login=excluded.last_login,
         banned=excluded.banned, muted=excluded.muted, grants=excluded.grants,
         permanent=excluded.permanent, is_bot=excluded.is_bot`,
      [rec.uid, rec.nickname, rec.pubkey, rec.browserId || null, rec.createdAt,
       rec.lastLogin || rec.createdAt, rec.banned ? 1 : 0, rec.muted ? 1 : 0,
       JSON.stringify(rec.grants || []), rec.permanent ? 1 : 0, rec.isBot ? 1 : 0]
    );
  }

  /* Bot pool: one INSERT OR IGNORE per record, no ledger block per bot. */
  insertBot(rec) {
    this.run(
      `INSERT OR IGNORE INTO identities
       (uid,nickname,pubkey,browser_id,created_at,last_login,banned,muted,grants,permanent,is_bot)
       VALUES(?,?,?,?,?,?,0,0,'[]',1,1)`,
      [rec.uid, rec.nickname, rec.pubkey, 'bot-pool', rec.createdAt, rec.createdAt]
    );
  }

  countBots() { return this.scalar('SELECT COUNT(*) FROM identities WHERE is_bot=1'); }
  botIdentities() {
    return this.query('SELECT * FROM identities WHERE is_bot=1 ORDER BY uid ASC').map(normalizeIdentity);
  }

  updateIdentity(uid, patch) {
    const cur = this.getIdentity(uid);
    if (!cur) return null;
    const next = Object.assign({}, cur, patch);
    this.upsertIdentity(next);
    return this.getIdentity(uid);
  }

  getIdentity(uid) {
    const r = this.query('SELECT * FROM identities WHERE uid=?', [uid]);
    return r.length ? normalizeIdentity(r[0]) : null;
  }

  allIdentities() {
    return this.query('SELECT * FROM identities ORDER BY created_at DESC').map(normalizeIdentity);
  }

  touchLogin(uid) {
    this.run('UPDATE identities SET last_login=? WHERE uid=?', [Date.now(), uid]);
  }

  /* ---------- ledger ---------- */

  lastBlock() {
    const r = this.query('SELECT * FROM ledger_blocks ORDER BY idx DESC LIMIT 1');
    return r.length ? r[0] : null;
  }

  appendBlock(b) {
    this.run(
      'INSERT INTO ledger_blocks(idx,prev_hash,ts,action,payload,nonce,hash,sig) VALUES(?,?,?,?,?,?,?,?)',
      [b.idx, b.prevHash, b.ts, b.action, b.payload, b.nonce, b.hash, b.sig]
    );
  }

  allBlocks() { return this.query('SELECT * FROM ledger_blocks ORDER BY idx ASC'); }
  blockCount() { return this.scalar('SELECT COUNT(*) FROM ledger_blocks'); }

  /* ---------- files ---------- */

  insertFile(f) {
    this.run(
      'INSERT OR REPLACE INTO files(id,room,name,ext,size,iv,ct,tag,aad,uploader,uploader_name,e2ee,ts) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
      [f.id, f.room, f.name, f.ext, f.size, f.iv, f.ct, f.tag, f.aad,
       f.uploader, f.uploaderName, f.e2ee ? 1 : 0, f.ts]
    );
  }

  getFile(id) {
    const r = this.query('SELECT * FROM files WHERE id=?', [id]);
    return r.length ? r[0] : null;
  }

  /* ---------- admin meta ---------- */

  getMeta(k) {
    const r = this.query('SELECT v FROM admin_meta WHERE k=?', [k]);
    return r.length ? r[0].v : null;
  }

  setMeta(k, v) {
    this.run('INSERT OR REPLACE INTO admin_meta(k,v) VALUES(?,?)', [k, String(v)]);
  }

  /* ---------- lifecycle ---------- */

  counts() {
    return {
      messages: this.scalar('SELECT COUNT(*) FROM messages'),
      rooms: this.scalar('SELECT COUNT(*) FROM rooms'),
      identities: this.scalar('SELECT COUNT(*) FROM identities'),
      blocks: this.scalar('SELECT COUNT(*) FROM ledger_blocks'),
      files: this.scalar('SELECT COUNT(*) FROM files')
    };
  }

  close() {
    if (this.flushTimer) clearTimeout(this.flushTimer);
    this.flush();
    if (this.db) this.db.close();
    this.db = null;
  }
}

function normalizeIdentity(r) {
  let grants = [];
  try { grants = JSON.parse(r.grants || '[]'); } catch (e) { grants = []; }
  return {
    uid: r.uid, nickname: r.nickname, pubkey: r.pubkey, browserId: r.browser_id,
    createdAt: r.created_at, lastLogin: r.last_login,
    banned: !!r.banned, muted: !!r.muted, grants: grants, permanent: !!r.permanent,
    isBot: !!r.is_bot
  };
}

module.exports = { Database, DB_FILE, DATA_DIR };
