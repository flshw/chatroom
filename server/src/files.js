/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
'use strict';
/*
 * Encrypted file store. The client encrypts file bytes with the room session key
 * before upload, so the server only ever holds ciphertext. Only png/pdf/zip.
 * Ciphertext lives in data/files/<id>.json; metadata lives in SQLite.
 */
const fs = require('fs');
const path = require('path');
const P = require('./protocol');

const { FILES_DIR } = require('./paths');

function fail(code, message) {
  const e = new Error(message);
  e.code = code;
  throw e;
}

function sanitizeName(name) {
  return String(name || 'file')
    .replace(/[\\/\x00-\x1f<>:"|*?]/g, '_')
    .slice(0, 120);
}

class FileStore {
  constructor(options) {
    this.db = options.db;
    this.log = options.logger || (() => {});
    fs.mkdirSync(FILES_DIR, { recursive: true });
  }

  validate(fields) {
    const ext = String(fields.ext || '').toLowerCase().replace(/^\./, '');
    if (P.ALLOWED_FILE_EXTS.indexOf(ext) === -1) {
      fail(P.ERR.BAD_FILE_TYPE, '只允许 png / pdf / zip / 音频格式');
    }
    const size = Number(fields.size);
    if (!Number.isInteger(size) || size < 1 || size > P.LIMITS.MAX_FILE_BYTES) {
      fail(P.ERR.FILE_TOO_LARGE, '文件大小超出限制（最大 8 MB）');
    }
    if (typeof fields.iv !== 'string' || typeof fields.ct !== 'string' ||
        typeof fields.tag !== 'string' || typeof fields.aad !== 'string') {
      fail(P.ERR.BAD_ENVELOPE, '文件密文字段不完整');
    }
    if (fields.ct.length > P.LIMITS.MAX_HTTP_BODY_BYTES) {
      fail(P.ERR.FILE_TOO_LARGE, '密文体积超出限制');
    }
    return { ext, name: sanitizeName(fields.name) };
  }

  put(fields, meta) {
    const v = this.validate(fields);
    const id = 'f_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 8);
    const blob = { iv: fields.iv, ct: fields.ct, tag: fields.tag, aad: fields.aad };
    fs.writeFileSync(path.join(FILES_DIR, id + '.json'), JSON.stringify(blob));
    this.db.insertFile({
      id, room: String(meta.room), name: v.name, ext: v.ext, size: Number(fields.size),
      iv: fields.iv, ct: '', tag: '', aad: fields.aad,
      uploader: meta.uploader, uploaderName: meta.uploaderName,
      e2ee: !!meta.e2ee, ts: Date.now()
    });
    this.log(`文件已接收 ${v.name}.${v.ext} (${fields.size} B) 房间=${meta.room} 密文`);
    return { id, name: v.name, ext: v.ext, size: Number(fields.size) };
  }

  get(id) {
    const row = this.db.getFile(String(id || '').slice(0, 64));
    if (!row) return null;
    const file = path.join(FILES_DIR, row.id + '.json');
    if (!fs.existsSync(file)) return null;
    try {
      return Object.assign({}, row, JSON.parse(fs.readFileSync(file, 'utf8')));
    } catch (e) { return null; }
  }

  list(roomId) {
    return this.db.query(
      'SELECT id,room,name,ext,size,uploader,uploader_name,e2ee,ts FROM files WHERE room=? ORDER BY ts DESC',
      [roomId]
    );
  }

  deleteRoom(roomId) {
    for (const row of this.db.query('SELECT id FROM files WHERE room=?', [roomId])) {
      try { fs.unlinkSync(path.join(FILES_DIR, row.id + '.json')); } catch (e) { /* noop */ }
    }
    this.db.run('DELETE FROM files WHERE room=?', [roomId]);
  }
}

module.exports = { FileStore, FILES_DIR };
