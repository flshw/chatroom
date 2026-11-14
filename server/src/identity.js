/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
'use strict';
/*
 * Persistent identities and access control.
 * The server stores ONLY public keys — a user's private key never leaves the
 * client's XML identity file. Every identity change is committed to the ledger.
 */
const forge = require('node-forge');
const C = require('./crypto');

function resumeCanonical(uid, ts, challenge) {
  return [uid, ts, challenge].join('|');
}

class IdentityStore {
  constructor(options) {
    this.db = options.db;
    this.ledger = options.ledger;
    this.log = options.logger || (() => {});
  }

  /* Create a brand-new (temporary or permanent) identity record. */
  register(rec) {
    const record = {
      uid: rec.uid,
      nickname: rec.nickname,
      pubkey: rec.pubkey,
      browserId: rec.browserId || null,
      createdAt: Date.now(),
      lastLogin: Date.now(),
      banned: false,
      muted: false,
      grants: [],
      permanent: !!rec.permanent
    };
    this.db.upsertIdentity(record);
    /* v5: the identity chain is a permanent record of FORMAL users only.
     * Temporary users still get a DB row (needed for online moderation),
     * bots keep their pool rows, but neither is written to the chain. */
    if (this._chainable(record)) {
      this.ledger.append('identity_register', {
        uid: record.uid,
        nickname: record.nickname,
        pubkeyFingerprint: C.fingerprint(record.pubkey),
        browserId: record.browserId,
        permanent: true
      });
    }
    return record;
  }

  /* A formal, human, permanent identity. Excludes temporary logins and bots. */
  _chainable(rec) {
    return !!rec && !!rec.permanent && !rec.isBot &&
      String(rec.uid || '').indexOf('bot_') !== 0;
  }

  /* Resume a permanent identity: proof = RSA-PSS signature over uid|ts|challenge,
   * made with the private key held in the client's XML file. */
  verifyResume(inner, challenge) {
    const resume = inner && inner.resume;
    if (!resume || typeof resume.uid !== 'string' || typeof resume.proof !== 'string') return null;
    const rec = this.db.getIdentity(resume.uid);
    if (!rec || !rec.permanent) return null;
    if (rec.banned) return { error: 'banned' };
    if (rec.pubkey !== inner.clientPub) return { error: 'pubkey_mismatch' };

    let pub;
    try { pub = forge.pki.publicKeyFromPem(rec.pubkey); }
    catch (e) { return { error: 'bad_key' }; }
    if (!C.verifyCanonical(pub, resumeCanonical(resume.uid, inner.ts, challenge), resume.proof)) {
      return { error: 'bad_proof' };
    }

    this.db.touchLogin(rec.uid);
    if (this._chainable(rec)) {
      this.ledger.append('identity_login', { uid: rec.uid, nickname: rec.nickname, ts: Date.now() });
    }
    return { uid: rec.uid, nickname: rec.nickname, record: rec, permanent: true };
  }

  get(uid) { return this.db.getIdentity(uid); }
  list() { return this.db.allIdentities(); }

  canLogin(uid) {
    const r = this.get(uid);
    return !r || !r.banned;
  }

  canSpeak(uid) {
    const r = this.get(uid);
    return !r || (!r.banned && !r.muted);
  }

  /* Empty grants = unrestricted. Lobby is always reachable. */
  canJoin(uid, roomId) {
    const r = this.get(uid);
    if (!r || r.banned) return false;
    if (roomId === require('./protocol').LOBBY_ID) return true;
    if (!Array.isArray(r.grants) || r.grants.length === 0) return true;
    return r.grants.indexOf('*') !== -1 || r.grants.indexOf(roomId) !== -1;
  }

  setFlag(uid, action, value) {
    const cur = this.get(uid);
    if (!cur) return null;
    const patch = {};
    switch (action) {
      case 'ban': patch.banned = true; break;
      case 'unban': patch.banned = false; break;
      case 'mute': patch.muted = true; break;
      case 'unmute': patch.muted = false; break;
      case 'grant': {
        const g = Array.isArray(cur.grants) ? cur.grants.slice() : [];
        const v = String(value || '').slice(0, 64);
        if (v && g.indexOf(v) === -1) g.push(v);
        patch.grants = g;
        break;
      }
      case 'revoke': {
        const v = String(value || '');
        patch.grants = (cur.grants || []).filter(x => x !== v);
        break;
      }
      case 'clearGrants': patch.grants = []; break;
      case 'nickname': patch.nickname = String(value || '').slice(0, 24) || cur.nickname; break;
      default: return null;
    }
    const next = this.db.updateIdentity(uid, patch);
    if (this._chainable(cur)) {
      this.ledger.append('identity_update', {
        uid, action, value: value === undefined ? null : String(value).slice(0, 64),
        banned: next.banned, muted: next.muted, grants: next.grants
      });
    }
    this.log(`身份管理 ${action} uid=${uid.slice(0, 12)}… value=${value || ''} 写链=${this._chainable(cur)}`);
    return next;
  }
}

module.exports = { IdentityStore, resumeCanonical };
