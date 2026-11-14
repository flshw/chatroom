/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
'use strict';
/*
 * Invite codes: CR1.<base64url( AES-256-GCM( JSON(payload) ) )>
 * Payload carries IP, port, inviter, room id/name/pin and an expiry.
 * The outer layer uses a shared passphrase so a client can read the IP/port
 * BEFORE it has connected to the server. An HMAC over the payload, keyed by the
 * server-only archive key, lets the server reject forged invites on join.
 */
const forge = require('node-forge');
const C = require('./crypto');
const P = require('./protocol');

function inviteKey() {
  const md = forge.md.sha256.create();
  md.update(P.INVITE_PASSPHRASE, 'utf8');
  return md.digest().getBytes();
}

function encode(str) { return Buffer.from(str, 'utf8').toString('base64url'); }
function decode(s) { return Buffer.from(s, 'base64url').toString('utf8'); }

function canonical(p) {
  return [p.v, p.host, p.port, p.roomId, p.pin, p.inviterUid,
    p.inviterName, p.roomName, p.private ? 1 : 0, p.ts, p.exp, p.nonce].join('|');
}

function computeMac(payload, secret) {
  const hmac = forge.hmac.create();
  hmac.start('sha256', secret);
  hmac.update(canonical(payload), 'utf8');
  return C.b64(hmac.digest().getBytes());
}

class InviteCodec {
  constructor(options) {
    this.secret = C.b64(options.archiveKey);
  }

  make(fields) {
    const ts = Date.now();
    const payload = {
      v: 3,
      host: String(fields.host || '127.0.0.1').slice(0, 64),
      port: Number(fields.port) || 8080,
      roomId: String(fields.roomId || '').slice(0, 64),
      roomName: String(fields.roomName || '').slice(0, 40),
      pin: String(fields.pin || '').slice(0, 16),
      inviterUid: String(fields.inviterUid || '').slice(0, 64),
      inviterName: String(fields.inviterName || '').slice(0, 24),
      private: !!fields.private,
      ts,
      exp: ts + (Number(fields.ttlMs) || P.LIMITS.INVITE_TTL_MS),
      nonce: C.b64(C.randomBytes(8))
    };
    payload.mac = computeMac(payload, this.secret);
    const enc = C.aesEncrypt(inviteKey(), JSON.stringify(payload), P.INVITE_AAD);
    return P.INVITE_PREFIX + encode(JSON.stringify(enc));
  }

  /* Decodes without verifying the server MAC — usable by the browser client. */
  parse(code) {
    try {
      if (typeof code !== 'string' || code.slice(0, P.INVITE_PREFIX.length) !== P.INVITE_PREFIX) return null;
      const enc = JSON.parse(decode(code.slice(P.INVITE_PREFIX.length)));
      const payload = JSON.parse(C.aesDecrypt(inviteKey(), enc, P.INVITE_AAD));
      if (!payload || payload.v !== 3 || !payload.roomId) return null;
      if (Number(payload.exp) < Date.now()) return null;
      return payload;
    } catch (e) { return null; }
  }

  /* Server-side authenticity check. */
  verify(payload) {
    if (!payload) return false;
    const expected = computeMac(payload, this.secret);
    if (typeof payload.mac !== 'string' || expected.length !== payload.mac.length) return false;
    let diff = 0;
    for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ payload.mac.charCodeAt(i);
    return diff === 0 && Number(payload.exp) >= Date.now();
  }
}

module.exports = { InviteCodec, inviteKey };
