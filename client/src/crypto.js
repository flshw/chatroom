/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
(function (root) {
  'use strict';
  /* Browser-side cryptographic core. Mirrors server/src/crypto.js exactly. */
  var forge = root.forge;
  var P = root.ChatProtocol;

  function oaepOptions() {
    return { md: forge.md.sha256.create(), mgf1: { md: forge.md.sha256.create() } };
  }
  function pssOptions() {
    return forge.pss.create({
      md: forge.md.sha256.create(),
      mgf: forge.mgf.mgf1.create(forge.md.sha256.create()),
      saltLength: 32
    });
  }
  function randomBytes(n) { return forge.random.getBytesSync(n); }
  function b64(bytes) { return forge.util.encode64(bytes); }
  function unb64(str) { return forge.util.decode64(str); }
  function sha256Hex(str) {
    var md = forge.md.sha256.create();
    md.update(str, 'utf8');
    return md.digest().toHex();
  }
  function aesEncrypt(keyBytes, plaintext, aad) {
    var iv = randomBytes(P.CRYPTO.IV_BYTES);
    var cipher = forge.cipher.createCipher('AES-GCM', keyBytes);
    cipher.start({ iv: iv, additionalData: aad || '', tagLength: P.CRYPTO.TAG_BYTES * 8 });
    cipher.update(forge.util.createBuffer(forge.util.encodeUtf8(plaintext)));
    if (!cipher.finish()) throw new Error('AES-GCM 加密失败');
    return { iv: b64(iv), ct: b64(cipher.output.getBytes()), tag: b64(cipher.mode.tag.getBytes()) };
  }
  function aesDecrypt(keyBytes, payload, aad) {
    var decipher = forge.cipher.createDecipher('AES-GCM', keyBytes);
    decipher.start({
      iv: unb64(payload.iv), additionalData: aad || '',
      tag: forge.util.createBuffer(unb64(payload.tag)),
      tagLength: P.CRYPTO.TAG_BYTES * 8
    });
    decipher.update(forge.util.createBuffer(unb64(payload.ct)));
    if (!decipher.finish()) throw new Error('AES-GCM 校验失败');
    return forge.util.decodeUtf8(decipher.output.getBytes());
  }
  function unwrapKey(privateKey, wrapped) {
    return unb64(privateKey.decrypt(unb64(wrapped), 'RSA-OAEP', oaepOptions()));
  }
  function hybridEncrypt(serverPubPem, plaintext) {
    var pub = forge.pki.publicKeyFromPem(serverPubPem);
    var k = randomBytes(P.CRYPTO.AES_KEY_BYTES);
    var wrappedKey = b64(pub.encrypt(b64(k), 'RSA-OAEP', oaepOptions()));
    var enc = aesEncrypt(k, plaintext, 'chatroom-register-v1');
    enc.wrappedKey = wrappedKey;
    return enc;
  }
  function generateKeyPair() {
    return forge.pki.rsa.generateKeyPair({ bits: P.CRYPTO.RSA_BITS, e: P.CRYPTO.RSA_EXPONENT });
  }
  function publicKeyPem(keyPair) { return forge.pki.publicKeyToPem(keyPair.publicKey); }
  function signCanonical(privateKey, canonical) {
    var md = forge.md.sha256.create();
    md.update(canonical, 'utf8');
    return b64(privateKey.sign(md, pssOptions()));
  }
  function canonicalRegister(inner) {
    return [inner.username, inner.browserId, inner.ts, inner.nonce, inner.challenge].join('|');
  }
  function messageAad(room, uid, seq, ts) { return [room, uid, seq, ts].join('|'); }
  /* v5: lobby direct messages use their own AAD namespace so a public-room
   * ciphertext can never be replayed as a direct message and vice versa. */
  function directAad(room, uid, seq, ts) {
    return ['dm', room, uid, seq, ts].join('|');
  }

  /* Browser ID: stable within one tab session, combined with a fresh timestamp
   * on every login so the server always issues a brand new identity. */
  function browserId() {
    var parts = [];
    try {
      parts.push(navigator.userAgent, screen.width + 'x' + screen.height,
        screen.colorDepth, navigator.language, String(new Date().getTimezoneOffset()),
        String(navigator.hardwareConcurrency || 0), navigator.platform || '');
      var c = document.createElement('canvas');
      var ctx = c.getContext('2d');
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillText('ChatRoom-fingerprint-9f3a', 2, 2);
      parts.push(c.toDataURL().slice(-100));
      var gl = document.createElement('canvas').getContext('webgl');
      if (gl) parts.push(gl.getParameter(gl.VENDOR), gl.getParameter(gl.RENDERER));
    } catch (e) { parts.push('fp-fallback'); }
    var salt;
    try {
      salt = sessionStorage.getItem('cr_salt');
      if (!salt) { salt = b64(randomBytes(16)); sessionStorage.setItem('cr_salt', salt); }
    } catch (e) { salt = b64(randomBytes(16)); }
    parts.push(salt);
    return 'fp_' + sha256Hex(parts.join('|')).slice(0, 32);
  }

  /* ---- v3 additions: binary file encryption, key import/export, invites, KDF ---- */

  function privateKeyPem(keyPair) { return forge.pki.privateKeyToPem(keyPair.privateKey); }
  function privateKeyFromPem(pem) { return forge.pki.privateKeyFromPem(pem); }
  function publicKeyFromPem(pem) { return forge.pki.publicKeyFromPem(pem); }

  /* Wrap an AES room key for a specific member's public key (client-side E2EE). */
  function wrapKeyFor(publicKeyPem, keyBytes) {
    return b64(publicKeyFromPem(publicKeyPem).encrypt(b64(keyBytes), 'RSA-OAEP', oaepOptions()));
  }

  /* Bytes are forge "binary strings" (one char = one byte), not UTF-8 text. */
  function aesEncryptBytes(keyBytes, bytes, aad) {
    var iv = randomBytes(P.CRYPTO.IV_BYTES);
    var cipher = forge.cipher.createCipher('AES-GCM', keyBytes);
    cipher.start({ iv: iv, additionalData: aad || '', tagLength: P.CRYPTO.TAG_BYTES * 8 });
    cipher.update(forge.util.createBuffer(bytes));
    if (!cipher.finish()) throw new Error('文件加密失败');
    return { iv: b64(iv), ct: b64(cipher.output.getBytes()), tag: b64(cipher.mode.tag.getBytes()) };
  }
  function aesDecryptBytes(keyBytes, payload, aad) {
    var decipher = forge.cipher.createDecipher('AES-GCM', keyBytes);
    decipher.start({
      iv: unb64(payload.iv), additionalData: aad || '',
      tag: forge.util.createBuffer(unb64(payload.tag)),
      tagLength: P.CRYPTO.TAG_BYTES * 8
    });
    decipher.update(forge.util.createBuffer(unb64(payload.ct)));
    if (!decipher.finish()) throw new Error('文件校验失败');
    return decipher.output.getBytes();
  }

  function deriveKey(password, saltB64) {
    return forge.pkcs5.pbkdf2(String(password), unb64(saltB64), 12000, 32, forge.md.sha256.create());
  }

  function inviteKey() {
    var md = forge.md.sha256.create();
    md.update(P.INVITE_PASSPHRASE, 'utf8');
    return md.digest().getBytes();
  }
  function b64urlDecode(s) {
    var b = String(s).replace(/-/g, '+').replace(/_/g, '/');
    while (b.length % 4) b += '=';
    return forge.util.decodeUtf8(atob(b));
  }
  /* Invite outer layer is decryptable offline, so the client can learn the
   * server IP/port before connecting. Authenticity is checked by the server. */
  function inviteDecrypt(code) {
    try {
      if (typeof code !== 'string' || code.slice(0, P.INVITE_PREFIX.length) !== P.INVITE_PREFIX) return null;
      var enc = JSON.parse(b64urlDecode(code.slice(P.INVITE_PREFIX.length)));
      var payload = JSON.parse(aesDecrypt(inviteKey(), enc, P.INVITE_AAD));
      if (!payload || payload.v !== 3 || !payload.roomId) return null;
      return payload;
    } catch (e) { return null; }
  }

  function resumeCanonical(uid, ts, challenge) { return [uid, ts, challenge].join('|'); }

  root.ChatCrypto = {
    randomBytes: randomBytes, b64: b64, unb64: unb64, sha256Hex: sha256Hex,
    aesEncrypt: aesEncrypt, aesDecrypt: aesDecrypt,
    aesEncryptBytes: aesEncryptBytes, aesDecryptBytes: aesDecryptBytes,
    hybridEncrypt: hybridEncrypt, unwrapKey: unwrapKey, wrapKeyFor: wrapKeyFor,
    generateKeyPair: generateKeyPair, publicKeyPem: publicKeyPem,
    privateKeyPem: privateKeyPem,
    privateKeyFromPem: privateKeyFromPem, publicKeyFromPem: publicKeyFromPem,
    deriveKey: deriveKey, inviteDecrypt: inviteDecrypt,
    resumeCanonical: resumeCanonical,
    signCanonical: signCanonical, canonicalRegister: canonicalRegister,
    messageAad: messageAad, directAad: directAad, browserId: browserId
  };
})(window);
