/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
'use strict';
/*
 * Cryptographic core, shared by the server process.
 * The browser client has an equivalent implementation in client/src/crypto.js.
 * All binary values crossing the wire are base64 strings.
 */
const forge = require('node-forge');
const fs = require('fs');
const path = require('path');
const P = require('./protocol');

const { DATA_DIR } = require('./paths');
const KEYS_FILE = path.join(DATA_DIR, 'keys.json');
const REG_AAD = 'chatroom-register-v1';
const ARCHIVE_AAD_PREFIX = 'chatroom-archive-v1|';

function oaepOptions() {
  return {
    md: forge.md.sha256.create(),
    mgf1: { md: forge.md.sha256.create() }
  };
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
  const md = forge.md.sha256.create();
  md.update(str, 'utf8');
  return md.digest().toHex();
}
function fingerprint(pem) { return sha256Hex(pem).slice(0, 16); }

function aesEncrypt(keyBytes, plaintext, aad) {
  const iv = randomBytes(P.CRYPTO.IV_BYTES);
  const cipher = forge.cipher.createCipher('AES-GCM', keyBytes);
  cipher.start({
    iv: iv,
    additionalData: aad || '',
    tagLength: P.CRYPTO.TAG_BYTES * 8
  });
  cipher.update(forge.util.createBuffer(forge.util.encodeUtf8(plaintext)));
  if (!cipher.finish()) throw new Error('AES-GCM encryption failed');
  return {
    iv: b64(iv),
    ct: b64(cipher.output.getBytes()),
    tag: b64(cipher.mode.tag.getBytes())
  };
}

function aesDecrypt(keyBytes, payload, aad) {
  const decipher = forge.cipher.createDecipher('AES-GCM', keyBytes);
  decipher.start({
    iv: unb64(payload.iv),
    additionalData: aad || '',
    tag: forge.util.createBuffer(unb64(payload.tag)),
    tagLength: P.CRYPTO.TAG_BYTES * 8
  });
  decipher.update(forge.util.createBuffer(unb64(payload.ct)));
  if (!decipher.finish()) throw new Error('AES-GCM authentication failed');
  return forge.util.decodeUtf8(decipher.output.getBytes());
}

function wrapKey(publicKey, keyBytes) {
  return b64(publicKey.encrypt(b64(keyBytes), 'RSA-OAEP', oaepOptions()));
}

function unwrapKey(privateKey, wrapped) {
  return unb64(privateKey.decrypt(unb64(wrapped), 'RSA-OAEP', oaepOptions()));
}

/* RSA alone cannot carry a registration packet (public key PEM + signature > 190 bytes),
 * so registrations use hybrid encryption: random AES key wrapped by the server RSA key. */
function hybridEncrypt(publicKey, plaintext) {
  const k = randomBytes(P.CRYPTO.AES_KEY_BYTES);
  return Object.assign({ wrappedKey: wrapKey(publicKey, k) }, aesEncrypt(k, plaintext, REG_AAD));
}

function hybridDecrypt(privateKey, blob) {
  const k = unwrapKey(privateKey, blob.wrappedKey);
  return aesDecrypt(k, blob, REG_AAD);
}

function signCanonical(privateKey, canonical) {
  const md = forge.md.sha256.create();
  md.update(canonical, 'utf8');
  return b64(privateKey.sign(md, pssOptions()));
}

function verifyCanonical(publicKey, canonical, sigB64) {
  try {
    const md = forge.md.sha256.create();
    md.update(canonical, 'utf8');
    return publicKey.verify(md.digest().getBytes(), unb64(sigB64), pssOptions());
  } catch (e) {
    return false;
  }
}

function canonicalRegister(inner) {
  return [inner.username, inner.browserId, inner.ts, inner.nonce, inner.challenge].join('|');
}

function makeUid(inner, salt) {
  return sha256Hex([inner.browserId, inner.ts, salt, inner.challenge].join('|'));
}

function archiveEncrypt(archiveKey, plaintext, room, seq, ts) {
  return aesEncrypt(archiveKey, plaintext, ARCHIVE_AAD_PREFIX + [room, seq, ts].join('|'));
}
function archiveDecrypt(archiveKey, row) {
  return aesDecrypt(archiveKey, row, ARCHIVE_AAD_PREFIX + [row.room, row.seq, row.ts].join('|'));
}

function loadOrCreateKeys(logger) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  let stored;
  if (fs.existsSync(KEYS_FILE)) {
    stored = JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8'));
    if (logger) logger('密钥文件已加载：' + KEYS_FILE);
  } else {
    if (logger) logger('首次启动，正在生成 RSA-2048 密钥对（约需数秒）...');
    const kp = forge.pki.rsa.generateKeyPair({ bits: P.CRYPTO.RSA_BITS, e: P.CRYPTO.RSA_EXPONENT });
    const pub = forge.pki.publicKeyToPem(kp.publicKey);
    const priv = forge.pki.privateKeyToPem(kp.privateKey);
    const archiveKey = randomBytes(P.CRYPTO.AES_KEY_BYTES);
    stored = {
      createdAt: new Date().toISOString(),
      publicKeyPem: pub,
      privateKeyPem: priv,
      wrappedArchiveKey: b64(kp.publicKey.encrypt(b64(archiveKey), 'RSA-OAEP', oaepOptions()))
    };
    stored.fingerprint = fingerprint(pub);
    fs.writeFileSync(KEYS_FILE, JSON.stringify(stored, null, 2), { mode: 0o600 });
    if (logger) logger('密钥对与归档主密钥已生成并封装保存');
  }

  const publicKey = forge.pki.publicKeyFromPem(stored.publicKeyPem);
  const privateKey = forge.pki.privateKeyFromPem(stored.privateKeyPem);
  const archiveKey = unb64(privateKey.decrypt(unb64(stored.wrappedArchiveKey), 'RSA-OAEP', oaepOptions()));
  if (archiveKey.length !== P.CRYPTO.AES_KEY_BYTES) {
    throw new Error('归档主密钥解封失败：长度异常');
  }
  return {
    publicKey: publicKey,
    privateKey: privateKey,
    publicKeyPem: stored.publicKeyPem,
    fingerprint: stored.fingerprint || fingerprint(stored.publicKeyPem),
    archiveKey: archiveKey,
    createdAt: stored.createdAt
  };
}

module.exports = {
  oaepOptions, pssOptions, randomBytes, b64, unb64, sha256Hex, fingerprint,
  aesEncrypt, aesDecrypt, wrapKey, unwrapKey,
  hybridEncrypt, hybridDecrypt,
  signCanonical, verifyCanonical, canonicalRegister, makeUid,
  archiveEncrypt, archiveDecrypt,
  loadOrCreateKeys,
  REG_AAD, ARCHIVE_AAD_PREFIX
};
