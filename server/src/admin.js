/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
'use strict';
/*
 * Administrator authentication.
 * Two login modes: initial password (PBKDF2) and RSA-PSS challenge signature
 * with a dedicated administrator key pair whose private key is downloaded once.
 * Successful login yields a short-lived bearer token for /api/admin/* calls.
 */
const fs = require('fs');
const path = require('path');
const forge = require('node-forge');
const C = require('./crypto');
const P = require('./protocol');

const { DATA_DIR } = require('./paths');
const ADMIN_FILE = path.join(DATA_DIR, 'admin-keys.json');
const PBKDF2_ITER = 12000;

function derive(password, saltB64, iter) {
  return C.b64(forge.pkcs5.pbkdf2(
    String(password), C.unb64(saltB64), iter, 32, forge.md.sha256.create()
  ));
}

function randomPassword() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const bytes = C.randomBytes(16);
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += alphabet[bytes.charCodeAt(i) % alphabet.length];
  return out;
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

class AdminAuth {
  constructor(options) {
    this.log = options.logger || (() => {});
    this.tokens = new Map();
    this.challenges = new Map();
    this.data = this.loadOrCreate();
    this.publicKey = forge.pki.publicKeyFromPem(this.data.publicKeyPem);
    this.fingerprint = C.fingerprint(this.data.publicKeyPem);
  }

  loadOrCreate() {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    if (fs.existsSync(ADMIN_FILE)) {
      const stored = JSON.parse(fs.readFileSync(ADMIN_FILE, 'utf8'));
      this.log('管理员密钥已加载：' + ADMIN_FILE);
      return stored;
    }
    this.log('首次启动，正在生成管理员 RSA-2048 密钥对…');
    const kp = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
    const salt = C.b64(C.randomBytes(16));
    const password = randomPassword();
    const stored = {
      createdAt: new Date().toISOString(),
      publicKeyPem: forge.pki.publicKeyToPem(kp.publicKey),
      privateKeyPem: forge.pki.privateKeyToPem(kp.privateKey),
      passwordSalt: salt,
      passwordIter: PBKDF2_ITER,
      passwordHash: derive(password, salt, PBKDF2_ITER)
    };
    fs.writeFileSync(ADMIN_FILE, JSON.stringify(stored, null, 2), { mode: 0o600 });
    this.log('══════════════════════════════════════════════════════');
    this.log('  管理员初始口令: ' + password);
    this.log('  请用该口令登录 /admin，然后立即修改口令');
    this.log('  或下载管理员私钥，改用 RSA 非对称挑战签名登录');
    this.log('  私钥文件仅保存在服务端，请另行备份');
    this.log('══════════════════════════════════════════════════════');
    return stored;
  }

  challenge() {
    const challenge = C.b64(C.randomBytes(16));
    const ts = Date.now();
    this.challenges.set(challenge, ts);
    for (const [k, v] of this.challenges) {
      if (Date.now() - v > 120000) this.challenges.delete(k);
    }
    return {
      challenge, ts,
      pubKey: this.data.publicKeyPem,
      fingerprint: this.fingerprint,
      modes: ['password', 'signature']
    };
  }

  consume(challenge, ts) {
    if (!challenge || !this.challenges.has(challenge)) return false;
    this.challenges.delete(challenge);
    return Math.abs(Date.now() - Number(ts || 0)) < 120000;
  }

  loginPassword(password, challenge, ts) {
    if (!this.consume(challenge, ts)) throw new Error('挑战码无效或已过期');
    const hash = derive(password, this.data.passwordSalt, this.data.passwordIter);
    if (!safeEqual(hash, this.data.passwordHash)) throw new Error('管理员口令错误');
    return this.issue('password');
  }

  loginSignature(challenge, ts, sig) {
    if (!this.consume(challenge, ts)) throw new Error('挑战码无效或已过期');
    const canonical = ['admin', challenge, ts].join('|');
    if (!C.verifyCanonical(this.publicKey, canonical, sig)) throw new Error('管理员签名验证失败');
    return this.issue('signature');
  }

  issue(mode) {
    const token = C.b64(C.randomBytes(32)).replace(/[^A-Za-z0-9]/g, '').slice(0, 40);
    this.tokens.set(token, { expires: Date.now() + P.LIMITS.ADMIN_TOKEN_TTL_MS, mode });
    this.log('管理员登录成功（' + mode + '）');
    return token;
  }

  verify(token) {
    if (!token) return false;
    const rec = this.tokens.get(token);
    if (!rec) return false;
    if (rec.expires < Date.now()) { this.tokens.delete(token); return false; }
    return true;
  }

  logout(token) { this.tokens.delete(token); }

  setPassword(oldPassword, newPassword) {
    const hash = derive(oldPassword, this.data.passwordSalt, this.data.passwordIter);
    if (!safeEqual(hash, this.data.passwordHash)) throw new Error('原口令错误');
    if (String(newPassword).length < 8) throw new Error('新口令至少 8 位');
    const salt = C.b64(C.randomBytes(16));
    this.data.passwordSalt = salt;
    this.data.passwordHash = derive(newPassword, salt, this.data.passwordIter);
    fs.writeFileSync(ADMIN_FILE, JSON.stringify(this.data, null, 2), { mode: 0o600 });
    this.log('管理员口令已修改');
  }

  privateKeyPem() { return this.data.privateKeyPem; }
}

module.exports = { AdminAuth, ADMIN_FILE };
