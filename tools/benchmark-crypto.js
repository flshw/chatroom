/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
'use strict';
/*
 * Crypto primitive micro-benchmark: node-forge (pure JS) vs node:crypto (OpenSSL).
 * The registration handshake cost dominates our CPU budget, so this quantifies
 * how much capacity a drop-in native-crypto optimisation would recover.
 *   node tools/benchmark-crypto.js
 */
const nc = require('crypto');
const forge = require('../server/node_modules/node-forge');
const C = require('../server/src/crypto');

const N_RSA = 40;
const N_AES = 1500;
const PAYLOAD = Buffer.alloc(8192, 0x5a);

function bench(label, fn, rounds) {
  fn(); /* warm-up / JIT */
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < rounds; i++) fn();
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  console.log(`  ${label.padEnd(34)} ${(ms / rounds).toFixed(3)} ms/op   (${rounds} 次共 ${ms.toFixed(0)} ms)`);
  return ms / rounds;
}

function main() {
  console.log('\n=== 加密原语微基准：forge (纯 JS) vs node:crypto (OpenSSL) ===');
  console.log(`平台: Node ${process.version} ${process.platform}/${process.arch}\n`);

  const forgeKp = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const pubPem = forge.pki.publicKeyToPem(forgeKp.publicKey);
  const privPem = forge.pki.privateKeyToPem(forgeKp.privateKey);
  const message = 'alice|fp_bench|1763100000000|nonce|challenge';
  const aesKey = C.randomBytes(32);
  const keyText = C.b64(aesKey);

  console.log('RSA-2048 私钥解密 (OAEP-SHA256)');
  const forgeWrapped = forgeKp.publicKey.encrypt(keyText, 'RSA-OAEP', C.oaepOptions());
  const nativeWrapped = nc.publicEncrypt({
    key: pubPem, padding: nc.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256'
  }, Buffer.from(keyText, 'binary'));
  const forgeDec = bench('node-forge privateKey.decrypt', () => {
    forgeKp.privateKey.decrypt(forgeWrapped, 'RSA-OAEP', C.oaepOptions());
  }, N_RSA);
  const nativeDec = bench('node:crypto privateDecrypt', () => {
    nc.privateDecrypt({
      key: privPem, padding: nc.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256'
    }, nativeWrapped);
  }, N_RSA);

  console.log('\nRSA-PSS 签名 / 验签 (SHA-256, salt 32)');
  const forgeSig = forgeKp.privateKey.sign(
    (() => { const md = forge.md.sha256.create(); md.update(message, 'utf8'); return md; })(),
    C.pssOptions()
  );
  const nativeSig = nc.sign('sha256', Buffer.from(message, 'utf8'), {
    key: privPem, padding: nc.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32
  });
  const forgeVerify = bench('node-forge publicKey.verify', () => {
    const md = forge.md.sha256.create(); md.update(message, 'utf8');
    forgeKp.publicKey.verify(md.digest().getBytes(), forgeSig, C.pssOptions());
  }, N_RSA);
  const nativeVerify = bench('node:crypto verify', () => {
    nc.verify('sha256', Buffer.from(message, 'utf8'), {
      key: pubPem, padding: nc.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32
    }, nativeSig);
  }, N_RSA);

  console.log('\nAES-256-GCM 8 KB 加密');
  const forgeAes = bench('node-forge AES-GCM', () => {
    C.aesEncrypt(aesKey, 'x'.repeat(8192), 'aad');
  }, N_AES);
  const nativeAes = bench('node:crypto AES-GCM', () => {
    const iv = nc.randomBytes(12);
    const c = nc.createCipheriv('aes-256-gcm', Buffer.from(aesKey, 'binary'), iv);
    c.setAAD(Buffer.from('aad'));
    c.update(PAYLOAD);
    c.final();
    c.getAuthTag();
  }, N_AES);

  const handshakeForge = forgeDec + forgeVerify;
  const handshakeNative = nativeDec + nativeVerify;
  console.log('\n=== 单次注册的服务端 RSA 开销（解密 + 验签，不含 AES/DB） ===');
  console.log(`  node-forge : ${handshakeForge.toFixed(2)} ms  → 单核约 ${Math.round(1000 / handshakeForge)} 次注册/秒`);
  console.log(`  node:crypto: ${handshakeNative.toFixed(2)} ms  → 单核约 ${Math.round(1000 / handshakeNative)} 次注册/秒`);
  console.log(`  加速比     : ${(handshakeForge / handshakeNative).toFixed(1)}×`);
  console.log(`  AES-GCM    : forge ${forgeAes.toFixed(3)} ms vs native ${nativeAes.toFixed(3)} ms (${(forgeAes / nativeAes).toFixed(1)}×)`);
  console.log('\n结论: 握手瓶颈来自纯 JS 大数运算，换用 OpenSSL 原生实现即可大幅提升，无需改写整体架构。\n');
}

main();
