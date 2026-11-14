/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
'use strict';
/*
 * Identity ledger — a single-node permissioned hash chain ("blockchain-style").
 * Each block commits to its predecessor and is signed with the server RSA key.
 * There is no PoW / consensus / P2P: on a LAN stand-alone server those add no
 * trust (the server is the only writer), while the hash chain + signature make
 * any later tampering with identity records detectable.
 */
const C = require('./crypto');

const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

function normalize(r) {
  return {
    idx: Number(r.idx),
    prevHash: r.prev_hash,
    ts: Number(r.ts),
    action: r.action,
    payload: r.payload,
    nonce: r.nonce,
    hash: r.hash,
    sig: r.sig
  };
}

class IdentityLedger {
  constructor(options) {
    this.db = options.db;
    this.keys = options.keys;
    this.log = options.logger || (() => {});
    this.ensureGenesis();
  }

  ensureGenesis() {
    if (this.db.blockCount() === 0) {
      this.append('genesis', {
        note: 'ChatRoom identity ledger · v5 仅持久化正式用户',
        version: 5, createdAt: Date.now()
      });
    }
  }

  append(action, payload) {
    const prev = this.db.lastBlock();
    const idx = prev ? Number(prev.idx) + 1 : 0;
    const prevHash = prev ? prev.hash : GENESIS_HASH;
    const ts = Date.now();
    const nonce = C.b64(C.randomBytes(8));
    const payloadStr = JSON.stringify(payload || {});
    const hash = C.sha256Hex([idx, prevHash, ts, action, payloadStr, nonce].join('|'));
    const sig = C.signCanonical(this.keys.privateKey, hash);
    const block = { idx, prevHash, ts, action, payload: payloadStr, nonce, hash, sig };
    this.db.appendBlock(block);
    this.log(`身份链 #${idx} [${action}] ${hash.slice(0, 12)}`);
    return block;
  }

  list() { return this.db.allBlocks().map(normalize); }

  head() {
    const b = this.db.lastBlock();
    return b ? normalize(b) : null;
  }

  verify() {
    const blocks = this.list();
    const fail = (i, reason) => ({ ok: false, blocks: blocks.length, brokenAt: i, reason });
    let expectedPrev = GENESIS_HASH;
    for (let i = 0; i < blocks.length; i++) {
      const b = blocks[i];
      if (b.idx !== i) return fail(i, '区块索引不连续');
      if (b.prevHash !== expectedPrev) return fail(i, '前驱哈希不匹配，链可能被插入或删除');
      const recomputed = C.sha256Hex(
        [b.idx, b.prevHash, b.ts, b.action, b.payload, b.nonce].join('|')
      );
      if (recomputed !== b.hash) return fail(i, '区块哈希不匹配，内容被篡改');
      if (!C.verifyCanonical(this.keys.publicKey, b.hash, b.sig)) {
        return fail(i, '服务器签名无效');
      }
      expectedPrev = b.hash;
    }
    return { ok: true, blocks: blocks.length, head: expectedPrev };
  }

  /* Wipe the entire hash chain and re-write the genesis block, signed with the
   * server key. Used by the deployment wizard / admin maintenance panel. */
  reset() {
    this.db.run('DELETE FROM ledger_blocks');
    this.db.flush();
    this.ensureGenesis();
    this.db.flush();
    this.log('身份链已重置并重新写入创世区块');
    return this.verify();
  }
}

module.exports = { IdentityLedger, GENESIS_HASH };
