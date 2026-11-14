/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
'use strict';
const P = require('./protocol');

let counter = 0;

class Session {
  constructor(kind) {
    this.kind = kind;
    this.id = 's_' + (++counter).toString(36) + '_' + Date.now().toString(36);
    this.uid = null;
    this.username = null;
    this.clientPubPem = null;
    this.pending = null;
    this.authenticated = false;
    this.lastSeen = Date.now();
    this.windowStart = Date.now();
    this.messageCount = 0;
  }
  touch() { this.lastSeen = Date.now(); }
  send() { throw new Error('Session.send must be implemented'); }
  close() {}
  get isOpen() { return true; }
  error(code, message) {
    this.send(P.makeEnvelope(P.MSG.ERROR, { code: code, message: message || '' }));
  }
  notice(text) {
    this.send(P.makeEnvelope(P.MSG.NOTICE, { text: text, ts: Date.now() }));
  }
}

class WsSession extends Session {
  constructor(ws) {
    super('ws');
    this.ws = ws;
  }
  send(env) {
    if (this.ws.readyState === 1) {
      try { this.ws.send(JSON.stringify(env)); } catch (e) { /* connection gone */ }
    }
  }
  get isOpen() { return this.ws.readyState === 1; }
  close() { try { this.ws.close(); } catch (e) { /* noop */ } }
}

class RelaySession extends Session {
  constructor(clientId) {
    super('relay');
    this.clientId = clientId;
    this.queue = [];
  }
  send(env) {
    this.queue.push(env);
    if (this.queue.length > 500) this.queue.shift();
  }
  drain() {
    const out = this.queue;
    this.queue = [];
    return out;
  }
  get isOpen() { return Date.now() - this.lastSeen < P.LIMITS.RELAY_IDLE_MS; }
  close() { this.queue.length = 0; }
}

module.exports = { Session, WsSession, RelaySession };
