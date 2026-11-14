/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
(function (root) {
  'use strict';
  /* Two transports sharing one interface: WebSocket (direct) and HTTP relay (proxy).
   * Both deliver decrypted-of-nothing, still-encrypted envelopes to the app. */
  var P = root.ChatProtocol;

  function normalizeRelayUrl(input) {
    var base = String(input || '').trim().replace(/\/+$/, '');
    if (!/^https?:\/\//i.test(base)) base = 'http://' + base;
    if (/\/relay$/i.test(base)) return base;
    return base + '/relay';
  }

  function WsTransport(opts, handlers) {
    var url = 'ws://' + opts.host + ':' + opts.port + '/ws';
    var ws = new WebSocket(url);
    this.mode = 'ws';
    this.send = function (env) {
      if (ws.readyState === 1) ws.send(JSON.stringify(env));
    };
    this.close = function () { try { ws.close(); } catch (e) { /* noop */ } };
    ws.onopen = function () { handlers.onStatus('open'); };
    ws.onmessage = function (e) {
      try { handlers.onEnvelope(JSON.parse(e.data)); }
      catch (err) { handlers.onStatus('error'); }
    };
    ws.onerror = function () { handlers.onStatus('error'); };
    ws.onclose = function () { handlers.onStatus('closed'); };
  }

  function RelayTransport(opts, handlers) {
    var url = normalizeRelayUrl(opts.proxy);
    var clientId = 'c_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);
    var chain = Promise.resolve();
    var timer = null;
    var closed = false;
    this.mode = 'relay';

    function post(envelope) {
      chain = chain.then(function () {
        if (closed) return;
        return fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ clientId: clientId, envelope: envelope || null })
        }).then(function (r) {
          if (!r.ok) throw new Error('HTTP ' + r.status);
          return r.json();
        }).then(function (d) {
          (d.messages || []).forEach(handlers.onEnvelope);
        }).catch(function () { handlers.onStatus('error'); });
      });
      return chain;
    }

    this.send = function (env) { post(env); };
    this.close = function () { closed = true; if (timer) clearInterval(timer); };
    handlers.onStatus('open');
    post(null);
    timer = setInterval(function () { post(null); }, P.LIMITS.RELAY_POLL_MS);
  }

  root.ChatNet = {
    create: function (opts, handlers) {
      return opts.proxy
        ? new RelayTransport(opts, handlers)
        : new WsTransport(opts, handlers);
    }
  };
})(window);
