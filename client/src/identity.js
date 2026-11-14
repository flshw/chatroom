/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
(function (root) {
  'use strict';
  var C = root.ChatCrypto;
  var P = root.ChatProtocol;

  function xe(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
  }
  function cdata(s) { return '<![CDATA[' + String(s).replace(/]]>/g, ']]]]><![CDATA[>') + ']]>'; }
  function textOf(parent, tag) {
    var n = parent.getElementsByTagName(tag)[0];
    return n ? (n.textContent || '') : '';
  }
  function attrOf(parent, tag, name) {
    var n = parent.getElementsByTagName(tag)[0];
    return n ? (n.getAttribute(name) || '') : '';
  }

  /* Build the portable XML identity file. Private key NEVER leaves this file. */
  function build(doc, password) {
    var keysXml;
    var plainKeys = JSON.stringify({
      privateKeyPem: doc.privateKeyPem,
      publicKeyPem: doc.publicKeyPem
    });
    if (password) {
      var salt = C.b64(C.randomBytes(16));
      var key = C.deriveKey(password, salt);
      var enc = C.aesEncrypt(key, plainKeys, 'chatroom-identity-v3');
      keysXml = '<keys enc="password" salt="' + xe(salt) + '" iv="' + xe(enc.iv) +
        '" tag="' + xe(enc.tag) + '"><ciphertext>' + cdata(enc.ct) + '</ciphertext></keys>';
    } else {
      keysXml = '<keys enc="none">' +
        '<privateKey>' + cdata(doc.privateKeyPem) + '</privateKey>' +
        '<publicKey>' + cdata(doc.publicKeyPem) + '</publicKey></keys>';
    }
    var integrity = C.sha256Hex([
      doc.host, doc.port, doc.uid, doc.nickname, doc.publicKeyPem
    ].join('|'));
    return '<?xml version="1.0" encoding="UTF-8"?>\n' +
      '<ChatRoomIdentity version="' + P.IDENTITY_XML_VERSION + '">\n' +
      '  <server><host>' + xe(doc.host) + '</host><port>' + xe(doc.port) +
      '</port><fingerprint>' + xe(doc.fingerprint || '') + '</fingerprint></server>\n' +
      '  <user><uid>' + xe(doc.uid) + '</uid><nickname>' + xe(doc.nickname) +
      '</nickname><createdAt>' + xe(doc.createdAt || Date.now()) + '</createdAt></user>\n' +
      '  ' + keysXml + '\n' +
      '  <integrity algorithm="SHA-256">' + integrity + '</integrity>\n' +
      '</ChatRoomIdentity>\n';
  }

  /* Parse an identity file. Returns a plain object; throws on bad input. */
  function parse(xml, password) {
    var dom = new DOMParser().parseFromString(String(xml), 'application/xml');
    var err = dom.getElementsByTagName('parsererror')[0];
    if (err) throw new Error('XML 格式损坏');
    var r = dom.documentElement;
    if (!r || r.tagName !== 'ChatRoomIdentity') throw new Error('不是 ChatRoom 身份文件');
    if (r.getAttribute('version') !== String(P.IDENTITY_XML_VERSION)) {
      throw new Error('身份文件版本不兼容（需要 v' + P.IDENTITY_XML_VERSION + '）');
    }
    var server = r.getElementsByTagName('server')[0];
    var user = r.getElementsByTagName('user')[0];
    var keys = r.getElementsByTagName('keys')[0];
    if (!server || !user || !keys) throw new Error('身份文件字段缺失');

    var out = {
      host: textOf(server, 'host'),
      port: parseInt(textOf(server, 'port'), 10),
      fingerprint: textOf(server, 'fingerprint'),
      uid: textOf(user, 'uid'),
      nickname: textOf(user, 'nickname'),
      createdAt: Number(textOf(user, 'createdAt')) || 0,
      enc: keys.getAttribute('enc') || 'none',
      integrity: textOf(r, 'integrity')
    };

    if (out.enc === 'password') {
      if (!password) throw new Error('该身份文件已加密，请输入本地加密口令');
      /* salt/iv/tag are attributes on the keys element */
      var salt = keys.getAttribute('salt') || '';
      var iv = keys.getAttribute('iv') || '';
      var tag = keys.getAttribute('tag') || '';
      var ct = textOf(keys, 'ciphertext');
      try {
        var key = C.deriveKey(password, salt);
        var obj = JSON.parse(C.aesDecrypt(key, { iv: iv, ct: ct, tag: tag }, 'chatroom-identity-v3'));
        out.privateKeyPem = obj.privateKeyPem;
        out.publicKeyPem = obj.publicKeyPem;
      } catch (e) {
        throw new Error('口令错误或身份文件已损坏');
      }
    } else {
      out.privateKeyPem = textOf(keys, 'privateKey');
      out.publicKeyPem = textOf(keys, 'publicKey');
    }
    if (!out.uid || !out.privateKeyPem || !out.publicKeyPem) throw new Error('身份文件内容不完整');

    var check = C.sha256Hex([out.host, out.port, out.uid, out.nickname, out.publicKeyPem].join('|'));
    if (out.integrity && check !== out.integrity) throw new Error('身份文件完整性校验失败');
    try { C.privateKeyFromPem(out.privateKeyPem); C.publicKeyFromPem(out.publicKeyPem); }
    catch (e) { throw new Error('身份文件内的密钥无效'); }
    return out;
  }

  function filename(doc) {
    var safe = String(doc.nickname || 'user').replace(/[^\w\u4e00-\u9fa5-]/g, '_').slice(0, 16);
    return 'chatroom-identity-' + safe + '-' + String(doc.uid).slice(0, 8) + '.xml';
  }

  function download(xml, name) {
    var blob = new Blob([xml], { type: 'application/xml;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = name || 'chatroom-identity.xml';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 3000);
  }

  /* ---------- local identity vault (v4) ----------
   * Multiple identity files live in localStorage so mobile / desktop users can
   * switch accounts without hunting for downloaded XML files. Encrypted files
   * are stored as ciphertext; their password is never persisted. */
  var VAULT_KEY = P.IDENTITY_VAULT_KEY || 'chatroom-identity-vault-v4';

  function vaultList() {
    try {
      var arr = JSON.parse(root.localStorage.getItem(VAULT_KEY) || '[]');
      return Array.isArray(arr) ? arr : [];
    } catch (e) { return []; }
  }
  function vaultWrite(arr) {
    try { root.localStorage.setItem(VAULT_KEY, JSON.stringify(arr)); return true; }
    catch (e) { return false; }
  }
  function vaultSave(entry) {
    var arr = vaultList();
    var id = entry.id || ('v_' + C.sha256Hex(String(entry.xml)).slice(0, 12));
    var rec = {
      id: id,
      label: entry.label || entry.nickname || '未命名身份',
      host: entry.host || '', port: Number(entry.port) || 8080,
      uid: entry.uid || '', nickname: entry.nickname || '',
      xml: entry.xml, enc: entry.enc || 'none',
      createdAt: entry.createdAt || Date.now()
    };
    var idx = -1;
    for (var i = 0; i < arr.length; i++) {
      if (arr[i].id === id || (rec.uid && arr[i].uid === rec.uid)) { idx = i; break; }
    }
    if (idx >= 0) arr[idx] = Object.assign({}, arr[idx], rec, { id: arr[idx].id });
    else arr.push(rec);
    return vaultWrite(arr) ? rec : null;
  }
  function vaultRemove(id) {
    vaultWrite(vaultList().filter(function (x) { return x.id !== id; }));
  }
  function vaultRename(id, label) {
    var arr = vaultList();
    arr.forEach(function (x) { if (x.id === id) x.label = String(label).slice(0, 24); });
    vaultWrite(arr);
  }
  function vaultGet(id) {
    var arr = vaultList();
    for (var i = 0; i < arr.length; i++) if (arr[i].id === id) return arr[i];
    return null;
  }

  root.ChatIdentity = {
    build: build, parse: parse, download: download, filename: filename,
    vaultList: vaultList, vaultSave: vaultSave, vaultRemove: vaultRemove,
    vaultRename: vaultRename, vaultGet: vaultGet
  };
})(window);
