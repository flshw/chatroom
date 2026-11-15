/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
'use strict';
/*
 * Verifies that the BROWSER crypto implementation (client/src/crypto.js +
 * vendor/forge.min.js) is wire-compatible with the SERVER implementation,
 * and that every inlined <script> in the built single-file HTML parses.
 *
 *   node tools/verify-crypto-interop.js
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.resolve(__dirname, '..');
const forgeBrowserCode = fs.readFileSync(path.join(ROOT, 'vendor', 'forge.min.js'), 'utf8');
const P = require(path.join(ROOT, 'shared', 'protocol.js'));
const serverC = require(path.join(ROOT, 'server', 'src', 'crypto.js'));
const forgeServer = require(path.join(ROOT, 'server', 'node_modules', 'node-forge'));
const nodeCrypto = require('crypto');

let passed = 0, failed = 0;
function check(name, ok, detail) {
  if (ok) { passed++; console.log('  PASS  ' + name); }
  else { failed++; console.log('  FAIL  ' + name + (detail ? ' -> ' + detail : '')); }
}

/* Minimal browser-like sandbox for the client crypto module. */
/* A tiny XML parser so the identity-file module can be exercised in Node. */
class FakeEl {
  constructor(tag) { this.tagName = tag; this.attrs = {}; this.children = []; this._text = ''; }
  getAttribute(n) { return Object.prototype.hasOwnProperty.call(this.attrs, n) ? this.attrs[n] : ''; }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
  getElementsByTagName(tag) {
    let out = [];
    for (const c of this.children) {
      if (c.tagName === tag) out.push(c);
      out = out.concat(c.getElementsByTagName(tag));
    }
    return out;
  }
}
function fakeXml(src) {
  const root = new FakeEl('#root');
  const stack = [root];
  const re = /<(\/?)([A-Za-z_][\w-]*)([^>]*?)(\/?)>|<!\[CDATA\[([\s\S]*?)\]\]>|([^<]+)/g;
  let m;
  while ((m = re.exec(src)) !== null) {
    if (m[5] !== undefined) { stack[stack.length - 1]._text += m[5]; continue; }
    if (m[6] !== undefined) { stack[stack.length - 1]._text += m[6].replace(/^\s*\?xml[^>]*\?>\s*/, ''); continue; }
    if (m[1] === '/') { if (stack.length > 1) stack.pop(); continue; }
    const el = new FakeEl(m[2]);
    const ar = /([A-Za-z_][\w-]*)="([^"]*)"/g;
    let a;
    while ((a = ar.exec(m[3])) !== null) el.attrs[a[1]] = a[2];
    stack[stack.length - 1].children.push(el);
    if (!m[4]) stack.push(el);
  }
  const doc = root.children[0] || root;
  return {
    documentElement: doc,
    getElementsByTagName: tag => root.getElementsByTagName(tag)
  };
}

const sandbox = {
  ChatProtocol: P,
  atob: s => Buffer.from(s, 'base64').toString('binary'),
  btoa: s => Buffer.from(s, 'binary').toString('base64'),
  DOMParser: function () { this.parseFromString = src => fakeXml(src); },
  crypto: { getRandomValues: arr => nodeCrypto.randomFillSync(arr) },
  navigator: { userAgent: 'smoke', language: 'zh-CN', hardwareConcurrency: 8, platform: 'Win32' },
  screen: { width: 1920, height: 1080, colorDepth: 24 },
  sessionStorage: { getItem: () => null, setItem: () => {} },
  localStorage: (() => {
    const mem = {};
    return {
      getItem: k => Object.prototype.hasOwnProperty.call(mem, k) ? mem[k] : null,
      setItem: (k, v) => { mem[k] = String(v); },
      removeItem: k => { delete mem[k]; }
    };
  })(),
  document: {
    createElement: () => ({
      getContext: () => ({
        textBaseline: '', font: '', fillText: () => {},
        getParameter: () => 'mock-gl', VENDOR: 1, RENDERER: 2
      }),
      toDataURL: () => 'data:image/png;base64,mock'
    })
  },
  console, Date, Math, JSON
};
sandbox.window = sandbox;
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
/* forge.min.js is a browser UMD bundle: it assigns to window.forge. */
vm.runInContext(forgeBrowserCode, sandbox);
const forgeBrowser = sandbox.forge;
vm.runInContext(fs.readFileSync(path.join(ROOT, 'client', 'src', 'crypto.js'), 'utf8'), sandbox);
const clientC = sandbox.ChatCrypto;
vm.runInContext(fs.readFileSync(path.join(ROOT, 'client', 'src', 'identity.js'), 'utf8'), sandbox);
const clientID = sandbox.ChatIdentity;

function run() {
  console.log('\n=== 浏览器端 / 服务端 加密互通验证 ===\n');

  check('vendor/forge.min.js 提供 PSS', typeof forgeBrowser.pss.create === 'function');
  check('vendor/forge.min.js 提供 AES-GCM',
    typeof forgeBrowser.cipher.createCipher === 'function');
  check('vendor/forge.min.js 提供 UTF-8 编解码',
    typeof forgeBrowser.util.encodeUtf8 === 'function' && typeof forgeBrowser.util.decodeUtf8 === 'function');
  check('客户端加密模块已挂载', !!clientC && typeof clientC.hybridEncrypt === 'function');

  /* Server key pair, as if issued at first startup. */
  const serverKp = forgeServer.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const serverPubPem = forgeServer.pki.publicKeyToPem(serverKp.publicKey);

  /* 1. Browser hybrid-encrypts a registration packet, server decrypts it. */
  const inner = {
    v: 1, username: '浏览器用户', browserId: 'fp_browser_01',
    ts: Date.now(), nonce: 'bm9uY2U=', challenge: 'Y2hhbGxlbmdl', clientPub: 'PEM', sig: ''
  };
  const blob = clientC.hybridEncrypt(serverPubPem, JSON.stringify(inner));
  check('注册包含 wrappedKey/iv/ct/tag 四字段',
    !!(blob.wrappedKey && blob.iv && blob.ct && blob.tag), JSON.stringify(Object.keys(blob)));
  let recovered;
  try { recovered = JSON.parse(serverC.hybridDecrypt(serverKp.privateKey, blob)); }
  catch (e) { recovered = null; }
  check('浏览器 RSA-OAEP + AES-GCM 注册包可被服务端解封',
    !!recovered && recovered.username === '浏览器用户' && recovered.browserId === inner.browserId);

  /* 2. Browser signs, server verifies (RSA-PSS/SHA-256). */
  const clientKp = clientC.generateKeyPair();
  const canonical = clientC.canonicalRegister(inner);
  const sig = clientC.signCanonical(clientKp.privateKey, canonical);
  const clientPubPem = clientC.publicKeyPem(clientKp);
  check('浏览器 RSA-PSS 签名可被服务端验证',
    serverC.verifyCanonical(forgeServer.pki.publicKeyFromPem(clientPubPem), canonical, sig) === true);
  check('篡改后的签名被拒绝',
    serverC.verifyCanonical(forgeServer.pki.publicKeyFromPem(clientPubPem), canonical + 'x', sig) === false);

  /* 3. Server wraps a room key with the browser public key; browser unwraps. */
  const roomKey = serverC.randomBytes(32);
  const wrapped = serverC.wrapKey(forgeServer.pki.publicKeyFromPem(clientPubPem), roomKey);
  const unwrapped = clientC.unwrapKey(clientKp.privateKey, wrapped);
  check('服务端封装的会话密钥可被浏览器私钥解封',
    unwrapped.length === 32 && unwrapped === roomKey);

  /* 4. AES-256-GCM interoperability in both directions, including Chinese text. */
  const aad = 'r_abc|hexuid|7|' + Date.now();
  const text = '中文消息 🔒 test 123';
  const encByClient = clientC.aesEncrypt(roomKey, JSON.stringify({ text }), aad);
  const decByServer = JSON.parse(serverC.aesDecrypt(roomKey, encByClient, aad));
  check('浏览器加密的消息可被服务端解密', decByServer.text === text, decByServer.text);
  const encByServer = serverC.aesEncrypt(roomKey, JSON.stringify({ text }), aad);
  const decByClient = JSON.parse(clientC.aesDecrypt(roomKey, encByServer, aad));
  check('服务端加密的消息可被浏览器解密', decByClient.text === text, decByClient.text);
  let tamperRejected = false;
  try { clientC.aesDecrypt(roomKey, Object.assign({}, encByServer, { tag: encByClient.tag }), aad); }
  catch (e) { tamperRejected = true; }
  check('GCM 认证标签可检测篡改', tamperRejected);

  /* 5. Archive key round-trip (server-only). */
  const archiveKey = serverC.randomBytes(32);
  const arc = serverC.archiveEncrypt(archiveKey, JSON.stringify({ text }), 'r_abc', 1, 12345);
  const arcPlain = JSON.parse(serverC.archiveDecrypt(archiveKey,
    Object.assign({ room: 'r_abc', seq: 1, ts: 12345 }, arc)));
  check('归档主密钥加解密往返正确', arcPlain.text === text);

  /* 6. Browser ID shape. */
  const bid = clientC.browserId();
  check('浏览器 ID 形如 fp_ + 32 hex', /^fp_[0-9a-f]{32}$/.test(bid), bid);

  /* 7. v3: binary file encryption, key wrapping, invite codes, identity XML. */
  const fileKey = nodeCrypto.randomBytes(32).toString('binary');
  const binary = '\x89PNG\r\n\x1a\n' + '\x00\xff\x01\x7f' + 'payload-bytes';
  const encBytes = clientC.aesEncryptBytes(fileKey, binary, 'file|r1|u1|1');
  const decBytes = clientC.aesDecryptBytes(fileKey, encBytes, 'file|r1|u1|1');
  check('客户端二进制文件加解密往返一致', decBytes === binary);
  check('客户端 GCM 校验可拒绝篡改的文件密文', (() => {
    try { clientC.aesDecryptBytes(fileKey, encBytes, 'file|r1|u1|2'); return false; }
    catch (e) { return true; }
  })());

  const memberKp = forgeServer.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const memberPubPem = forgeServer.pki.publicKeyToPem(memberKp.publicKey);
  const wrappedByClient = clientC.wrapKeyFor(memberPubPem, fileKey);
  const unwrappedByServer = serverC.unwrapKey(memberKp.privateKey, wrappedByClient);
  check('客户端封装的房间密钥可被成员私钥解封',
    Buffer.from(unwrappedByServer, 'binary').equals(Buffer.from(fileKey, 'binary')));

  const { InviteCodec } = require(path.join(ROOT, 'server', 'src', 'invite.js'));
  const invites = new InviteCodec({ archiveKey: nodeCrypto.randomBytes(32).toString('binary') });
  const code = invites.make({
    host: '192.168.0.104', port: 8080, roomId: 'r_secret', roomName: '私密房间',
    pin: 'ABCD-1234', inviterUid: 'u_abc', inviterName: 'Alice', private: true
  });
  const decoded = clientC.inviteDecrypt(code);
  check('客户端可离线解出邀请码中的 IP/端口/房间',
    !!decoded && decoded.host === '192.168.0.104' && decoded.port === 8080 &&
    decoded.roomId === 'r_secret' && decoded.inviterName === 'Alice');
  check('服务端可验证自己签发的邀请码', invites.verify(decoded));
  check('篡改后的邀请码无法解析', clientC.inviteDecrypt(code.slice(0, -6) + 'AAAAAA') === null);

  const idKp = forgeServer.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const idDoc = {
    host: '192.168.0.104', port: 8080, fingerprint: 'abc123',
    uid: 'a'.repeat(64), nickname: '持久用户', createdAt: Date.now(),
    privateKeyPem: forgeServer.pki.privateKeyToPem(idKp.privateKey),
    publicKeyPem: forgeServer.pki.publicKeyToPem(idKp.publicKey)
  };
  const xmlPlain = clientID.build(idDoc, null);
  const parsedPlain = clientID.parse(xmlPlain, '');
  check('身份 XML 明文模式可生成并解析',
    parsedPlain.uid === idDoc.uid && parsedPlain.privateKeyPem === idDoc.privateKeyPem);
  const xmlEnc = clientID.build(idDoc, 'my-pass-123');
  const parsedEnc = clientID.parse(xmlEnc, 'my-pass-123');
  check('身份 XML 口令加密模式可往返',
    parsedEnc.privateKeyPem === idDoc.privateKeyPem && parsedEnc.publicKeyPem === idDoc.publicKeyPem);
  check('身份 XML 明文不泄露私钥口令', xmlEnc.indexOf(idDoc.privateKeyPem) === -1);
  check('错误口令无法解开身份 XML', (() => {
    try { clientID.parse(xmlEnc, 'wrong'); return false; } catch (e) { return true; }
  })());
  check('损坏的身份 XML 被完整性校验拒绝', (() => {
    try { clientID.parse(xmlPlain.replace('持久用户', '别人'), ''); return false; }
    catch (e) { return true; }
  })());

  /* 7b. v4: local identity vault — multiple accounts, rename, delete. */
  const vaultRec1 = clientID.vaultSave({
    host: '192.168.0.104', port: 8080, uid: idDoc.uid, nickname: '持久用户',
    createdAt: idDoc.createdAt, xml: xmlPlain, enc: 'none'
  });
  check('身份库可保存明文身份', !!vaultRec1 && clientID.vaultList().length === 1);
  const idDoc2 = Object.assign({}, idDoc, { uid: 'b'.repeat(64), nickname: '第二身份' });
  const xmlEnc2 = clientID.build(idDoc2, 'pass2');
  const vaultRec2 = clientID.vaultSave({
    host: '192.168.0.104', port: 8080, uid: idDoc2.uid, nickname: '第二身份',
    createdAt: idDoc2.createdAt, xml: xmlEnc2, enc: 'password'
  });
  check('身份库可保存多份身份且区分条目',
    !!vaultRec2 && clientID.vaultList().length === 2 && vaultRec1.id !== vaultRec2.id);
  const gotEnc = clientID.vaultGet(vaultRec2.id);
  check('身份库中加密身份可用口令重新解析',
    !!gotEnc && clientID.parse(gotEnc.xml, 'pass2').uid === idDoc2.uid);
  clientID.vaultRename(vaultRec1.id, '主号');
  check('身份库支持重命名', clientID.vaultGet(vaultRec1.id).label === '主号');
  clientID.vaultRemove(vaultRec2.id);
  check('身份库支持删除条目', clientID.vaultList().length === 1);

  /* 7c. v4 client static capability checks. */
  const appSrc = fs.readFileSync(path.join(ROOT, 'client', 'src', 'app.js'), 'utf8');
  const cssSrc = fs.readFileSync(path.join(ROOT, 'client', 'src', 'style.css'), 'utf8');
  const tplSrc = fs.readFileSync(path.join(ROOT, 'client', 'src', 'index.html'), 'utf8');
  check('客户端实现多房间独立状态与标签',
    /roomState/.test(appSrc) && /renderRoomTabs/.test(appSrc) && /openRooms/.test(appSrc));
  check('客户端实现拖拽上传',
    /dataTransfer/.test(appSrc) && /drop-overlay/.test(tplSrc));
  check('客户端实现身份库与快速切换',
    /vaultSave/.test(appSrc) && /useIdentity/.test(appSrc) && /btn-switch-user/.test(tplSrc));
  check('客户端具备移动端 H5 适配',
    /100dvh/.test(cssSrc) && /safe-area-inset/.test(cssSrc) &&
    /viewport-fit=cover/.test(tplSrc) && /font-size:16px/.test(cssSrc));

  /* 7d. v5: lobby direct-message crypto namespace + client capabilities. */
  check('协议版本与默认版权常量为 v5',
    P.RELEASE_VERSION === '5.0.0' && P.DEFAULT_COPYRIGHT === 'CJS flshw@126.com' &&
    P.TEMP_NAME_SEPARATOR === '·');
  check('客户端提供独立的直聊 AAD 构造函数', typeof clientC.directAad === 'function');
  const dmRoom = P.LOBBY_ID, dmUid = 'f'.repeat(64), dmSeq = 9, dmTs = 1794600000000;
  const expectedDmAad = ['dm', dmRoom, dmUid, dmSeq, dmTs].join('|');
  check('直聊 AAD 与服务端归档命名空间一致', clientC.directAad(dmRoom, dmUid, dmSeq, dmTs) === expectedDmAad);
  check('直聊 AAD 与公聊 AAD 隔离（不可跨命名空间重放）',
    clientC.directAad(dmRoom, dmUid, dmSeq, dmTs) !== clientC.messageAad(dmRoom, dmUid, dmSeq, dmTs));

  const receiverKp = forgeServer.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const receiverPubPem = forgeServer.pki.publicKeyToPem(receiverKp.publicKey);
  const dmKey = clientC.randomBytes(32);
  const dmWrapped = clientC.wrapKeyFor(receiverPubPem, dmKey);
  const dmUnwrapped = serverC.unwrapKey(receiverKp.privateKey, dmWrapped);
  check('客户端封装的私聊会话密钥可被接收方私钥解封', dmUnwrapped === dmKey);
  const dmText = '大厅私聊 🔒 仅双方可见';
  const dmEnc = clientC.aesEncrypt(dmKey, JSON.stringify({ text: dmText, kind: 'text' }),
    clientC.directAad(dmRoom, dmUid, dmSeq, dmTs));
  const dmPlain = JSON.parse(serverC.aesDecrypt(dmUnwrapped, dmEnc, expectedDmAad));
  check('直聊密文在 dm AAD 命名空间下互通', dmPlain.text === dmText);
  check('用公聊 AAD 无法解密直聊密文（AAD 绑定生效）', (() => {
    try { serverC.aesDecrypt(dmUnwrapped, dmEnc, [dmRoom, dmUid, dmSeq, dmTs].join('|')); return false; }
    catch (e) { return true; }
  })());
  check('房间会话密钥无法解密直聊密文', (() => {
    try { serverC.aesDecrypt(roomKey, dmEnc, expectedDmAad); return false; }
    catch (e) { return true; }
  })());
  const dmEncByServer = serverC.aesEncrypt(dmKey, JSON.stringify({ text: dmText }), expectedDmAad);
  check('服务端构造的直聊密文可被客户端解密',
    JSON.parse(clientC.aesDecrypt(dmKey, dmEncByServer,
      clientC.directAad(dmRoom, dmUid, dmSeq, dmTs))).text === dmText);
  check('直聊密文标签篡改被 GCM 拒绝', (() => {
    try {
      clientC.aesDecrypt(dmKey, Object.assign({}, dmEncByServer, { tag: dmEnc.tag }), expectedDmAad);
      return false;
    } catch (e) { return true; }
  })());

  check('登录页身份信息包两个入口均外置可见',
    /identity-panel/.test(tplSrc) && /f-identity/.test(tplSrc) &&
    /f-save-identity/.test(tplSrc) && /f-add-vault/.test(tplSrc));
  check('客户端实现公聊/私聊快切与大厅直聊',
    /mode-bar/.test(tplSrc) && /dm-chip/.test(tplSrc) &&
    /setDirectMode/.test(appSrc) && /sendDirectMessage/.test(appSrc) &&
    /DIRECT_MESSAGE_BROADCAST/.test(appSrc));
  check('客户端实现临时时间戳、在线改名与品牌同步',
    /makeTempStamp/.test(appSrc) && /composeNickname/.test(appSrc) &&
    /applyRename/.test(appSrc) && /NICKNAME_CHANGE/.test(appSrc) &&
    /applyServerBrand/.test(appSrc) && /rename-modal/.test(tplSrc));
  check('样式表区分正式/临时昵称与私聊气泡并美化整体背景',
    /msg-author\.formal/.test(cssSrc) && /msg-author\.temp/.test(cssSrc) &&
    /mname\.formal/.test(cssSrc) && /mname\.temp/.test(cssSrc) &&
    /msg-row\.direct/.test(cssSrc) && /radial-gradient/.test(cssSrc) &&
    /app-foot/.test(cssSrc));
  check('客户端底栏与登录页展示版权信息',
    /app-foot/.test(tplSrc) && /login-copyright/.test(tplSrc) &&
    /CJS flshw@126\.com/.test(tplSrc));

  /* 7e. v5.1: preset backgrounds, picker, room tabs & member list restyle. */
  check('预置背景主题至少 5 套且默认为 aurora',
    (cssSrc.match(/body\[data-bg="/g) || []).length >= 5 &&
    /body\[data-bg="aurora"\]/.test(cssSrc) &&
    /body\.custom-bg/.test(cssSrc));
  check('客户端实现背景选择器与本地图片背景',
    /bg-modal/.test(tplSrc) && /bg-grid/.test(tplSrc) && /f-bg-custom/.test(tplSrc) &&
    /BG_PRESETS/.test(appSrc) && /bgApply/.test(appSrc) && /bgLoadCustom/.test(appSrc) &&
    /chatroom-bg-v5/.test(appSrc));
  check('背景选择持久化到 localStorage 且不随身份文件上传',
    /localStorage\.setItem\(BG_KEY/.test(appSrc) && /localStorage\.getItem\(BG_CUSTOM_KEY/.test(appSrc) &&
    !/bgSave/.test(fs.readFileSync(path.join(ROOT, 'client', 'src', 'identity.js'), 'utf8')));
  check('自定义背景经 canvas 压缩后存储（限制尺寸与体积）',
    /createElement\('canvas'\)/.test(appSrc) && /1600/.test(appSrc) &&
    /toDataURL\('image\/jpeg', 0\.82\)/.test(appSrc));
  check('房间标签含图标、未读角标与入场动画',
    /rt-ico/.test(cssSrc) && /tab-in/.test(cssSrc) && /badge-pop/.test(cssSrc) &&
    /rt-ico/.test(appSrc) && /scrollIntoView/.test(appSrc));
  check('成员列表为两行卡片并带身份标签与头像配色',
    /mline/.test(cssSrc) && /msub/.test(cssSrc) && /mtag\.formal/.test(cssSrc) &&
    /avColorClass/.test(appSrc) && /is-dm/.test(cssSrc) && /is-dm/.test(appSrc));

  /* 8. Every inlined script in the built HTML must parse. */
  const html = fs.readFileSync(path.join(ROOT, 'client', 'dist', 'chatroom.html'), 'utf8');
  const scripts = [];
  const re = /<script>([\s\S]*?)<\/script>/g;
  let m;
  while ((m = re.exec(html)) !== null) scripts.push(m[1]);
  check('单文件包含 6 段内联脚本', scripts.length === 6, '实际 ' + scripts.length);
  let syntaxOk = true, badIndex = -1, badMsg = '';
  scripts.forEach((code, i) => {
    try { new Function(code); }
    catch (e) { syntaxOk = false; badIndex = i; badMsg = e.message; }
  });
  check('全部内联脚本语法合法', syntaxOk, `script[${badIndex}]: ${badMsg}`);
  check('单文件不含未替换占位符', !/__[A-Z]+__/.test(html));
  check('单文件不引用任何外部资源', !/<script[^>]+src=/.test(html) && !/<link[^>]+href=/.test(html));
  check('单文件体积合理 (< 500 KB)', Buffer.byteLength(html) < 500 * 1024,
    (Buffer.byteLength(html) / 1024).toFixed(1) + ' KB');

  /* 7e. v5.4: in-room mesh video call — protocol constants + client wiring. */
  check('v5.4 协议新增 WEBRTC 信令类型', P.MSG.WEBRTC === 'webrtc');
  check('v5.4 协议新增 WEBRTC 错误码', P.ERR.WEBRTC_INVALID === 'E_WEBRTC_INVALID');
  check('v5.4 协议新增信令大小上限', typeof P.LIMITS.MAX_WEBRTC_SIGNAL_BYTES === 'number' && P.LIMITS.MAX_WEBRTC_SIGNAL_BYTES === 16384);
  check('客户端实现房间内视频通话（信令 + 网格 + 挂断）',
    /function startVideoCall/.test(appSrc) && /function onWebrtcSignal/.test(appSrc) &&
    /RTCPeerConnection/.test(appSrc) && /function endVideoCall/.test(appSrc));
  check('客户端视频通话仅限房间（非大厅）', /function videoAllowed/.test(appSrc) && /currentRoom !== P\.LOBBY_ID/.test(appSrc));
  check('HTML 含视频通话浮层与按钮', /id="video-overlay"/.test(tplSrc) && /id="btn-video"/.test(tplSrc));
  check('CSS 含视频浮层样式', /\.video-overlay\{/.test(cssSrc) && /\.video-grid\{/.test(cssSrc));

  console.log(`\n=== 结果: ${passed} 通过 / ${failed} 失败 ===\n`);
  process.exit(failed ? 1 : 0);
}

run();
