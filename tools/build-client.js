/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
'use strict';
/* Builds client/dist/chatroom.html as a single self-contained file and
 * copies it to server/public/ so the server can host it. */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const read = p => fs.readFileSync(path.join(ROOT, p), 'utf8');
const write = (p, s) => {
  fs.mkdirSync(path.dirname(path.join(ROOT, p)), { recursive: true });
  fs.writeFileSync(path.join(ROOT, p), s);
};
/* A library could theoretically contain the literal closing tag; neutralise it. */
const safeJs = s => s.replace(/<\/script/gi, '<\\/script');

/* Keep server/ self-contained: shared/protocol.js is canonical, and a
 * byte-identical copy lives in server/src/ so that copying only server/
 * to another machine (Windows or Linux) still boots. */
const canonicalProtocol = read('shared/protocol.js');
const serverProtocol = path.join(ROOT, 'server', 'src', 'protocol.js');
if (!fs.existsSync(serverProtocol) || fs.readFileSync(serverProtocol, 'utf8') !== canonicalProtocol) {
  fs.writeFileSync(serverProtocol, canonicalProtocol);
  console.log('已同步: server/src/protocol.js (与 shared/protocol.js 保持一致)');
}

const parts = {
  '__CSS__': read('client/src/style.css'),
  '__PROTOCOL__': safeJs(canonicalProtocol),
  '__FORGE__': safeJs(read('vendor/forge.min.js')),
  '__CRYPTO__': safeJs(read('client/src/crypto.js')),
  '__IDENTITY__': safeJs(read('client/src/identity.js')),
  '__NET__': safeJs(read('client/src/net.js')),
  '__APP__': safeJs(read('client/src/app.js'))
};

let html = read('client/src/index.html');
for (const key of Object.keys(parts)) {
  const token = '/*' + key + '*/';
  if (html.indexOf(token) === -1) throw new Error('模板缺少占位符: ' + token);
  html = html.replace(token, () => parts[key]);
}
if (/__[A-Z]+__/.test(html)) throw new Error('仍有未替换的占位符');

write('client/dist/chatroom.html', html);
write('server/public/chatroom.html', html);

const kb = (Buffer.byteLength(html) / 1024).toFixed(1);
console.log(`构建完成: client/dist/chatroom.html (${kb} KB)`);
console.log('已同步: server/public/chatroom.html');
console.log('内联内容: CSS / 协议常量 / node-forge / 加密核心 / 身份文件 / 网络层 / 应用逻辑');
