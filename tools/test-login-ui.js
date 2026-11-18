/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · login UI (public area + two tabs, passphrase-free keyfile) regression test.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const ROOT = path.resolve(__dirname, '..');
const read = p => fs.readFileSync(path.join(ROOT, p), 'utf8');

let pass = 0, fail = 0;
function check(name, ok) {
  if (ok) { pass++; console.log('  OK   ' + name); }
  else { fail++; console.log(' FAIL  ' + name); }
}

const tpl = read('client/src/index.html');
const app = read('client/src/app.js');
const css = read('client/src/style.css');
const ident = read('client/src/identity.js');
const sident = read('server/src/identity.js');
const built = read('server/public/chatroom.html');

/* --- layout: public area on top, tabs below, login button at bottom --- */
check('公共区含服务器地址/端口/邀请码',
  /class="login-public"/.test(tpl) && /id="f-host"/.test(tpl) &&
  /id="f-port"/.test(tpl) && /id="f-invite"/.test(tpl));
check('公共区在选项卡之前、选项卡在登录按钮之前',
  tpl.indexOf('login-public') < tpl.indexOf('login-tabs') &&
  tpl.indexOf('login-tabs') < tpl.indexOf('btn-connect'));

/* --- two tabs, username is the default --- */
check('两个选项卡：用户名登录(默认) / 密钥文件登录',
  /id="tab-username" class="login-tab active"/.test(tpl) &&
  /id="tab-keyfile" class="login-tab"/.test(tpl) &&
  /aria-selected="true"[^>]*>用户名登录/.test(tpl));
check('用户名面板默认显示、密钥面板默认隐藏',
  /class="login-panel" id="panel-username"/.test(tpl) &&
  /class="login-panel hidden" id="panel-keyfile"/.test(tpl));

/* --- username tab fields: no passphrase field anymore --- */
check('用户名模式：用户名 + 注册正式用户（无加密口令框）',
  /id="panel-username"[\s\S]*?id="f-username"[\s\S]*?id="f-save-identity"[\s\S]*?<\/div>/.test(tpl) &&
  /注册为正式用户/.test(tpl) && !/id="f-save-pass"/.test(tpl));

/* --- keyfile tab: file input, no passphrase, no username --- */
check('密钥模式：选择 .xml 文件 + 身份库选项（无解密口令）',
  /id="panel-keyfile"[\s\S]*?id="f-identity"[\s\S]*?id="f-add-vault"[\s\S]*?<\/div>/.test(tpl) &&
  !/id="f-identity-pass"/.test(tpl));
const keyPanel = tpl.slice(tpl.indexOf('id="panel-keyfile"'), tpl.indexOf('</details>', tpl.indexOf('id="panel-keyfile"')));
check('密钥面板内部无用户名/口令输入框', !/id="f-username"/.test(keyPanel) && !/type="password"/.test(keyPanel));

/* --- preserved element ids (logic compatibility) --- */
const ids = ['view-login','f-username','f-host','f-port','f-invite','f-proxy',
  'f-save-identity','f-identity','identity-info','f-add-vault','btn-clear-identity',
  'advanced','btn-connect','login-status'];
check('既有元素 id 保留：' + ids.length + ' 个',
  ids.every(id => new RegExp('id="' + id + '"').test(tpl)));

/* --- logic wiring --- */
check('setLoginMode 已定义并接到两个选项卡',
  /function setLoginMode/.test(app) &&
  /\$\('tab-username'\)\.addEventListener\('click', function \(\) \{ setLoginMode\('username'\)/.test(app) &&
  /\$\('tab-keyfile'\)\.addEventListener\('click', function \(\) \{ setLoginMode\('keyfile'\)/.test(app));
check('密钥模式无密钥文件时阻止登录',
  /loginMode === 'keyfile' && !state\.identityFile/.test(app));
check('用户名模式切回时清除已加载密钥文件',
  /if \(isUser\) clearIdentityFile\(\)/.test(app));
check('loadIdentityFile 无口令解析并自动回填',
  /function loadIdentityFile\(file\)/.test(app) &&
  /ID\.parse\(xml, null\)/.test(app) &&
  /\$\('f-username'\)\.value = id\.nickname/.test(app) &&
  /\$\('f-host'\)\.value = id\.host/.test(app) &&
  /\$\('f-port'\)\.value = id\.port/.test(app));
check('选择密钥文件后自动登录（无需点按钮/输口令）',
  /loadIdentityFile\(f\)\.then\(function \(\) \{[\s\S]{0,150}connect\(\)/.test(app));
check('build 身份文件无口令明文导出',
  /ID\.build\(doc, null\)/.test(app) && !/ID\.build\(doc, state\.savePassword/.test(app));
check('app 内无口令输入框引用', !/f-save-pass|f-identity-pass|savePassword/.test(app));

/* --- integrity EOL fix (the actual login bug) --- */
check('identity.js 用 normEol 统一换行计算完整性',
  /function normEol/.test(ident) && /function integrityOf/.test(ident) &&
  /normEol\(pubPem\)/.test(ident) && /out\.integrity !== check && out\.integrity !== checkCrlf/.test(ident));
check('identity.js build 写入 LF 规范化 PEM 且用 integrityOf',
  /cdata\(normEol\(doc\.publicKeyPem\)\)/.test(ident) && /integrityOf\(doc, doc\.publicKeyPem\)/.test(ident));
check('server verifyResume 公钥比对忽略换行差异',
  /function normPem/.test(sident) && /normPem\(rec\.pubkey\) !== normPem\(inner\.clientPub\)/.test(sident));

/* --- CSS + built artifact --- */
check('选项卡样式存在（含 active 高亮）', /\.login-tabs/.test(css) && /\.login-tab\.active/.test(css));
check('构建产物已含新结构与无口令逻辑',
  /class="login-public"/.test(built) && /function setLoginMode/.test(built) &&
  /function normEol/.test(built) && !/id="f-identity-pass"/.test(built) && !/id="f-save-pass"/.test(built));

console.log('\n登录界面+密钥文件修复回归: ' + pass + ' PASS / ' + fail + ' FAIL');
process.exit(fail ? 1 : 0);
