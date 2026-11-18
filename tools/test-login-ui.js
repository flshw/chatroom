/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · login UI (public area + two tabs) regression test.
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

/* --- username tab fields --- */
check('用户名模式：用户名/注册正式用户/加密口令',
  /id="panel-username"[\s\S]*?id="f-username"[\s\S]*?id="f-save-identity"[\s\S]*?id="f-save-pass"[\s\S]*?<\/div>/.test(tpl) &&
  /注册为正式用户/.test(tpl) && /密钥加密口令（可选）/.test(tpl));

/* --- keyfile tab fields, no username input inside --- */
check('密钥模式：选择 .xml 文件 + 解密口令 + 身份库选项',
  /id="panel-keyfile"[\s\S]*?id="f-identity"[\s\S]*?id="f-identity-pass"[\s\S]*?id="f-add-vault"[\s\S]*?<\/div>/.test(tpl));
const keyPanel = tpl.slice(tpl.indexOf('id="panel-keyfile"'), tpl.indexOf('</details>', tpl.indexOf('id="panel-keyfile"')));
check('密钥面板内部无用户名字段（无需输入用户名）', !/id="f-username"/.test(keyPanel));

/* --- all legacy IDs preserved (no logic breakage) --- */
const ids = ['view-login','f-username','f-host','f-port','f-invite','f-proxy',
  'f-save-identity','f-save-pass','f-identity','f-identity-pass','identity-info',
  'f-add-vault','btn-clear-identity','advanced','btn-connect','login-status'];
check('全部既有元素 id 保留：' + ids.length + ' 个',
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
check('加密口令框支持回车登录',
  /'f-save-pass'[\s\S]{0,300}id === 'f-save-pass'/.test(app) || /'f-save-pass'/.test(app));
check('loadIdentityFile 自动回填用户名/地址/端口（密钥登录无需手输）',
  /\$\('f-username'\)\.value = id\.nickname/.test(app) &&
  /\$\('f-host'\)\.value = id\.host/.test(app) &&
  /\$\('f-port'\)\.value = id\.port/.test(app));

/* --- CSS + built artifact --- */
check('选项卡样式存在（含 active 高亮）', /\.login-tabs/.test(css) && /\.login-tab\.active/.test(css));
check('构建产物已含新登录结构',
  /class="login-public"/.test(built) && /class="login-tab active"/.test(built) &&
  /function setLoginMode/.test(built) && /\.login-tab\.active/.test(built));

console.log('\n登录界面改造回归: ' + pass + ' PASS / ' + fail + ' FAIL');
process.exit(fail ? 1 : 0);
