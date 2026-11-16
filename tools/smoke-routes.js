/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
'use strict';
/*
 * Route regression tests: two-project virtual directories plus the full
 * ChatRoom page migration from the site root into /chat/
 * (client / admin / setup / welcome / assets / download).
 *
 *   node tools/smoke-routes.js
 *   CHATROOM_BASE=http://127.0.0.1:8099 node tools/smoke-routes.js
 *
 * Requires a running server (local or remote); no admin token needed.
 */
const BASE = process.env.CHATROOM_BASE || 'http://127.0.0.1:8080';

let passed = 0, failed = 0;
function check(name, ok, detail) {
  if (ok) { passed++; console.log('  PASS  ' + name); }
  else { failed++; console.log('  FAIL  ' + name + (detail ? ' -> ' + detail : '')); }
}

async function get(pathname) {
  const r = await fetch(BASE + pathname, { redirect: 'manual' });
  return {
    status: r.status,
    location: r.headers.get('location'),
    headers: r.headers,
    text: await r.text()
  };
}

(async () => {
  console.log('== 虚拟目录与管理台路由回归 (' + BASE + ') ==');

  const nav = await get('/');
  check('根路径提供双项目导航页',
    nav.status === 200 && /项目导航/.test(nav.text) &&
    /href="\/chat\/"/.test(nav.text) && /href="\/Pchat\/"/.test(nav.text));
  check('导航页使用说明指向 /chat/welcome/',
    /href="\/chat\/welcome\/"/.test(nav.text));

  const chat = await get('/chat/');
  check('聊天室客户端位于 /chat/',
    chat.status === 200 && /ChatRoom/.test(chat.text));
  check('客户端内下载链接指向 /chat/download/',
    /href="\/chat\/download\/chatroom\.html"/.test(chat.text) &&
    !/href="\/download\/chatroom\.html"/.test(chat.text));

  const pchat = await get('/Pchat/');
  check('私密聊天门户由独立服务经 /Pchat/ 提供',
    pchat.status === 200 && /私密聊天/.test(pchat.text) &&
    /btn-apply/.test(pchat.text));

  const pcHealth = await get('/pc/api/health');
  check('私密聊天 API 经 /pc/api/health 反代',
    pcHealth.status === 200 && /"ok":true/.test(pcHealth.text) &&
    /"pcVersion"/.test(pcHealth.text));

  const admin = await get('/chat/admin/');
  check('管理台已迁移到 /chat/admin/',
    admin.status === 200 && /data-view="bots"/.test(admin.text) &&
    /btn-welcome/.test(admin.text));

  check('管理台资源引用改为 /chat/assets/',
    /src="\/chat\/assets\/forge\.min\.js"/.test(admin.text));

  const setup = await get('/chat/setup/');
  check('部署向导已迁移到 /chat/setup/',
    setup.status === 200 && /href="\/chat\/admin\/"/.test(setup.text));

  const welcome = await get('/chat/welcome/');
  check('下载说明页已迁移到 /chat/welcome/',
    welcome.status === 200 && /身份文件/.test(welcome.text) && /SHA-256/.test(welcome.text));
  check('欢迎页在线聊天与下载链接指向 /chat/',
    /href="\/chat\/"/.test(welcome.text) &&
    /href="\/chat\/download\/chatroom\.html"/.test(welcome.text));

  const download = await get('/chat/download/chatroom.html');
  check('单文件下载端点位于 /chat/download/ 且带 attachment 头',
    download.status === 200 &&
    /attachment/.test(download.headers.get('content-disposition') || '') &&
    download.text.indexOf('ChatRoom') !== -1);

  const asset = await get('/chat/assets/forge.min.js');
  check('forge 资源在 /chat/assets/ 可访问',
    asset.status === 200 && asset.text.length > 1000);

  const redirects = [
    ['/index.html', '/chat/', '客户端旧首页别名'],
    ['/chatroom.html', '/chat/', '客户端旧文件别名'],
    ['/admin', '/chat/admin/', '管理台旧地址'],
    ['/admin/', '/chat/admin/', '管理台旧地址（带斜杠）'],
    ['/admin/index.html', '/chat/admin/', '管理台旧文件地址'],
    ['/setup', '/chat/setup/', '向导旧地址'],
    ['/setup/', '/chat/setup/', '向导旧地址（带斜杠）'],
    ['/setup.html', '/chat/setup/', '向导旧文件地址'],
    ['/welcome', '/chat/welcome/', '下载说明页旧地址'],
    ['/welcome/', '/chat/welcome/', '下载说明页旧地址（带斜杠）'],
    ['/welcome.html', '/chat/welcome/', '下载说明页旧文件地址'],
    ['/download/chatroom.html', '/chat/download/chatroom.html', '下载端点旧地址'],
    ['/assets/forge.min.js', '/chat/assets/forge.min.js', '资源旧地址']
  ];
  for (const [from, to, label] of redirects) {
    const r = await get(from);
    check(label + ' 301 跳转', r.status === 301 && r.location === to,
      'status=' + r.status + ' location=' + r.location);
  }

  const info = await fetch(BASE + '/api/client-info').then(r => r.json());
  check('client-info 发布新的虚拟目录路径',
    info.adminUrl === '/chat/admin/' && info.chatUrl === '/chat/' &&
    info.welcomeUrl === '/chat/welcome/' &&
    info.downloadUrl === '/chat/download/chatroom.html',
    JSON.stringify({ adminUrl: info.adminUrl, chatUrl: info.chatUrl,
      welcomeUrl: info.welcomeUrl, downloadUrl: info.downloadUrl }));

  console.log('\n结果: ' + passed + ' 通过 / ' + failed + ' 失败');
  process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
