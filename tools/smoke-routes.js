/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
'use strict';
/*
 * Route regression tests: two-project virtual directories plus the admin UI
 * migration from the site root into /chat/.
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
  return { status: r.status, location: r.headers.get('location'), text: await r.text() };
}

(async () => {
  console.log('== 虚拟目录与管理台路由回归 (' + BASE + ') ==');

  const nav = await get('/');
  check('根路径提供双项目导航页',
    nav.status === 200 && /项目导航/.test(nav.text) &&
    /href="\/chat\/"/.test(nav.text) && /href="\/Pchat\/"/.test(nav.text));

  const chat = await get('/chat/');
  check('聊天室客户端位于 /chat/',
    chat.status === 200 && /ChatRoom/.test(chat.text));

  const pchat = await get('/Pchat/');
  check('私密聊天占位页位于 /Pchat/',
    pchat.status === 200 && /私密聊天/.test(pchat.text));

  const admin = await get('/chat/admin/');
  check('管理台已迁移到 /chat/admin/',
    admin.status === 200 && /data-view="bots"/.test(admin.text) &&
    /btn-welcome/.test(admin.text));

  check('管理台资源引用改为 /chat/assets/',
    /src="\/chat\/assets\/forge\.min\.js"/.test(admin.text));

  const setup = await get('/chat/setup/');
  check('部署向导已迁移到 /chat/setup/',
    setup.status === 200 && /href="\/chat\/admin\/"/.test(setup.text));

  const asset = await get('/chat/assets/forge.min.js');
  check('forge 资源在 /chat/assets/ 可访问',
    asset.status === 200 && asset.text.length > 1000);

  const redirects = [
    ['/admin', '/chat/admin/', '管理台旧地址'],
    ['/admin/', '/chat/admin/', '管理台旧地址（带斜杠）'],
    ['/admin/index.html', '/chat/admin/', '管理台旧文件地址'],
    ['/setup', '/chat/setup/', '向导旧地址'],
    ['/setup/', '/chat/setup/', '向导旧地址（带斜杠）'],
    ['/setup.html', '/chat/setup/', '向导旧文件地址'],
    ['/assets/forge.min.js', '/chat/assets/forge.min.js', '资源旧地址']
  ];
  for (const [from, to, label] of redirects) {
    const r = await get(from);
    check(label + ' 301 跳转', r.status === 301 && r.location === to,
      'status=' + r.status + ' location=' + r.location);
  }

  const info = await fetch(BASE + '/api/client-info').then(r => r.json());
  check('client-info 发布新的虚拟目录路径',
    info.adminUrl === '/chat/admin/' && info.chatUrl === '/chat/',
    JSON.stringify({ adminUrl: info.adminUrl, chatUrl: info.chatUrl }));

  console.log('\n结果: ' + passed + ' 通过 / ' + failed + ' 失败');
  process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
