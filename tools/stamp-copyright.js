/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
'use strict';
/*
 * Stamp the project copyright line into every first-party source file.
 * Idempotent: files already carrying the marker are left untouched.
 * Third-party bundles under vendor/ are deliberately excluded.
 *
 *   node tools/stamp-copyright.js [--check]
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const MARKER = 'CJS flshw@126.com';
const YEAR = '2026';

const JS_HEADER = [
  '/*',
  ` * Copyright (c) ${YEAR} ${MARKER}`,
  ' * ChatRoom · LAN encrypted chat room. All rights reserved.',
  ' * Licensed for use with this ChatRoom distribution only.',
  ' */'
].join('\n');

const CSS_HEADER = JS_HEADER;
const HTML_HEADER = [
  '<!--',
  `  Copyright (c) ${YEAR} ${MARKER}`,
  '  ChatRoom · LAN encrypted chat room. All rights reserved.',
  '  Licensed for use with this ChatRoom distribution only.',
  '-->'
].join('\n');

function collect() {
  const out = [];
  const addDir = (rel, exts) => {
    const dir = path.join(ROOT, rel);
    for (const name of fs.readdirSync(dir).sort()) {
      const f = path.join(dir, name);
      if (!fs.statSync(f).isFile()) continue;
      if (exts.some(e => name.endsWith(e))) out.push(path.relative(ROOT, f).replace(/\\/g, '/'));
    }
  };
  addDir('shared', ['.js']);
  addDir('server/src', ['.js']);
  addDir('client/src', ['.js', '.css', '.html']);
  addDir('tools', ['.js']);
  out.push('server/admin/index.html', 'server/public/welcome.html');
  return out;
}

function stamp(rel, checkOnly) {
  const abs = path.join(ROOT, rel);
  const src = fs.readFileSync(abs, 'utf8');
  const head = src.slice(0, 400);
  if (head.includes(MARKER)) return { rel, status: 'already' };
  if (checkOnly) return { rel, status: 'missing' };

  let next;
  if (rel.endsWith('.html')) {
    const m = src.match(/^\s*(<!doctype[^>]*>)/i);
    if (!m) throw new Error('HTML 缺少 doctype: ' + rel);
    const at = m.index + m[0].length;
    next = src.slice(0, at) + '\n' + HTML_HEADER + src.slice(at);
  } else {
    next = (rel.endsWith('.css') ? CSS_HEADER : JS_HEADER) + '\n' + src;
  }
  fs.writeFileSync(abs, next);
  return { rel, status: 'stamped' };
}

const checkOnly = process.argv.includes('--check');
const results = collect().map(f => stamp(f, checkOnly));
let added = 0, skipped = 0, missing = 0;
for (const r of results) {
  if (r.status === 'stamped') { added++; console.log('  已添加  ' + r.rel); }
  else if (r.status === 'missing') { missing++; console.log('  缺少    ' + r.rel); }
  else skipped++;
}
console.log(`\n版权信息 ${MARKER}：新增 ${added} 个，已存在 ${skipped} 个` +
  (checkOnly ? `，缺少 ${missing} 个` : ''));
if (checkOnly && missing) process.exitCode = 1;
