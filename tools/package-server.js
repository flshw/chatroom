/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
'use strict';
/*
 * Package the standalone server for deployment (primarily Ubuntu).
 *
 *   node tools/package-server.js           -> dist/chatroom-server-v{ver}.tar.gz
 *   node tools/package-server.js --zip     -> additionally dist/chatroom-server-v{ver}.zip
 *
 * The archive contains a single top-level directory chatroom-server/ with:
 *   src/ admin/ public/ node_modules/ deploy/ package.json DEPLOY-UBUNTU.md
 * Runtime data (server/data) and logs (server/logs) are EXCLUDED on purpose:
 * production keeps them in /var/lib/chatroom / /var/log/chatroom (see
 * docs/16-Ubuntu部署说明.md and deploy/chatroom.service).
 *
 * node_modules ships inside the package: all three dependencies are pure
 * JS / WASM, so the target machine needs only a Node.js >= 22 runtime and
 * never runs npm install.
 */
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const nodeCrypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const SERVER_DIR = path.join(ROOT, 'server');
const STAGING = path.join(ROOT, '.package-staging');
const DIST = path.join(ROOT, 'dist');
const PKG_DIR_NAME = 'chatroom-server';
const VERSION = JSON.parse(fs.readFileSync(path.join(SERVER_DIR, 'package.json'), 'utf8')).version;
const BASE_NAME = `chatroom-server-v${VERSION}`;

const wantZip = process.argv.indexOf('--zip') !== -1;

function rmrf(p) { fs.rmSync(p, { recursive: true, force: true }); }

function copyDirFiltered(src, dest) {
  fs.mkdirSync(dest, { recursive: true });
  const skip = new Set(['data', 'logs']);          /* runtime state, never shipped */
  for (const name of fs.readdirSync(src)) {
    if (skip.has(name)) continue;
    if (name === '.DS_Store' || name === 'Thumbs.db') continue;
    const s = path.join(src, name);
    const d = path.join(dest, name);
    const st = fs.lstatSync(s);
    if (st.isDirectory()) copyDirFiltered(s, d);
    else fs.copyFileSync(s, d);
  }
}

function sha256(file) {
  return nodeCrypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function shell(cmd, args) {
  execFileSync(cmd, args, { cwd: ROOT, stdio: ['ignore', 'pipe', 'inherit'] });
}

function main() {
  /* ---- sanity: the server tree must be complete ---- */
  const mustExist = [
    'src/main.js', 'src/protocol.js', 'admin/index.html', 'admin/assets/forge.min.js',
    'public/chatroom.html', 'public/welcome.html', 'deploy/chatroom.service',
    'deploy/install-ubuntu.sh', 'node_modules/ws', 'node_modules/node-forge', 'node_modules/sql.js'
  ].map(rel => path.join(SERVER_DIR, rel));
  const missing = mustExist.filter(p => !fs.existsSync(p));
  if (missing.length) throw new Error('服务器目录不完整，缺少: ' + missing.join(', '));
  const built = fs.readFileSync(path.join(SERVER_DIR, 'public', 'chatroom.html'), 'utf8');
  if (!/ChatCrypto/.test(built)) throw new Error('public/chatroom.html 不是构建产物，请先运行 node tools/build-client.js');

  /* ---- stage the package ---- */
  rmrf(STAGING);
  const pkgRoot = path.join(STAGING, PKG_DIR_NAME);
  copyDirFiltered(SERVER_DIR, pkgRoot);
  fs.copyFileSync(
    path.join(ROOT, 'docs', '16-Ubuntu部署说明.md'),
    path.join(pkgRoot, 'DEPLOY-UBUNTU.md')
  );

  /* ---- tar.gz (primary, Linux) ---- */
  fs.mkdirSync(DIST, { recursive: true });
  const tarGz = path.join(DIST, BASE_NAME + '.tar.gz');
  rmrf(tarGz);
  /* Keep every tar argument RELATIVE to ROOT: GNU tar parses "D:\..." or
   * "D:/..." as host:path (remote archive) and fails on Windows drive letters. */
  shell('tar', ['-czf', path.relative(ROOT, tarGz), '-C',
    path.relative(ROOT, STAGING), PKG_DIR_NAME]);

  /* ---- optional zip (Windows transfer convenience) ---- */
  const outputs = [tarGz];
  if (wantZip) {
    const zip = path.join(DIST, BASE_NAME + '.zip');
    rmrf(zip);
    shell('powershell', [
      '-NoProfile', '-Command',
      `Compress-Archive -Path "${path.join(STAGING, PKG_DIR_NAME)}" -DestinationPath "${zip}" -Force`
    ]);
    outputs.push(zip);
  }

  /* ---- verify: listing must contain the critical entries ---- */
  const listing = execFileSync('tar', ['-tzf', path.relative(ROOT, tarGz)],
    { cwd: ROOT }).toString().split('\n');
  const need = [
    `${PKG_DIR_NAME}/src/main.js`, `${PKG_DIR_NAME}/src/protocol.js`,
    `${PKG_DIR_NAME}/admin/index.html`, `${PKG_DIR_NAME}/public/chatroom.html`,
    `${PKG_DIR_NAME}/public/welcome.html`, `${PKG_DIR_NAME}/node_modules/ws/package.json`,
    `${PKG_DIR_NAME}/node_modules/node-forge/package.json`,
    `${PKG_DIR_NAME}/node_modules/sql.js/package.json`,
    `${PKG_DIR_NAME}/deploy/chatroom.service`, `${PKG_DIR_NAME}/deploy/install-ubuntu.sh`,
    `${PKG_DIR_NAME}/DEPLOY-UBUNTU.md`, `${PKG_DIR_NAME}/package.json`
  ];
  const absent = need.filter(n => listing.indexOf(n) === -1);
  if (absent.length) throw new Error('打包校验失败，缺少: ' + absent.join(', '));
  const leaked = listing.filter(n => /^chatroom-server\/(data|logs)\//.test(n));
  if (leaked.length) throw new Error('运行期目录泄漏进包内: ' + leaked.slice(0, 3).join(', '));

  rmrf(STAGING);

  console.log(`打包完成: ChatRoom 服务器 v${VERSION}`);
  for (const f of outputs) {
    console.log(`  ${path.relative(ROOT, f)}  ${(fs.statSync(f).size / 1024 / 1024).toFixed(2)} MB  sha256=${sha256(f).slice(0, 16)}…`);
  }
  console.log(`  内容: src / admin / public / node_modules(纯 JS·WASM, 无需 npm install) / deploy / DEPLOY-UBUNTU.md`);
  console.log(`  已排除: data/ 与 logs/（生产环境放 /var/lib/chatroom 与 /var/log/chatroom）`);
  console.log(`  Ubuntu 部署: tar -xzf ${BASE_NAME}.tar.gz && cd ${PKG_DIR_NAME} && sudo bash deploy/install-ubuntu.sh`);
}

main();
