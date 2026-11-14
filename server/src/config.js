/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const { DATA_DIR } = require('./paths');

const CONFIG_FILE = path.join(DATA_DIR, 'config.json');

const P = require('./protocol');

const DEFAULTS = {
  name: 'ChatRoom',
  host: '0.0.0.0',
  port: 8080,
  maxRooms: 50,
  maxMembersPerRoom: 30,
  historyEnabled: true,
  maxMessageBytes: 8192,
  copyright: P.DEFAULT_COPYRIGHT,
  copyrightLink: ''
};

const EDITABLE = [
  'name', 'port', 'maxRooms', 'maxMembersPerRoom', 'historyEnabled',
  'copyright', 'copyrightLink'
];

/* Human-readable annotations for every server setting. The admin page renders
 * these next to each field so an operator knows the effect, scope and caveats
 * before saving (v5 requirement #2). */
const FIELD_NOTES = {
  name: {
    label: '聊天室名称',
    note: '显示在客户端顶栏与门户页。保存后立即广播给所有在线客户端，无需刷新；不影响房间名。',
    scope: '即时生效 · 广播同步'
  },
  host: {
    label: '监听地址',
    note: '0.0.0.0 表示监听本机全部网卡，局域网其它设备才能通过 IP 访问；127.0.0.1 仅本机可用。',
    scope: '只读 · 进程启动时决定'
  },
  port: {
    label: '服务端口',
    note: 'TCP 监听端口，客户端 IP:端口 与 ws:// 都使用它。修改后需重启进程，管理页「重启服务」是软重启且保持当前端口。',
    scope: '需进程级重启 · 放行防火墙'
  },
  maxRooms: {
    label: '最大房间数',
    note: '包含大厅在内的房间总数上限，超过后创建房间返回 ROOM_FULL。',
    scope: '即时生效'
  },
  maxMembersPerRoom: {
    label: '每房间人数上限',
    note: '单个房间最多同时在线的成员数；大厅同样受此限制，机器人也占位。',
    scope: '即时生效'
  },
  historyEnabled: {
    label: '保存历史消息',
    note: '开启后普通房间消息以服务器归档密钥加密落盘，管理员可解密查看；E2EE 私聊仅存密文。关闭后不再读取历史。',
    scope: '即时生效'
  },
  maxMessageBytes: {
    label: '单条消息密文上限',
    note: '限制消息密文字节数，防止超大帧耗尽内存；默认 8192 字节，修改需进程级重启。',
    scope: '只读 · 进程启动时决定'
  },
  copyright: {
    label: '版权信息文字',
    note: '显示在客户端底栏、管理台页脚与 /welcome 门户页。保存后广播给所有在线客户端即时更新。',
    scope: '即时生效 · 广播同步'
  },
  copyrightLink: {
    label: '版权链接（可选）',
    note: '可填 http(s) 链接或邮箱；留空则版权文字为纯文本，不生成链接。',
    scope: '即时生效 · 广播同步'
  }
};

function loadConfig() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  let user = {};
  if (fs.existsSync(CONFIG_FILE)) {
    try { user = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')); }
    catch (e) { user = {}; }
  }
  const merged = Object.assign({}, DEFAULTS, user);
  const envPort = parseInt(process.env.CHATROOM_PORT || '', 10);
  if (Number.isInteger(envPort) && envPort > 0 && envPort < 65536) merged.port = envPort;
  const argPort = process.argv.indexOf('--port');
  if (argPort !== -1) {
    const p = parseInt(process.argv[argPort + 1], 10);
    if (Number.isInteger(p) && p > 0 && p < 65536) merged.port = p;
  }
  return merged;
}

function saveConfig(patch) {
  const current = loadConfig();
  for (const key of EDITABLE) {
    if (Object.prototype.hasOwnProperty.call(patch, key)) {
      let v = patch[key];
      if (key === 'port' || key === 'maxRooms' || key === 'maxMembersPerRoom') v = Number(v);
      if (key === 'historyEnabled') v = !!v;
      if (key === 'name') v = String(v).slice(0, 40).trim() || DEFAULTS.name;
      if (key === 'copyright') v = String(v == null ? '' : v).slice(0, 120).trim();
      if (key === 'copyrightLink') {
        v = String(v == null ? '' : v).slice(0, 160).trim();
        if (v && !/^(https?:\/\/|mailto:)/i.test(v)) continue;
      }
      if (key === 'port' && (!Number.isInteger(v) || v < 1 || v > 65535)) continue;
      current[key] = v;
    }
  }
  const out = {};
  for (const key of EDITABLE) out[key] = current[key];
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(out, null, 2));
  return out;
}

function publicConfig(cfg) {
  return {
    name: cfg.name,
    maxRooms: cfg.maxRooms,
    maxMembersPerRoom: cfg.maxMembersPerRoom,
    historyEnabled: cfg.historyEnabled,
    copyright: cfg.copyright,
    copyrightLink: cfg.copyrightLink
  };
}

module.exports = {
  loadConfig, saveConfig, publicConfig, DEFAULTS, EDITABLE, FIELD_NOTES, CONFIG_FILE
};
