/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
'use strict';
/*
 * Hub v5: authentication, key distribution, room routing and encrypted archiving.
 * Adds: live server/room metadata broadcast, lobby direct messages (E2EE, no
 * room creation), online nickname change, and a formal-user-only identity chain.
 */
const forge = require('node-forge');
const P = require('./protocol');
const C = require('./crypto');
const { RelaySession } = require('./session');

function shortId(prefix) {
  return prefix + '_' + C.b64(C.randomBytes(9)).replace(/[^a-zA-Z0-9]/g, '').slice(0, 12);
}
function makeInvite() {
  const s = C.b64(C.randomBytes(9)).replace(/[^A-Z0-9]/gi, '').toUpperCase().slice(0, 8).padEnd(8, 'X');
  return s.slice(0, 4) + '-' + s.slice(4, 8);
}
function messageAad(room, uid, seq, ts) { return [room, uid, seq, ts].join('|'); }

class Hub {
  constructor(options) {
    this.keys = options.keys;
    this.db = options.db;
    this.config = options.config;
    this.log = options.logger || (() => {});
    this.identity = options.identity;
    this.ledger = options.ledger;
    this.invite = options.invite;
    this.files = options.files;
    this.admin = options.admin;
    this.serverInfo = options.serverInfo || (() => ({ host: '127.0.0.1', port: this.config.port }));
    this.sessions = new Set();
    this.users = new Map();
    this.rooms = new Map();
    this.relaySessions = new Map();
    this.usedNonces = new Set();
    this.messageHooks = [];
    /* v5.2: drag-to-room invites pending target confirmation, token -> record */
    this.dragInvites = new Map();
    this.startedAt = Date.now();
    this.lobby = this.createRoom('大厅', false, P.LOBBY_ID, {});
  }

  /* ---------- sessions ---------- */

  attach(session) {
    this.sessions.add(session);
    this.log(`接入 ${session.kind} ${session.id}`);
    return session;
  }

  detach(session) {
    if (session.uid) {
      const user = this.users.get(session.uid);
      /* A newer session may have taken over this uid. In that case the old
       * socket closing must not wipe the current user's rooms/state. */
      if (user && user.session !== session) {
        this.sessions.delete(session);
        if (session.clientId) this.relaySessions.delete(session.clientId);
        this.log(`断开 ${session.kind} ${session.id}（该身份已由新会话接管）`);
        return;
      }
      if (user) {
        for (const roomId of Array.from(user.rooms)) {
          const room = this.rooms.get(roomId);
          if (room) {
            room.members.delete(user.uid);
            this.broadcastMembers(room);
            /* Bots rotate frequently; suppress noise for their joins/leaves. */
            if (!user.isBot) this.broadcastNotice(room, `${user.username} 离开了房间`, user.uid);
          }
        }
        this.users.delete(user.uid);
      }
    }
    this.sessions.delete(session);
    if (session.clientId) this.relaySessions.delete(session.clientId);
    /* Bots rotate every few seconds; keep their churn out of the log. */
    if (session.kind !== 'bot') this.log(`断开 ${session.kind} ${session.id}`);
  }

  getOrCreateRelaySession(clientId) {
    let s = this.relaySessions.get(clientId);
    if (!s || !s.isOpen) {
      if (s) this.detach(s);
      s = new RelaySession(clientId);
      this.relaySessions.set(clientId, s);
      this.sessions.add(s);
    }
    s.touch();
    return s;
  }

  handleRelay(clientId, envelope) {
    const s = this.getOrCreateRelaySession(clientId);
    if (envelope) this.handleEnvelope(s, envelope);
    return s.drain();
  }

  sweep() {
    for (const s of Array.from(this.sessions)) {
      if (!s.isOpen) this.detach(s);
    }
    if (this.usedNonces.size > 10000) this.usedNonces.clear();
  }

  /* ---------- rooms ---------- */

  createRoom(name, isPrivate, forcedId, opts) {
    opts = opts || {};
    if (this.rooms.size >= this.config.maxRooms) throw new Error('ROOM_FULL');
    const pin = isPrivate ? makeInvite() : null;
    const room = {
      id: forcedId || shortId('r'),
      name: String(name || '新房间').slice(0, 30),
      private: !!isPrivate,
      invite: pin,
      pin: pin,
      e2ee: !!opts.e2ee,
      key: opts.e2ee ? null : C.randomBytes(P.CRYPTO.AES_KEY_BYTES),
      wrappedKeys: opts.wrappedKeys || null,
      createdBy: opts.createdBy || null,
      members: new Set(),
      createdAt: Date.now()
    };
    this.rooms.set(room.id, room);
    this.db.upsertRoom(room);
    return room;
  }

  roomSummary(room) {
    return {
      id: room.id,
      name: room.name,
      private: room.private,
      invite: room.invite,
      e2ee: !!room.e2ee,
      members: room.members.size,
      createdAt: room.createdAt,
      createdBy: room.createdBy
    };
  }

  memberList(room) {
    const out = [];
    for (const uid of room.members) {
      const u = this.users.get(uid);
      if (u) out.push({
        uid: u.uid, username: u.username, pubKey: u.clientPubPem,
        permanent: !!u.permanent, bot: !!u.isBot
      });
    }
    return out;
  }

  /* Observers for plaintext messages in non-E2EE rooms (used by auto-reply bots). */
  registerMessageHook(fn) { this.messageHooks.push(fn); }

  attachBotUser(user, roomIds) {
    this.sessions.add(user.session);
    this.users.set(user.uid, user);
    for (const roomId of roomIds) {
      const room = this.rooms.get(roomId);
      if (room && !room.e2ee && room.members.size < this.config.maxMembersPerRoom) {
        this.addMember(user, room);
      }
    }
    for (const roomId of user.rooms) {
      const room = this.rooms.get(roomId);
      if (room) this.broadcastMembers(room);
    }
  }

  detachBotUser(uid) {
    const user = this.users.get(uid);
    if (user) this.detach(user.session);
  }

  addMember(user, room) {
    room.members.add(user.uid);
    user.rooms.add(room.id);
  }

  deliverRoomKey(user, room) {
    let wrapped;
    if (room.e2ee) {
      wrapped = room.wrappedKeys && room.wrappedKeys[user.uid];
      if (!wrapped) {
        user.session.error(P.ERR.KEY_DELIVERY_FAILED || P.ERR.FORBIDDEN,
          '该加密房间没有为您封装的会话密钥');
        return;
      }
    } else {
      const pub = forge.pki.publicKeyFromPem(user.clientPubPem);
      wrapped = C.wrapKey(pub, room.key);
    }
    user.session.send(P.makeEnvelope(P.MSG.ROOM_JOINED, {
      room: this.roomSummary(room),
      wrappedKey: wrapped,
      members: this.memberList(room)
    }));
  }

  broadcastMembers(room) {
    const env = P.makeEnvelope(P.MSG.ROOM_MEMBERS, {
      room: room.id, members: this.memberList(room)
    });
    for (const uid of room.members) {
      const u = this.users.get(uid);
      if (u) u.session.send(env);
    }
  }

  broadcastNotice(room, text, exceptUid) {
    const env = P.makeEnvelope(P.MSG.NOTICE, { text, room: room.id, ts: Date.now() });
    for (const uid of room.members) {
      if (uid === exceptUid) continue;
      const u = this.users.get(uid);
      if (u) u.session.send(env);
    }
  }

  sendRoomList(session) {
    session.send(P.makeEnvelope(P.MSG.ROOM_LIST_DATA, {
      rooms: Array.from(this.rooms.values())
        .filter(r => !r.private || r.createdBy === session.uid || r.members.has(session.uid))
        .map(r => this.roomSummary(r))
    }));
  }

  isMember(uid, roomId) {
    const u = this.users.get(uid);
    return !!(u && u.rooms.has(roomId));
  }

  /* ---------- envelope dispatch ---------- */

  handleEnvelope(session, env) {
    if (!P.isValidEnvelope(env)) { session.error(P.ERR.BAD_ENVELOPE, '报文格式错误'); return; }
    session.touch();

    if (env.type === P.MSG.PONG) return;
    if (env.type === P.MSG.PING) {
      session.send(P.makeEnvelope(P.MSG.PONG, { ts: Date.now() }));
      return;
    }
    if (env.type === P.MSG.HELLO) return this.onHello(session);
    if (env.type === P.MSG.REGISTER) return this.onRegister(session, env.data);
    if (env.type === P.MSG.SERVER_CONFIG_UPDATE ||
        env.type === P.MSG.ROOM_UPDATED ||
        env.type === P.MSG.NICKNAME_UPDATED ||
        env.type === P.MSG.DIRECT_MESSAGE_BROADCAST) return; /* server -> client only */

    if (!session.authenticated || !this.users.has(session.uid)) {
      session.error(P.ERR.NOT_AUTHENTICATED, '请先完成注册');
      return;
    }
    if (!this.identity.canLogin(session.uid)) {
      session.error(P.ERR.BANNED, '该身份已被禁止登录');
      try { session.close(); } catch (e) { /* noop */ }
      return;
    }
    const user = this.users.get(session.uid);
    try {
      switch (env.type) {
        case P.MSG.ROOM_LIST: return this.sendRoomList(session);
        case P.MSG.ROOM_CREATE: return this.onRoomCreate(user, env.data);
        case P.MSG.ROOM_JOIN: return this.onRoomJoin(user, env.data);
        case P.MSG.ROOM_LEAVE: return this.onRoomLeave(user, env.data);
        case P.MSG.MESSAGE: return this.onMessage(user, env.data);
        case P.MSG.DIRECT_MESSAGE: return this.onDirectMessage(user, env.data);
        case P.MSG.ROOM_DRAG_INVITE: return this.onRoomDragInvite(user, env.data);
        case P.MSG.ROOM_INVITE_REPLY: return this.onRoomInviteReply(user, env.data);
        case P.MSG.NICKNAME_CHANGE: return this.onNicknameChange(user, env.data);
        case P.MSG.HISTORY: return this.onHistory(user, env.data);
        case P.MSG.WEBRTC: return this.onWebrtcSignal(user, env.data);
        default: session.error(P.ERR.BAD_ENVELOPE, '未知消息类型: ' + env.type);
      }
    } catch (e) {
      this.log(`处理 ${env.type} 出错: ${e.message}`);
      session.error(e.code || P.ERR.INTERNAL, e.message || '处理失败');
    }
  }

  onHello(session) {
    const challenge = C.b64(C.randomBytes(P.CRYPTO.NONCE_BYTES));
    const salt = C.b64(C.randomBytes(P.CRYPTO.SALT_BYTES));
    session.pending = { challenge, salt, createdAt: Date.now() };
    session.send(P.makeEnvelope(P.MSG.WELCOME, {
      pubKey: this.keys.publicKeyPem,
      fingerprint: this.keys.fingerprint,
      adminPubKey: this.admin ? this.admin.data.publicKeyPem : null,
      challenge, salt, ts: Date.now(), version: P.RELEASE_VERSION,
      server: this.serverPublicInfo(),
      features: {
        identityFile: true, e2eePrivate: true, files: true, inviteCodes: true,
        lobbyDirect: true, onlineRename: true, serverConfigSync: true
      }
    }));
  }

  /* Public, non-secret branding shown by the client and portal page. */
  serverPublicInfo() {
    return {
      name: this.config.name,
      version: P.RELEASE_VERSION,
      copyright: this.config.copyright || P.DEFAULT_COPYRIGHT,
      copyrightLink: this.config.copyrightLink || ''
    };
  }

  /* v5: after an admin edits the chatroom name or copyright, push the new
   * values to every connected client so no refresh is needed. */
  broadcastServerConfig() {
    const env = P.makeEnvelope(P.MSG.SERVER_CONFIG_UPDATE, {
      server: this.serverPublicInfo(), ts: Date.now()
    });
    for (const u of this.users.values()) {
      try { u.session.send(env); } catch (e) { /* session went away */ }
    }
    return this.serverPublicInfo();
  }

  /* v5: rename a room (including the lobby) and sync the new name to clients. */
  renameRoom(roomId, rawName) {
    const room = this.rooms.get(roomId);
    if (!room) throw new Error('房间不存在');
    const name = String(rawName || '').trim().slice(0, 30);
    if (!name) throw new Error('房间名称不能为空');
    room.name = name;
    this.db.upsertRoom(room);
    const env = P.makeEnvelope(P.MSG.ROOM_UPDATED, {
      room: this.roomSummary(room), ts: Date.now()
    });
    for (const u of this.users.values()) {
      try { u.session.send(env); } catch (e) { /* session went away */ }
    }
    this.log(`房间已改名 ${roomId} → ${name}`);
    return this.roomSummary(room);
  }

  /* v5: only formal users leave traces in the identity chain. */
  chainUserEvent(user, action, payload) {
    if (!user || !user.permanent || user.isBot || String(user.uid).indexOf('bot_') === 0) return false;
    this.ledger.append(action, payload);
    return true;
  }

  /* v5: change a nickname while online. Temporary users keep their random
   * timestamp suffix because the client sends the full composed name. */
  onNicknameChange(user, data) {
    const next = String((data && data.nickname) || '').trim().slice(0, P.LIMITS.MAX_USERNAME);
    if (!next) {
      user.session.error(P.ERR.NICKNAME_INVALID, '昵称不能为空');
      return;
    }
    user.username = next;
    user.session.username = next;
    if (this.users.get(user.uid) === user) this.users.get(user.uid).username = next;
    this.identity.setFlag(user.uid, 'nickname', next);
    user.session.send(P.makeEnvelope(P.MSG.NICKNAME_UPDATED, {
      nickname: next, permanent: !!user.permanent, ts: Date.now()
    }));
    for (const roomId of user.rooms) {
      const room = this.rooms.get(roomId);
      if (room) {
        this.broadcastMembers(room);
        this.broadcastNotice(room, `${next} 更新了昵称`, user.uid);
      }
    }
    this.log(`用户在线改名 uid=${user.uid.slice(0, 12)}… → ${next}`);
  }

  onRegister(session, data) {
    try {
      if (session.authenticated || !session.pending) throw new Error('bad state');
      if (Date.now() - session.pending.createdAt > 120000) throw new Error('challenge expired');
      if (!data || !data.blob) throw new Error('missing blob');

      const inner = JSON.parse(C.hybridDecrypt(this.keys.privateKey, data.blob));
      const { username, browserId, ts, nonce, challenge, clientPub, sig } = inner;
      if (typeof username !== 'string' || !username.trim() || username.length > P.LIMITS.MAX_USERNAME) throw new Error('bad username');
      if (typeof browserId !== 'string' || !browserId || typeof ts !== 'number' ||
          typeof nonce !== 'string' || typeof challenge !== 'string' ||
          typeof clientPub !== 'string' || typeof sig !== 'string') throw new Error('bad fields');
      if (challenge !== session.pending.challenge) throw new Error('challenge mismatch');
      if (Math.abs(Date.now() - ts) > P.CRYPTO.TIMESTAMP_TOLERANCE_MS) throw new Error('timestamp skew');
      if (this.usedNonces.has(nonce)) throw new Error('nonce reuse');

      const pub = forge.pki.publicKeyFromPem(clientPub);
      if (!C.verifyCanonical(pub, C.canonicalRegister(inner), sig)) throw new Error('bad signature');

      let uid, nickname = username.trim(), permanent = false;
      if (inner.resume) {
        const r = this.identity.verifyResume(inner, session.pending.challenge);
        if (!r || r.error) {
          this.log(`身份恢复失败: ${r ? r.error : 'not found'}`);
          session.error(P.ERR.IDENTITY_INVALID,
            r && r.error === 'banned' ? '该身份已被禁止登录' : '身份文件校验失败，请检查密钥与服务器记录');
          return;
        }
        uid = r.uid;
        nickname = r.nickname || nickname;
        permanent = true;
      } else {
        uid = C.makeUid(inner, session.pending.salt);
        if (this.users.has(uid)) uid = C.sha256Hex(uid + '|' + C.b64(C.randomBytes(8)));
        permanent = !!inner.permanent;
        this.identity.register({
          uid, nickname, pubkey: clientPub, browserId, permanent
        });
      }
      this.usedNonces.add(nonce);

      /* One online session per identity: a new login with the same identity
       * file takes over and closes the previous socket. */
      const previous = this.users.get(uid);
      if (previous && previous.session !== session) {
        try {
          previous.session.send(P.makeEnvelope(P.MSG.NOTICE,
            { text: '该身份已在其他位置登录，本连接已下线', ts: Date.now() }));
          previous.session.close();
        } catch (e) { /* noop */ }
        this.log(`身份 ${uid.slice(0, 12)}… 被新会话接管`);
      }

      session.authenticated = true;
      session.uid = uid;
      session.username = nickname;
      session.clientPubPem = clientPub;
      session.pending = null;

      const user = {
        uid, username: nickname, clientPubPem: clientPub,
        session, rooms: new Set(), lastSeq: new Map(), dmLastSeq: new Map(),
        joinedAt: Date.now(), permanent
      };
      this.users.set(uid, user);
      this.addMember(user, this.lobby);

      session.send(P.makeEnvelope(P.MSG.REGISTERED, {
        uid,
        username: nickname,
        permanent,
        room: this.roomSummary(this.lobby),
        wrappedLobbyKey: C.wrapKey(pub, this.lobby.key),
        members: this.memberList(this.lobby),
        server: {
          name: this.config.name,
          version: P.RELEASE_VERSION,
          copyright: this.config.copyright || P.DEFAULT_COPYRIGHT,
          copyrightLink: this.config.copyrightLink || '',
          maxRooms: this.config.maxRooms,
          historyEnabled: this.config.historyEnabled,
          allowedFileExts: P.ALLOWED_FILE_EXTS,
          maxFileBytes: P.LIMITS.MAX_FILE_BYTES
        }
      }));
      this.broadcastMembers(this.lobby);
      this.broadcastNotice(this.lobby, `${nickname} 加入了聊天室`, uid);
      this.log(`注册成功 ${nickname} (${uid.slice(0, 12)}…) 持久身份=${permanent}`);
    } catch (e) {
      this.log(`注册失败: ${e.message}`);
      session.error(P.ERR.REGISTER_FAILED, '身份认证失败');
    }
  }

  onRoomCreate(user, data) {
    if (user.rooms.size >= P.LIMITS.MAX_ACTIVE_ROOMS) {
      user.session.error(P.ERR.ROOM_LIMIT,
        `最多同时加入 ${P.LIMITS.MAX_ACTIVE_ROOMS} 个房间，请先关闭一个房间标签`);
      return;
    }
    const name = String((data && data.name) || '新房间').slice(0, 30);
    const isPrivate = !!(data && data.private);
    const e2ee = !!(data && data.e2ee);
    const wrappedKeys = e2ee && data.wrappedKeys && typeof data.wrappedKeys === 'object'
      ? data.wrappedKeys : null;
    if (e2ee && (!wrappedKeys || !wrappedKeys[user.uid])) {
      user.session.error(P.ERR.BAD_ENVELOPE, '加密房间缺少会话密钥封装');
      return;
    }

    const room = this.createRoom(name, isPrivate && !e2ee ? true : !!isPrivate, null,
      { e2ee, wrappedKeys, createdBy: user.uid });

    let targets;
    if (e2ee) targets = Object.keys(wrappedKeys).filter(uid => uid !== user.uid);
    else targets = Array.isArray(data && data.members) ? data.members.slice(0, 8) : [];

    this.addMember(user, room);
    this.deliverRoomKey(user, room);
    for (const uid of targets) {
      const target = this.users.get(uid);
      if (!target || uid === user.uid) continue;
      if (!this.identity.canJoin(uid, room.id)) continue;
      if (target.rooms.size >= P.LIMITS.MAX_ACTIVE_ROOMS) continue;
      this.addMember(target, room);
      this.deliverRoomKey(target, room);
    }
    this.broadcastMembers(room);
    this.chainUserEvent(user, 'room_create', {
      roomId: room.id, name: room.name, by: user.uid, private: room.private, e2ee: room.e2ee
    });
    this.log(`房间创建 ${room.name} (${room.id}) 私有=${isPrivate} E2EE=${e2ee} 发起人=${user.username}`);
  }

  onRoomJoin(user, data) {
    const raw = String((data && data.invite) || '').trim();
    let room = null, fullCode = null;

    if (raw.slice(0, P.INVITE_PREFIX.length) === P.INVITE_PREFIX) {
      fullCode = this.invite.parse(raw);
      if (!fullCode || !this.invite.verify(fullCode)) {
        user.session.error(P.ERR.INVITE_INVALID, '邀请码无效、被篡改或已过期');
        return;
      }
      room = this.rooms.get(fullCode.roomId);
      if (!room || (room.pin && room.pin !== fullCode.pin)) {
        user.session.error(P.ERR.ROOM_NOT_FOUND, '邀请码指向的房间不存在或邀请码已失效');
        return;
      }
    } else if (data && data.roomId) {
      room = this.rooms.get(data.roomId);
    } else if (raw) {
      const code = raw.toUpperCase();
      room = Array.from(this.rooms.values()).find(r => r.pin && r.pin === code);
    }
    if (!room) { user.session.error(P.ERR.ROOM_NOT_FOUND, '房间或邀请码不存在'); return; }

    if (!this.identity.canJoin(user.uid, room.id)) {
      user.session.error(P.ERR.ROOM_FORBIDDEN, '没有加入该房间的权限');
      return;
    }
    if (room.private && !fullCode && room.pin !== raw.toUpperCase()) {
      user.session.error(P.ERR.FORBIDDEN, '私有房间需要有效邀请码');
      return;
    }
    if (room.e2ee && !(room.wrappedKeys && room.wrappedKeys[user.uid])) {
      user.session.error(P.ERR.FORBIDDEN, '端到端加密房间仅限受邀成员');
      return;
    }
    if (room.members.size >= this.config.maxMembersPerRoom) {
      user.session.error(P.ERR.ROOM_FULL, '房间人数已满');
      return;
    }
    if (user.rooms.has(room.id)) { this.deliverRoomKey(user, room); return; }
    if (user.rooms.size >= P.LIMITS.MAX_ACTIVE_ROOMS) {
      user.session.error(P.ERR.ROOM_LIMIT,
        `最多同时加入 ${P.LIMITS.MAX_ACTIVE_ROOMS} 个房间，请先关闭一个房间标签`);
      return;
    }
    this.addMember(user, room);
    this.deliverRoomKey(user, room);
    this.broadcastMembers(room);
    this.broadcastNotice(room, `${user.username} 加入了房间`, user.uid);
  }

  onRoomLeave(user, data) {
    const room = this.rooms.get(data && data.roomId);
    if (!room || !user.rooms.has(room.id)) return;
    if (room.id === P.LOBBY_ID) return;
    room.members.delete(user.uid);
    user.rooms.delete(room.id);
    user.session.notice(`已离开 ${room.name}`);
    this.broadcastMembers(room);
    this.broadcastNotice(room, `${user.username} 离开了房间`, user.uid);
  }

  /* ---------- v5.2: drag-to-room invite (member list -> room tab) ---------- */

  onRoomDragInvite(user, data) {
    const roomId = String((data && data.room) || '');
    const toUid = String((data && data.to) || '');
    const room = this.rooms.get(roomId);
    if (!room) { user.session.error(P.ERR.ROOM_NOT_FOUND, '目标房间不存在'); return; }
    if (roomId === P.LOBBY_ID) { user.session.error(P.ERR.DRAG_INVITE_INVALID, '大厅无需邀请，所有人都在线时可自由交流'); return; }
    if (!user.rooms.has(roomId)) { user.session.error(P.ERR.FORBIDDEN, '你不在该房间内，无法邀请成员'); return; }
    if (room.e2ee) { user.session.error(P.ERR.FORBIDDEN, '端到端加密房间暂不支持拖拽邀请，请使用邀请码'); return; }
    if (toUid === user.uid) { user.session.error(P.ERR.DRAG_INVITE_INVALID, '不能邀请自己'); return; }
    const target = this.users.get(toUid);
    if (!target) { user.session.error(P.ERR.DIRECT_TARGET_INVALID, '对方当前不在线'); return; }
    if (target.isBot || String(toUid).indexOf('bot_') === 0) { user.session.error(P.ERR.DRAG_INVITE_INVALID, '机器人不支持房间邀请'); return; }
    if (room.members.has(toUid)) { user.session.notice(`${target.username} 已在房间内`); return; }
    if (room.members.size >= this.config.maxMembersPerRoom) { user.session.error(P.ERR.ROOM_FULL, '房间人数已满'); return; }
    if (target.rooms.size >= P.LIMITS.MAX_ACTIVE_ROOMS) { user.session.error(P.ERR.ROOM_LIMIT, '对方同时打开的房间已达上限'); return; }
    if (!this.identity.canJoin(toUid, room.id)) { user.session.error(P.ERR.ROOM_FORBIDDEN, '对方被禁止加入该房间'); return; }

    const token = C.b64(C.randomBytes(12)).replace(/[^a-zA-Z0-9]/g, '').slice(0, 16);
    this.dragInvites.set(token, {
      roomId, roomName: room.name, inviterUid: user.uid, inviterName: user.username,
      targetUid: toUid, ts: Date.now()
    });
    target.session.send(P.makeEnvelope(P.MSG.ROOM_INVITE_OFFER, {
      token, roomId, roomName: room.name,
      inviter: user.uid, inviterName: user.username,
      inviterPermanent: !!user.permanent, private: !!room.private, ts: Date.now()
    }));
    user.session.notice(`已向 ${target.username} 发出加入「${room.name}」的邀请，等待确认…`);
  }

  onRoomInviteReply(user, data) {
    const token = String((data && data.token) || '');
    const rec = this.dragInvites.get(token);
    if (!rec || rec.targetUid !== user.uid) {
      user.session.error(P.ERR.INVITE_INVALID, '邀请不存在或不是发给你的');
      return;
    }
    this.dragInvites.delete(token);
    const inviter = this.users.get(rec.inviterUid);
    if (Date.now() - rec.ts > (P.LIMITS.DRAG_INVITE_TTL_MS || 60000)) {
      user.session.error(P.ERR.INVITE_INVALID, '邀请已过期（60 秒未确认）');
      if (inviter) inviter.session.notice(`${user.username} 未在有效期内确认房间邀请`);
      return;
    }
    if (!data || !data.accept) {
      if (inviter) inviter.session.notice(`${user.username} 拒绝了加入「${rec.roomName}」的邀请`);
      user.session.notice(`已拒绝加入「${rec.roomName}」`);
      return;
    }
    const room = this.rooms.get(rec.roomId);
    if (!room) { user.session.error(P.ERR.ROOM_NOT_FOUND, '房间已被删除'); return; }
    if (room.members.size >= this.config.maxMembersPerRoom) { user.session.error(P.ERR.ROOM_FULL, '房间人数已满'); return; }
    if (user.rooms.size >= P.LIMITS.MAX_ACTIVE_ROOMS) {
      user.session.error(P.ERR.ROOM_LIMIT, `你同时打开的房间已达上限（${P.LIMITS.MAX_ACTIVE_ROOMS}）`);
      return;
    }
    if (!user.rooms.has(room.id)) {
      this.addMember(user, room);
      this.broadcastNotice(room, `${user.username} 接受邀请加入了房间`, user.uid);
    }
    this.deliverRoomKey(user, room);
    this.broadcastMembers(room);
    if (inviter) inviter.session.notice(`${user.username} 已接受邀请，进入「${room.name}」`);
    this.chainUserEvent(user, 'room_join_invite', {
      roomId: room.id, roomName: room.name, invitedBy: rec.inviterUid
    });
  }

  onMessage(user, data) {
    const { room: roomId, seq, iv, ct, tag, ts } = data || {};
    const room = this.rooms.get(roomId);
    if (!room || !user.rooms.has(roomId)) { user.session.error(P.ERR.NOT_IN_ROOM, '未在目标房间'); return; }
    if (!this.identity.canSpeak(user.uid)) {
      user.session.error(P.ERR.MUTED, '您已被禁止发言');
      return;
    }
    if (!Number.isInteger(seq) || seq <= 0 || typeof iv !== 'string' ||
        typeof ct !== 'string' || typeof tag !== 'string' || typeof ts !== 'number') {
      user.session.error(P.ERR.BAD_ENVELOPE, '消息字段不合法'); return;
    }
    if (ct.length > this.config.maxMessageBytes) { user.session.error(P.ERR.BAD_ENVELOPE, '消息过长'); return; }
    const last = user.lastSeq.get(roomId) || 0;
    if (seq <= last) { user.session.error(P.ERR.REPLAY, '消息序号重复'); return; }

    const now = Date.now();
    if (now - user.session.windowStart > 1000) {
      user.session.windowStart = now;
      user.session.messageCount = 0;
    }
    if (++user.session.messageCount > 30) { user.session.error(P.ERR.RATE_LIMIT, '发送过于频繁'); return; }
    const aad = messageAad(roomId, user.uid, seq, ts);

    if (room.e2ee) {
      /* The server has no key for E2EE private rooms: it stores and forwards
       * ciphertext only, and can never read these messages. */
      this.db.insertArchived({
        room: roomId, fromUid: user.uid, fromName: user.username, seq,
        iv, ct, tag, aad, ts, e2ee: true
      });
    } else {
      let parsed;
      try {
        const plain = C.aesDecrypt(room.key, { iv, ct, tag }, aad);
        parsed = JSON.parse(plain);
      } catch (e) {
        user.session.error(P.ERR.BAD_ENVELOPE, '消息校验失败');
        return;
      }
      if (!parsed || typeof parsed.text !== 'string' || parsed.text.length > 4000) {
        user.session.error(P.ERR.BAD_ENVELOPE, '消息内容不合法'); return;
      }
      const archived = C.archiveEncrypt(
        this.keys.archiveKey,
        JSON.stringify({
          text: parsed.text, kind: parsed.kind || 'text',
          file: parsed.file || null, uid: user.uid, name: user.username, seq, ts
        }),
        roomId, seq, ts
      );
      this.db.insertArchived({
        room: roomId, fromUid: user.uid, fromName: user.username, seq,
        iv: archived.iv, ct: archived.ct, tag: archived.tag,
        aad: C.ARCHIVE_AAD_PREFIX + [roomId, seq, ts].join('|'), ts, e2ee: false
      });
      /* E2EE rooms are never observed: the server has no key and no plaintext. */
      for (const fn of this.messageHooks) {
        try { fn({ room, user, text: parsed.text, isBot: !!user.isBot }); }
        catch (e) { this.log('消息观察者异常: ' + e.message); }
      }
    }

    user.lastSeq.set(roomId, seq);
    const out = P.makeEnvelope(P.MSG.MESSAGE_BROADCAST, {
      room: roomId, seq, iv, ct, tag, ts,
      from: user.uid, fromName: user.username, fromPermanent: !!user.permanent
    });
    for (const uid of room.members) {
      if (uid === user.uid) continue;
      const target = this.users.get(uid);
      if (target) target.session.send(out);
    }
  }

  /* v5: lobby direct chat — no room is created. The sender generates a fresh
   * AES key, wraps it with the recipient's public key and encrypts the text.
   * The server only sees/forwards ciphertext, stores it as an E2EE archive row
   * and can never decrypt it (nor can bots observe it). */
  /* v5.4: in-room WebRTC signaling relay. The server ONLY forwards small JSON
   * envelopes (SDP descriptions / ICE candidates) between two room members and
   * never inspects or stores media. End-to-end encryption of the call is
   * provided by the browser's DTLS-SRTP, so the relay learns nothing. */
  onWebrtcSignal(user, data) {
    const { room: roomId, to, signal } = data || {};
    const room = this.rooms.get(roomId);
    if (!room || !user.rooms.has(roomId)) {
      user.session.error(P.ERR.NOT_IN_ROOM, '未在目标房间'); return;
    }
    if (roomId === P.LOBBY_ID) {
      user.session.error(P.ERR.FORBIDDEN, '大厅不支持视频通话'); return;
    }
    if (!this.identity.canSpeak(user.uid)) {
      user.session.error(P.ERR.MUTED, '您已被禁止发言'); return;
    }
    if (!to || to === user.uid) {
      user.session.error(P.ERR.BAD_ENVELOPE, '视频信令目标无效'); return;
    }
    const target = this.users.get(to);
    if (!target || !room.members.has(to) || !target.rooms.has(roomId)) {
      user.session.error(P.ERR.DIRECT_TARGET_INVALID, '对方不在线或不在同一房间'); return;
    }
    if (!signal || typeof signal !== 'object' || !signal.kind) {
      user.session.error(P.ERR.BAD_ENVELOPE, '视频信令格式不合法'); return;
    }
    if (JSON.stringify(signal).length > P.LIMITS.MAX_WEBRTC_SIGNAL_BYTES) {
      user.session.error(P.ERR.BAD_ENVELOPE, '视频信令过大'); return;
    }
    /* Light rate limit so a misbehaving client cannot flood the relay. */
    const now = Date.now();
    if (now - (user.session.sigWindow || 0) > 1000) {
      user.session.sigWindow = now; user.session.sigCount = 0;
    }
    user.session.sigCount = (user.session.sigCount || 0) + 1;
    if (user.session.sigCount > 200) {
      user.session.error(P.ERR.RATE_LIMIT, '视频信令过于频繁'); return;
    }
    target.session.send(P.makeEnvelope(P.MSG.WEBRTC, {
      room: roomId, from: user.uid, fromName: user.username, signal
    }));
  }

  onDirectMessage(user, data) {
    const { room: roomId, to, seq, ts, iv, ct, tag, wrappedKey } = data || {};
    const room = this.rooms.get(roomId);
    if (!room || !user.rooms.has(roomId)) {
      user.session.error(P.ERR.NOT_IN_ROOM, '未在目标房间'); return;
    }
    if (!this.identity.canSpeak(user.uid)) {
      user.session.error(P.ERR.MUTED, '您已被禁止发言'); return;
    }
    const target = this.users.get(to);
    if (!target || to === user.uid || !room.members.has(to) || !target.rooms.has(roomId)) {
      user.session.error(P.ERR.DIRECT_TARGET_INVALID, '私聊对象不在线或不在同一房间');
      return;
    }
    if (!Number.isInteger(seq) || seq <= 0 || typeof iv !== 'string' ||
        typeof ct !== 'string' || typeof tag !== 'string' || typeof ts !== 'number' ||
        typeof wrappedKey !== 'string') {
      user.session.error(P.ERR.BAD_ENVELOPE, '私聊字段不合法'); return;
    }
    if (ct.length > this.config.maxMessageBytes) {
      user.session.error(P.ERR.BAD_ENVELOPE, '消息过长'); return;
    }
    if (!user.dmLastSeq) user.dmLastSeq = new Map();
    if (seq <= (user.dmLastSeq.get(roomId) || 0)) {
      user.session.error(P.ERR.REPLAY, '消息序号重复'); return;
    }
    const now = Date.now();
    if (now - user.session.windowStart > 1000) {
      user.session.windowStart = now;
      user.session.messageCount = 0;
    }
    if (++user.session.messageCount > 30) {
      user.session.error(P.ERR.RATE_LIMIT, '发送过于频繁'); return;
    }

    const aad = ['dm', roomId, user.uid, seq, ts].join('|');
    this.db.insertArchived({
      room: roomId, fromUid: user.uid, fromName: user.username, seq,
      iv, ct, tag, aad, ts, e2ee: true
    });
    user.dmLastSeq.set(roomId, seq);

    target.session.send(P.makeEnvelope(P.MSG.DIRECT_MESSAGE_BROADCAST, {
      room: roomId, to, seq, ts, iv, ct, tag, wrappedKey,
      from: user.uid, fromName: user.username, fromPermanent: !!user.permanent
    }));
    this.log(`大厅私聊 ${user.username} → ${target.username} (${roomId}) 密文 ${ct.length}B`);
  }

  onHistory(user, data) {
    const room = this.rooms.get(data && data.roomId);
    if (!room || !user.rooms.has(room.id)) { user.session.error(P.ERR.NOT_IN_ROOM); return; }
    if (!this.config.historyEnabled) {
      user.session.send(P.makeEnvelope(P.MSG.HISTORY_DATA, { room: room.id, messages: [] }));
      return;
    }
    const rows = this.db.getHistory(room.id, data.limit || 50);
    const messages = [];
    for (const r of rows) {
      try {
        if (r.e2ee) {
          messages.push({
            room: r.room, seq: r.seq, ts: r.ts, from: r.from_uid, fromName: r.from_name,
            iv: r.iv, ct: r.ct, tag: r.tag, e2ee: true
          });
          continue;
        }
        const plain = C.archiveDecrypt(this.keys.archiveKey, {
          iv: r.iv, ct: r.ct, tag: r.tag, room: r.room, seq: r.seq, ts: r.ts
        });
        const obj = JSON.parse(plain);
        const enc = C.aesEncrypt(
          room.key,
          JSON.stringify({ text: obj.text, kind: obj.kind || 'text', file: obj.file || null }),
          messageAad(r.room, r.from_uid, r.seq, r.ts)
        );
        messages.push(Object.assign({
          room: r.room, seq: r.seq, ts: r.ts, from: r.from_uid, fromName: r.from_name
        }, enc));
      } catch (e) { /* skip corrupted archive rows */ }
    }
    user.session.send(P.makeEnvelope(P.MSG.HISTORY_DATA, { room: room.id, messages }));
  }

  /* ---------- admin operations ---------- */

  deleteRoom(roomId) {
    if (roomId === P.LOBBY_ID) throw new Error('不能删除大厅');
    const room = this.rooms.get(roomId);
    if (!room) throw new Error('房间不存在');
    for (const uid of room.members) {
      const u = this.users.get(uid);
      if (u) {
        u.rooms.delete(roomId);
        u.session.send(P.makeEnvelope(P.MSG.ROOM_DELETED, { room: roomId, name: room.name }));
      }
    }
    this.rooms.delete(roomId);
    this.db.deleteRoom(roomId);
    this.files.deleteRoom(roomId);
    this.ledger.append('room_delete', { roomId, name: room.name });
    this.log(`房间已删除 ${room.name} (${roomId})`);
    return { ok: true, roomId };
  }

  applyUserAction(uid, action, value) {
    const rec = this.identity.setFlag(uid, action, value);
    if (!rec) throw new Error('身份不存在');
    const user = this.users.get(uid);
    if (user) {
      user.session.send(P.makeEnvelope(P.MSG.USER_STATUS, {
        banned: rec.banned, muted: rec.muted, grants: rec.grants
      }));
      if (rec.banned) { try { user.session.close(); } catch (e) { /* noop */ } }
    }
    return rec;
  }

  makeRoomInvite(roomId, inviterUid, inviterName, host, port) {
    const room = this.rooms.get(roomId);
    if (!room) throw new Error('房间不存在');
    const info = this.serverInfo();
    const code = this.invite.make({
      host: host || info.host,
      port: port || info.port,
      roomId: room.id,
      roomName: room.name,
      pin: room.pin || '',
      inviterUid: inviterUid || 'admin',
      inviterName: inviterName || '管理员',
      private: room.private
    });
    if (inviterUid === 'admin') {
      this.ledger.append('invite_issued', { roomId, by: 'admin' });
    } else {
      this.chainUserEvent(this.users.get(inviterUid), 'invite_issued',
        { roomId, by: inviterUid });
    }
    return code;
  }

  adminRoomMessages(roomId, limit) {
    const room = this.rooms.get(roomId);
    if (room && room.e2ee) {
      return {
        e2ee: true,
        note: '端到端加密私聊：服务端不持有会话密钥，仅能提供元数据与密文',
        messages: this.db.getHistory(roomId, limit).map(r => ({
          seq: r.seq, ts: r.ts, from: r.from_name, uid: r.from_uid,
          ciphertextBytes: String(r.ct || '').length, text: '[端到端加密内容，服务端不可解密]'
        }))
      };
    }
    return { e2ee: false, messages: this.adminHistory(roomId, limit) };
  }

  /* ---------- stats ---------- */

  stats() {
    return {
      name: this.config.name,
      version: P.RELEASE_VERSION,
      copyright: this.config.copyright || P.DEFAULT_COPYRIGHT,
      copyrightLink: this.config.copyrightLink || '',
      startedAt: this.startedAt,
      uptimeSec: Math.round((Date.now() - this.startedAt) / 1000),
      fingerprint: this.keys.fingerprint,
      publicKey: this.keys.publicKeyPem,
      adminFingerprint: this.admin ? this.admin.fingerprint : null,
      clients: this.sessions.size,
      users: this.users.size,
      bots: Array.from(this.users.values()).filter(u => u.isBot).length,
      rooms: Array.from(this.rooms.values()).map(r => this.roomSummary(r)),
      usersList: Array.from(this.users.values()).map(u => ({
        uid: u.uid, username: u.username, rooms: u.rooms.size,
        permanent: u.permanent, bot: !!u.isBot, online: true
      })),
      onlineUids: Array.from(this.users.keys()),
      chainPolicy: 'formal-users-only',
      identities: this.identity.list().length,
      ledger: { blocks: this.ledger.head() ? this.ledger.head().idx + 1 : 0 },
      archive: this.db.counts()
    };
  }

  adminHistory(room, limit) {
    const rows = this.db.getHistory(room, limit);
    return rows.map(r => {
      if (r.e2ee) {
        return { room: r.room, seq: r.seq, ts: r.ts, from: r.from_name, uid: r.from_uid,
          text: '[端到端加密内容，服务端不可解密]' };
      }
      try {
        const obj = JSON.parse(C.archiveDecrypt(this.keys.archiveKey, {
          iv: r.iv, ct: r.ct, tag: r.tag, room: r.room, seq: r.seq, ts: r.ts
        }));
        return { room: r.room, seq: r.seq, ts: r.ts, from: obj.name, uid: obj.uid,
          text: obj.text, kind: obj.kind || 'text', file: obj.file || null };
      } catch (e) {
        return { room: r.room, seq: r.seq, ts: r.ts, from: r.from_name, text: '[解密失败]' };
      }
    });
  }
}

module.exports = { Hub, messageAad };
