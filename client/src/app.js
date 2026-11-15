/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
(function (root) {
  'use strict';
  var P = root.ChatProtocol;
  var C = root.ChatCrypto;
  var ID = root.ChatIdentity;
  var $ = function (id) { return document.getElementById(id); };

  var state = {
    username: '', host: '', port: 8080, proxy: '',
    transport: null, connected: false, manualClose: false,
    privateKey: null, publicKeyPem: '', privateKeyPem: '',
    challenge: '', salt: '', serverPubPem: '', fingerprint: '', uid: '',
    keys: {}, rooms: [], currentRoom: '', seq: {}, dmSeq: {},
    openRooms: [], roomState: {},
    historyEnabled: true, reconnectTimer: null,
    identityFile: null, saveIdentity: false, savePassword: '',
    vaultPasswords: {},
    pendingInvite: null, muted: false, banned: false,
    fileCache: {}, preview: null,
    /* v5 */
    serverName: 'ChatRoom', copyright: 'CJS flshw@126.com', copyrightLink: '',
    permanent: false, tempStamp: '', baseNickname: '',
    directTo: null, directMode: false,
    /* v5.2: drag-to-room invites */
    dragUid: '', dragName: '', inviteQueue: [], inviteBusy: false,
    /* v5.4: in-room mesh video call */
    call: null
  };

  /* ---------- helpers ---------- */

  function loginStatus(text, kind) {
    var el = $('login-status');
    el.textContent = text || '';
    el.className = 'login-status' + (kind ? ' ' + kind : '');
  }
  function setConn(ok, text) {
    $('conn-dot').className = 'dot ' + (ok ? 'on' : 'off');
    $('conn-text').textContent = text || (ok ? '已连接' : '未连接');
  }
  function httpBase() {
    if (state.proxy) return state.proxy.replace(/\/relay\/?$/, '').replace(/\/$/, '');
    /* HTTPS page -> HTTPS API, otherwise mixed content is blocked by browsers. */
    var secure = (window.location && location.protocol === 'https:');
    var scheme = secure ? 'https://' : 'http://';
    /* Omit the port when it is the scheme's standard port (443/80) so URLs stay
     * clean and match what visitors type. */
    var standard = (secure && state.port == 443) || (!secure && state.port == 80);
    return scheme + state.host + (standard ? '' : (':' + state.port));
  }
  function isVoiceExt(ext) {
    return P.VOICE_EXTS.indexOf(String(ext || '').toLowerCase()) !== -1;
  }
  /* Voice clips are a room feature: never available in the lobby, private
   * (direct) mode, while muted/banned, or before a room key is available. */
  function voiceAllowed() {
    return !!(state.connected && state.uid && state.currentRoom &&
      state.currentRoom !== P.LOBBY_ID && !state.directMode &&
      !state.muted && !state.banned && state.keys[state.currentRoom]);
  }
  function updateVoiceUI() {
    var btn = $('btn-voice');
    if (!btn) return;
    var allowed = voiceAllowed();
    btn.disabled = !allowed;
    btn.classList.toggle('recording', !!state.recording);
    btn.textContent = state.recording ? '停止录音' : '语音';
    btn.title = allowed
      ? (state.recording ? '点击结束并发送加密语音' : '仅房间内可用，点击开始录音')
      : '语音仅在非大厅房间、公聊模式下可用';
  }
  function setComposerEnabled(ok) {
    $('msg-input').disabled = !ok;
    $('btn-send').disabled = !ok;
    $('btn-file').disabled = !ok || state.directMode;
    /* 说明类文字收进「附件」按钮的 title（悬停可见），不再常驻聊天区底部。 */
    var hint = ok
      ? (state.directMode
        ? '私聊模式下附件与语音不可用；切回「公聊」即可发送'
        : (voiceAllowed()
          ? '房间内可发送加密语音条（最长 60 秒）；附件最大 8 MB，端到端加密'
          : '语音仅房间内可用；附件支持 png / pdf / zip / 音频，最大 8 MB，端到端加密'))
      : '你已被禁止发言或上传文件';
    $('btn-file').title = ok ? (hint + '。点击选择，或直接把文件拖进聊天窗口') : hint;
    updateVoiceUI();
    updateVideoUI();
  }

  /* ---------- v5: branding, temporary-user stamps, direct chat ---------- */

  function makeTempStamp() {
    var t = Date.now().toString(36).slice(-4).toUpperCase();
    var r = C.b64(C.randomBytes(2)).replace(/[^A-Z0-9]/gi, '').slice(0, 2).toUpperCase();
    return (t + r).slice(0, 6);
  }
  /* Temporary nicknames carry a random timestamp suffix; renaming keeps it. */
  function composeNickname(base, formal) {
    base = String(base || '').trim();
    if (formal) return base.slice(0, P.LIMITS.MAX_USERNAME);
    var sep = P.TEMP_NAME_SEPARATOR || '·';
    var stamp = state.tempStamp || makeTempStamp();
    state.tempStamp = stamp;
    var room = P.LIMITS.MAX_USERNAME - stamp.length - sep.length;
    return (room > 0 ? base.slice(0, room) : base.slice(0, P.LIMITS.MAX_USERNAME)) +
      sep + stamp;
  }
  function applyServerBrand(info) {
    if (!info) return;
    state.serverName = info.name || state.serverName;
    state.copyright = info.copyright || P.DEFAULT_COPYRIGHT;
    state.copyrightLink = info.copyrightLink || '';
    $('app-title').textContent = state.serverName;
    $('login-title').textContent = state.serverName;
    document.title = state.serverName + ' · 局域网加密聊天室';
    /* 版权信息置于顶栏聊天室名称之后，取代原先的底部栏。 */
    var foot = $('app-copyright');
    foot.textContent = '';
    if (state.copyrightLink) {
      var a = document.createElement('a');
      a.href = state.copyrightLink;
      a.target = '_blank'; a.rel = 'noopener noreferrer';
      a.textContent = state.copyright;
      foot.appendChild(a);
    } else {
      foot.textContent = state.copyright;
    }
    $('login-copyright').textContent = state.copyright;
  }
  function setDirectMode(on) {
    state.directMode = !!on && !!state.directTo;
    $('btn-mode-public').classList.toggle('on', !state.directMode);
    $('btn-mode-private').classList.toggle('on', state.directMode);
    $('dm-chip').classList.toggle('hidden', !state.directMode);
    $('dm-target').textContent = state.directMode ? state.directTo.username : '';
    $('btn-mode-private').title = state.directMode
      ? '私聊内容用对方公钥单独封装，服务端只转发密文'
      : '点击右侧成员列表中的用户名可直接私聊';
    $('msg-input').placeholder = state.directMode
      ? '发送给 ' + state.directTo.username + '（仅对方可见）…'
      : '输入消息，Enter 发送，Shift+Enter 换行';
    $('btn-file').disabled = state.directMode || state.muted || state.banned;
    setComposerEnabled(!state.muted && !state.banned);
  }
  function clearDirectTarget() {
    state.directTo = null;
    state.directMode = false;
    setDirectMode(false);
    renderMembers();
  }
  function setDirectTarget(m) {
    if (m.uid === state.uid) return;
    state.directTo = {
      uid: m.uid, username: m.username, pubKey: m.pubKey,
      permanent: !!m.permanent
    };
    setDirectMode(true);
    renderMembers();
    sysMessage('已切换到与 ' + m.username + ' 的大厅私聊（不创建房间，内容仅双方可见）');
    if (window.innerWidth <= 760) toggleSidebar(false);
    $('msg-input').focus();
  }
  function humanSize(n) {
    return n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(1) + ' MB';
  }
  function mimeFor(ext) {
    var e = String(ext || '').toLowerCase();
    if (e === 'png') return 'image/png';
    if (e === 'pdf') return 'application/pdf';
    if (e === 'zip') return 'application/zip';
    if (e === 'webm') return 'audio/webm';
    if (e === 'ogg') return 'audio/ogg';
    if (e === 'm4a' || e === 'mp4') return 'audio/mp4';
    if (e === 'mp3') return 'audio/mpeg';
    if (e === 'wav') return 'audio/wav';
    return 'application/octet-stream';
  }
  function fileToBytes(file) {
    return file.arrayBuffer().then(function (buf) {
      var u = new Uint8Array(buf), out = [];
      for (var i = 0; i < u.length; i += 8192) {
        out.push(String.fromCharCode.apply(null, u.subarray(i, i + 8192)));
      }
      return out.join('');
    });
  }
  function bytesToBlob(bytes, mime) {
    var u = new Uint8Array(bytes.length);
    for (var i = 0; i < bytes.length; i++) u[i] = bytes.charCodeAt(i) & 0xff;
    return new Blob([u], { type: mime });
  }

  /* ---------- per-room state (v4: several rooms open at once) ---------- */

  function ensureRoomState(id) {
    if (!state.roomState[id]) {
      state.roomState[id] = { messages: [], members: [], unread: 0, historyLoaded: false };
    }
    return state.roomState[id];
  }
  function roomById(id) {
    for (var i = 0; i < state.rooms.length; i++) if (state.rooms[i].id === id) return state.rooms[i];
    return null;
  }
  function fallbackRoom(id) {
    return roomById(id) || {
      id: id, name: id === P.LOBBY_ID ? '大厅' : id,
      private: false, invite: null, e2ee: false, members: 0
    };
  }
  function upsertRoom(room) {
    var found = false;
    for (var i = 0; i < state.rooms.length; i++) {
      if (state.rooms[i].id === room.id) { state.rooms[i] = room; found = true; break; }
    }
    if (!found) state.rooms.push(room);
  }
  function currentRoomObject() { return fallbackRoom(state.currentRoom); }

  /* ---------- file helpers ---------- */

  function ensureFileBlob(file, roomId) {
    var id = file.id;
    if (state.fileCache[id]) return Promise.resolve(state.fileCache[id]);
    return fetch(httpBase() + '/api/file/get?id=' + encodeURIComponent(id) +
      '&uid=' + encodeURIComponent(state.uid)).then(function (r) { return r.json(); })
      .then(function (j) {
        if (!j.ok) throw new Error(j.error || '文件不存在');
        var key = state.keys[roomId];
        if (!key) throw new Error('缺少该房间的会话密钥');
        var bytes = C.aesDecryptBytes(key, j.blob, j.blob.aad);
        var blob = bytesToBlob(bytes, mimeFor(j.file.ext));
        var rec = { url: URL.createObjectURL(blob), blob: blob, name: j.file.name, ext: j.file.ext };
        state.fileCache[id] = rec;
        return rec;
      });
  }
  function openPreview(file, roomId) {
    $('preview-title').textContent = '文件预览 · ' + file.name;
    $('preview-body').textContent = '正在解密并加载…';
    $('preview-modal').classList.remove('hidden');
    ensureFileBlob(file, roomId).then(function (rec) {
      state.preview = rec;
      var body = $('preview-body');
      body.textContent = '';
      if (rec.ext === 'png') {
        var img = document.createElement('img');
        img.src = rec.url; img.alt = rec.name;
        body.appendChild(img);
      } else if (rec.ext === 'pdf') {
        var frame = document.createElement('iframe');
        frame.src = rec.url; frame.title = rec.name;
        body.appendChild(frame);
      } else {
        var p = document.createElement('div');
        p.className = 'sys'; p.textContent = 'zip 文件不支持在线预览，请下载后查看';
        body.appendChild(p);
      }
    }).catch(function (e) { $('preview-body').textContent = '加载失败: ' + e.message; });
  }
  function downloadFile(file, roomId) {
    ensureFileBlob(file, roomId).then(function (rec) {
      var a = document.createElement('a');
      a.href = rec.url; a.download = rec.name;
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
    }).catch(function (e) { sysMessage('下载失败: ' + e.message, state.currentRoom); });
  }

  /* ---------- message rendering ---------- */

  function appendMessageNode(m) {
    var box = $('messages');
    if (m.sys) {
      var srow = document.createElement('div');
      srow.className = 'sys';
      var sspan = document.createElement('span');
      sspan.textContent = m.text;
      srow.appendChild(sspan);
      box.appendChild(srow);
      box.scrollTop = box.scrollHeight;
      return;
    }
    var row = document.createElement('div');
    row.className = 'msg-row' + (m.self ? ' self' : '') + (m.direct ? ' direct' : '');
    var av = document.createElement('div');
    av.className = 'avatar';
    av.textContent = (m.name || '?').slice(0, 1).toUpperCase();
    var bubble = document.createElement('div');
    bubble.className = 'bubble';
    var meta = document.createElement('div');
    meta.className = 'msg-meta';
    var author = document.createElement('span');
    author.className = 'msg-author ' + (m.formal ? 'formal' : 'temp');
    author.textContent = m.name || '未知';
    var details = document.createElement('span');
    details.className = 'msg-time';
    var dt = new Date(m.ts || Date.now());
    details.textContent = ' · ' + (isNaN(dt.getTime()) ? '' : dt.toLocaleTimeString('zh-CN', { hour12: false })) +
      (m.direct ? (m.directTo ? ' · 私聊→' + m.directTo : ' · 私聊') : '') +
      (m.formal ? ' · 正式' : ' · 临时') +
      (m.history ? ' · 历史' : '') + (m.bot ? ' · 机器人' : '');
    meta.appendChild(author);
    meta.appendChild(details);
    bubble.appendChild(meta);

    if (m.file) {
      var card = document.createElement('div');
      card.className = 'file-card';
      var icon = document.createElement('span');
      icon.className = 'file-icon';
      var voice = isVoiceExt(m.file.ext);
      if (voice) card.className = 'file-card voice-card';
      icon.textContent = voice ? '♪' : String(m.file.ext || '?').toUpperCase().slice(0, 4);
      var info = document.createElement('div');
      info.className = 'file-name';
      info.textContent = voice
        ? ('语音消息' + (m.file.duration ? ' · ' + m.file.duration + ' 秒' : ''))
        : m.file.name;
      var size = document.createElement('span');
      size.className = 'file-size';
      size.textContent = humanSize(m.file.size || 0) + ' · 已加密';
      info.appendChild(size);
      var ops = document.createElement('div');
      ops.className = 'file-ops';
      if (m.file.ext === 'png' || m.file.ext === 'pdf') {
        var pv = document.createElement('button');
        pv.className = 'ghost'; pv.textContent = '预览';
        pv.addEventListener('click', function () { openPreview(m.file, m.room); });
        ops.appendChild(pv);
      }
      var dl = document.createElement('button');
      dl.className = 'ghost'; dl.textContent = '下载';
      dl.addEventListener('click', function () { downloadFile(m.file, m.room); });
      ops.appendChild(dl);
      card.appendChild(icon); card.appendChild(info); card.appendChild(ops);
      bubble.appendChild(card);

      if (voice) {
        var au = document.createElement('audio');
        au.className = 'voice-player'; au.controls = true; au.preload = 'none';
        bubble.appendChild(au);
        ensureFileBlob(m.file, m.room).then(function (rec) { au.src = rec.url; })
          .catch(function () { au.remove(); });
      }

      if (m.file.ext === 'png') {
        var thumb = document.createElement('img');
        thumb.className = 'file-thumb';
        thumb.alt = m.file.name;
        thumb.title = '点击放大预览';
        thumb.addEventListener('click', function () { openPreview(m.file, m.room); });
        bubble.appendChild(thumb);
        ensureFileBlob(m.file, m.room).then(function (rec) { thumb.src = rec.url; })
          .catch(function () { thumb.remove(); });
      }
    } else {
      var text = document.createElement('div');
      text.textContent = m.text;
      bubble.appendChild(text);
    }
    row.appendChild(av);
    row.appendChild(bubble);
    box.appendChild(row);
    box.scrollTop = box.scrollHeight;
  }

  /* Store every message in its own room so switching tabs never loses history. */
  function appendMessage(m, quiet) {
    /* v5: locally-originated messages inherit the current identity class so
     * formal users are not rendered with the temporary-user colour. */
    if (m.self && m.formal === undefined) m.formal = !!state.permanent;
    var roomId = m.room || state.currentRoom;
    var rs = ensureRoomState(roomId);
    rs.messages.push(m);
    if (rs.messages.length > P.LIMITS.MAX_ROOM_MESSAGES) rs.messages.shift();
    if (roomId === state.currentRoom) appendMessageNode(m);
    else if (!quiet) { rs.unread++; renderRoomTabs(); }
    else renderRoomTabs();
  }
  function sysMessage(text, roomId) {
    appendMessage({ sys: true, text: text, ts: Date.now(), room: roomId || state.currentRoom });
  }
  function renderMessages(roomId) {
    var box = $('messages');
    box.textContent = '';
    var rs = ensureRoomState(roomId);
    rs.messages.forEach(appendMessageNode);
    box.scrollTop = box.scrollHeight;
  }

  /* ---------- v5.1: background themes & picker ---------- */
  var BG_KEY = 'chatroom-bg-v5';
  var BG_CUSTOM_KEY = 'chatroom-bg-custom-v5';
  var BG_PRESETS = [
    { id: 'aurora', name: '晨雾蓝' },
    { id: 'ocean', name: '海空青' },
    { id: 'meadow', name: '青原绿' },
    { id: 'dusk', name: '暮紫粉' },
    { id: 'graphite', name: '石墨灰' }
  ];

  function bgRead() {
    try { return JSON.parse(localStorage.getItem(BG_KEY) || '{}'); } catch (e) { return {}; }
  }
  function bgCurrent() {
    var conf = bgRead();
    if (conf.type === 'custom') return 'custom';
    var known = BG_PRESETS.some(function (p) { return p.id === conf.id; });
    return known ? conf.id : 'aurora';
  }
  function bgApply() {
    var body = document.body;
    if (bgCurrent() === 'custom') {
      var img = '';
      try { img = localStorage.getItem(BG_CUSTOM_KEY) || ''; } catch (e) {}
      body.removeAttribute('data-bg');
      body.classList.add('custom-bg');
      body.style.backgroundImage = img ? 'url("' + img + '")' : 'none';
    } else {
      body.classList.remove('custom-bg');
      body.style.backgroundImage = '';
      body.setAttribute('data-bg', bgCurrent());
    }
  }
  function bgSave(conf) {
    try { localStorage.setItem(BG_KEY, JSON.stringify(conf)); } catch (e) {}
    bgApply();
  }
  function renderBgGrid() {
    var box = $('bg-grid');
    box.textContent = '';
    var cur = bgCurrent();
    BG_PRESETS.forEach(function (p) {
      var sw = document.createElement('div');
      sw.className = 'bg-swatch s-' + p.id + (cur === p.id ? ' on' : '');
      sw.title = p.name;
      var name = document.createElement('span');
      name.className = 'bs-name';
      name.textContent = p.name;
      sw.appendChild(name);
      sw.addEventListener('click', function () { bgSave({ type: 'preset', id: p.id }); renderBgGrid(); });
      box.appendChild(sw);
    });
    var img = '';
    try { img = localStorage.getItem(BG_CUSTOM_KEY) || ''; } catch (e) {}
    var csw = document.createElement('div');
    csw.className = 'bg-swatch s-custom' + (cur === 'custom' ? ' on' : '') + (img ? '' : ' noimg');
    if (img) csw.style.backgroundImage = 'url("' + img + '")';
    var cl = document.createElement('span');
    cl.className = 'bs-name';
    cl.textContent = img ? '自定义图片' : '＋ 本地图片';
    csw.appendChild(cl);
    csw.addEventListener('click', function () {
      if (img) { bgSave({ type: 'custom' }); renderBgGrid(); }
      else { $('f-bg-custom').click(); }
    });
    box.appendChild(csw);
  }
  function bgLoadCustom(file) {
    if (!file) return;
    if (file.size > 8 * 1024 * 1024) { sysMessage('背景图片超过 8 MB，请压缩后再试'); return; }
    var reader = new FileReader();
    reader.onload = function () {
      var raw = new Image();
      raw.onload = function () {
        var max = 1600;
        var scale = Math.min(1, max / Math.max(raw.width, raw.height, 1));
        var cv = document.createElement('canvas');
        cv.width = Math.max(1, Math.round(raw.width * scale));
        cv.height = Math.max(1, Math.round(raw.height * scale));
        cv.getContext('2d').drawImage(raw, 0, 0, cv.width, cv.height);
        var dataUrl = /^image\/png/.test(file.type) ? cv.toDataURL('image/png') : cv.toDataURL('image/jpeg', 0.82);
        try { localStorage.setItem(BG_CUSTOM_KEY, dataUrl); }
        catch (e) { sysMessage('背景保存失败：超出本机存储容量，请换更小的图片'); return; }
        bgSave({ type: 'custom' });
        renderBgGrid();
      };
      raw.onerror = function () { sysMessage('背景图片解析失败，请换一张'); };
      raw.src = reader.result;
    };
    reader.onerror = function () { sysMessage('背景图片读取失败'); };
    reader.readAsDataURL(file);
  }
  function bgReset() {
    try { localStorage.removeItem(BG_CUSTOM_KEY); } catch (e) {}
    bgSave({ type: 'preset', id: 'aurora' });
    renderBgGrid();
  }
  function openBgModal() {
    renderBgGrid();
    $('bg-modal').classList.remove('hidden');
  }

  /* ---------- rooms / tabs / members ---------- */

  var tabRendered = {};
  function renderRoomTabs() {
    var box = $('room-tabs');
    if (!box) return;
    box.textContent = '';
    state.openRooms.forEach(function (id) {
      var r = fallbackRoom(id);
      var rs = ensureRoomState(id);
      var tab = document.createElement('div');
      tab.className = 'room-tab' + (id === state.currentRoom ? ' active' : '') +
        (tabRendered[id] ? '' : ' enter');
      tabRendered[id] = true;
      var ico = document.createElement('span');
      ico.className = 'rt-ico';
      ico.textContent = id === P.LOBBY_ID ? '⌂' : (r.e2ee ? '🔒' : '#');
      var label = document.createElement('span');
      label.className = 'rt-name';
      label.textContent = r.name;
      tab.appendChild(ico);
      tab.appendChild(label);
      if (rs.unread > 0 && id !== state.currentRoom) {
        var badge = document.createElement('span');
        badge.className = 'rt-badge';
        badge.textContent = rs.unread > 99 ? '99+' : String(rs.unread);
        tab.appendChild(badge);
      }
      if (id !== P.LOBBY_ID) {
        var x = document.createElement('button');
        x.className = 'rt-close'; x.type = 'button';
        x.textContent = '×'; x.title = '离开该房间';
        x.addEventListener('click', function (e) { e.stopPropagation(); delete tabRendered[id]; closeRoom(id); });
        tab.appendChild(x);
      }
      tab.addEventListener('click', function () { switchToRoom(id); });
      wireDropTarget(tab, id);
      box.appendChild(tab);
    });
    var active = box.querySelector('.room-tab.active');
    if (active && active.scrollIntoView) {
      try { active.scrollIntoView({ block: 'nearest', inline: 'nearest' }); } catch (e) { /* older UA */ }
    }
  }

  function renderRooms() {
    var box = $('room-list');
    box.textContent = '';
    if (!state.rooms.length) {
      var e = document.createElement('div');
      e.className = 'empty'; e.textContent = '暂无房间';
      box.appendChild(e); return;
    }
    state.rooms.forEach(function (r) {
      var opened = state.openRooms.indexOf(r.id) !== -1;
      var item = document.createElement('div');
      item.className = 'room-item' + (r.id === state.currentRoom ? ' active' : '');
      var name = document.createElement('span');
      name.className = 'rname';
      name.textContent = r.name + (r.e2ee ? ' 🔒' : '') + (opened ? '' : ' ·');
      var pill = document.createElement('span');
      pill.className = 'pill' + (r.private ? ' private' : '');
      pill.textContent = r.e2ee ? 'E2EE' : r.private ? '私聊' : String(r.members || 0);
      item.appendChild(name); item.appendChild(pill);
      item.addEventListener('click', function () {
        if (!state.transport || !state.connected) return;
        if (opened) { switchToRoom(r.id); return; }
        if (state.openRooms.length >= P.LIMITS.MAX_ACTIVE_ROOMS) {
          sysMessage('最多同时打开 ' + P.LIMITS.MAX_ACTIVE_ROOMS + ' 个房间，请先关闭一个标签');
          return;
        }
        state.transport.send(P.makeEnvelope(P.MSG.ROOM_JOIN,
          r.private ? { invite: r.invite || '' } : { roomId: r.id }));
      });
      if (!r.e2ee) wireDropTarget(item, r.id);
      box.appendChild(item);
    });
  }

  function avColorClass(name) {
    var h = 0, s = String(name || '?');
    for (var i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) % 997;
    return 'av-c' + (h % 5);
  }

  function renderMembers() {
    var box = $('members');
    box.textContent = '';
    var rs = ensureRoomState(state.currentRoom);
    var list = rs.members || [];
    if (!list.length) {
      var e = document.createElement('div');
      e.className = 'empty'; e.textContent = '暂无成员';
      box.appendChild(e); return;
    }
    list.forEach(function (m) {
      var self = m.uid === state.uid;
      var isDm = !!state.directTo && state.directTo.uid === m.uid;
      var item = document.createElement('div');
      item.className = 'member-item' + (isDm ? ' is-dm' : '');
      var av = document.createElement('span');
      av.className = 'avatar ' + avColorClass(m.username);
      av.textContent = (m.username || '?').slice(0, 1).toUpperCase();
      var line = document.createElement('div');
      line.className = 'mline';
      var name = document.createElement('span');
      name.className = 'mname ' + (m.permanent ? 'formal' : 'temp');
      name.textContent = m.username + (self ? '（我）' : '');
      name.title = m.permanent ? '正式用户' : '临时用户（昵称含随机时间戳）';
      var sub = document.createElement('div');
      sub.className = 'msub';
      var tag = document.createElement('span');
      tag.className = 'mtag ' + (m.bot ? 'bot' : (m.permanent ? 'formal' : 'temp'));
      tag.textContent = m.bot ? '机器人' : (m.permanent ? '正式用户' : '临时用户');
      sub.appendChild(tag);
      if (isDm) {
        var dmTag = document.createElement('span');
        dmTag.className = 'mtag me';
        dmTag.textContent = '私聊中';
        sub.appendChild(dmTag);
      }
      line.appendChild(name);
      line.appendChild(sub);
      var act = document.createElement('span');
      act.className = 'act';
      act.textContent = self ? '' : (m.bot ? '自动回复' : '私聊');
      item.appendChild(av);
      item.appendChild(line);
      item.appendChild(act);
      if (!self && !m.bot) {
        item.draggable = true;
        item.addEventListener('dragstart', function (e) {
          state.dragUid = m.uid;
          state.dragName = m.username;
          try {
            e.dataTransfer.setData('text/plain', m.uid);
            e.dataTransfer.effectAllowed = 'link';
          } catch (err) { /* older UA */ }
          item.classList.add('dragging');
        });
        item.addEventListener('dragend', function () {
          item.classList.remove('dragging');
          state.dragUid = ''; state.dragName = '';
        });
        item.addEventListener('click', function () { startPrivateChat(m); });
      }
      box.appendChild(item);
    });
  }

  function showRoom(room) {
    $('room-title').textContent = room.name + (room.e2ee ? ' 🔒' : '');
    var inv = $('room-invite');
    inv.textContent = room.e2ee ? '端到端加密 · 仅双方可见'
      : room.invite ? ('邀请码 ' + room.invite) : (room.private ? '私密房间' : '公开房间');
    renderRooms();
    renderRoomTabs();
  }
  function switchToRoom(id) {
    if (state.call && state.call.active) endVideoCall(true);
    if (!id) return;
    state.currentRoom = id;
    var rs = ensureRoomState(id);
    rs.unread = 0;
    showRoom(fallbackRoom(id));
    renderMessages(id);
    renderMembers();
    if (state.historyEnabled && !rs.historyLoaded) {
      rs.historyLoaded = true;
      requestHistory(id);
    }
    renderRoomTabs();
    setComposerEnabled(!state.muted && !state.banned);
  }
  function openRoom(room) {
    var id = room.id;
    if (state.openRooms.indexOf(id) === -1) {
      if (state.openRooms.length >= P.LIMITS.MAX_ACTIVE_ROOMS) {
        sysMessage('最多同时打开 ' + P.LIMITS.MAX_ACTIVE_ROOMS + ' 个房间，请先关闭一个标签');
        return false;
      }
      state.openRooms.push(id);
    }
    ensureRoomState(id);
    switchToRoom(id);
    return true;
  }
  function closeRoom(id) {
    if (id === P.LOBBY_ID) return;
    if (state.transport && state.connected) {
      state.transport.send(P.makeEnvelope(P.MSG.ROOM_LEAVE, { roomId: id }));
    }
    state.openRooms = state.openRooms.filter(function (x) { return x !== id; });
    delete state.keys[id];
    delete state.roomState[id];
    delete state.seq[id];
    switchToRoom(state.openRooms[0] || P.LOBBY_ID);
    renderRoomTabs();
  }
  function requestRoomList() { state.transport.send(P.makeEnvelope(P.MSG.ROOM_LIST, {})); }
  function requestHistory(roomId) {
    state.transport.send(P.makeEnvelope(P.MSG.HISTORY, { roomId: roomId, limit: 50 }));
  }
  function resetSessionState() {
    state.keys = {}; state.rooms = []; state.seq = {}; state.dmSeq = {};
    state.currentRoom = ''; state.openRooms = []; state.roomState = {};
    state.uid = ''; state.connected = false; state.fileCache = {};
    state.directTo = null; state.directMode = false;
    state.inviteQueue = []; state.inviteBusy = null;
    state.dragUid = ''; state.dragName = '';
    $('invite-modal').classList.add('hidden');
    if (state.transport) { try { state.transport.close(); } catch (e) { /* noop */ } }
    state.transport = null;
    setDirectMode(false);
    tabRendered = {};
  }

  /* ---------- identity vault (local, multi-account, quick switch) ---------- */

  function renderVaultInto(box, list, full) {
    box.textContent = '';
    if (!list.length) {
      var e = document.createElement('div');
      e.className = 'vault-empty';
      e.textContent = '尚未保存身份。勾选「保存身份文件」或导入 XML 后会出现在这里，可一键切换登录。';
      box.appendChild(e); return;
    }
    list.forEach(function (en) {
      var row = document.createElement('div');
      row.className = 'vault-item';
      var main = document.createElement('div');
      main.className = 'vi-main';
      var name = document.createElement('div');
      name.className = 'vi-name';
      name.textContent = en.label || en.nickname || '未命名身份';
      var sub = document.createElement('div');
      sub.className = 'vi-sub';
      sub.textContent = (en.host || '?') + ':' + (en.port || '') + ' · ' + String(en.uid || '').slice(0, 14) + '…';
      main.appendChild(name); main.appendChild(sub);
      main.addEventListener('click', function () { useIdentity(en); });
      row.appendChild(main);
      var tag = document.createElement('span');
      tag.className = 'vi-tag' + (en.enc === 'password' ? ' enc' : '');
      tag.textContent = en.enc === 'password' ? '已加密' : '明文';
      row.appendChild(tag);
      if (full) {
        [['导出', function () {
          ID.download(en.xml, ID.filename({ nickname: en.label || en.nickname, uid: en.uid }));
        }], ['重命名', function () {
          var v = root.prompt('新名称：', en.label || en.nickname);
          if (v) { ID.vaultRename(en.id, v); renderVault(); }
        }], ['删除', function () {
          if (root.confirm('确认从本机身份库删除「' + (en.label || en.nickname) + '」？已导出的 XML 备份不受影响。')) {
            ID.vaultRemove(en.id); renderVault();
          }
        }]].forEach(function (op) {
          var b = document.createElement('button');
          b.className = 'ghost'; b.type = 'button'; b.textContent = op[0];
          b.addEventListener('click', op[1]);
          row.appendChild(b);
        });
      } else {
        var b = document.createElement('button');
        b.className = 'ghost'; b.type = 'button'; b.textContent = '登录';
        b.addEventListener('click', function () { useIdentity(en); });
        row.appendChild(b);
      }
      box.appendChild(row);
    });
    if (full) {
      var t = document.createElement('div');
      t.className = 'vault-section-title';
      t.textContent = '加密身份切换时需输入本地口令；口令只保存在本次页面会话内存中，不写入任何文件。';
      box.appendChild(t);
    }
  }
  function renderVault() {
    var list = ID.vaultList();
    $('vault-count').textContent = list.length ? '(' + list.length + ')' : '';
    renderVaultInto($('vault-list'), list, false);
    renderVaultInto($('user-modal-body'), list, true);
  }
  function useIdentity(en) {
    var pass = state.vaultPasswords[en.id] || '';
    if (en.enc === 'password' && !pass) {
      pass = root.prompt('身份「' + (en.label || en.nickname) + '」已加密，请输入本地加密口令：') || '';
      if (!pass) return;
    }
    var id;
    try { id = ID.parse(en.xml, en.enc === 'password' ? pass : null); }
    catch (e) { root.alert('身份文件解析失败：' + e.message); return; }
    state.vaultPasswords[en.id] = pass;
    state.identityFile = id;
    $('f-username').value = id.nickname;
    $('f-host').value = id.host;
    $('f-port').value = id.port;
    $('f-save-identity').checked = false;
    state.manualClose = true;
    if (state.reconnectTimer) { clearTimeout(state.reconnectTimer); state.reconnectTimer = null; }
    resetSessionState();
    $('view-chat').classList.add('hidden');
    $('view-login').classList.remove('hidden');
    $('user-modal').classList.add('hidden');
    var info = $('identity-info');
    info.className = 'hint-box ok';
    info.textContent = '已选择身份：' + id.nickname + '（' + id.uid.slice(0, 12) + '…）';
    $('btn-clear-identity').classList.remove('hidden');
    loginStatus('正在以 ' + id.nickname + ' 快速登录…', 'ok');
    connect();
  }
  function loadIdentityFile(file, password) {
    return file.text().then(function (xml) {
      var id = ID.parse(xml, password);
      state.identityFile = id;
      $('f-username').value = id.nickname;
      $('f-host').value = id.host;
      $('f-port').value = id.port;
      var info = $('identity-info');
      info.className = 'hint-box ok';
      info.textContent = '已加载身份：' + id.nickname + ' (' + id.uid.slice(0, 12) + '…) · ' +
        (id.enc === 'password' ? '口令加密' : '明文保存') + ' · 创建于 ' +
        new Date(id.createdAt).toLocaleDateString('zh-CN');
      $('btn-clear-identity').classList.remove('hidden');
      if ($('f-add-vault').checked) {
        var rec = ID.vaultSave({
          host: id.host, port: id.port, uid: id.uid, nickname: id.nickname,
          createdAt: id.createdAt, xml: xml, enc: id.enc
        });
        if (rec && password) state.vaultPasswords[rec.id] = password;
        renderVault();
        loginStatus('身份已加入本机身份库，可在聊天中一键切换', 'ok');
      } else {
        loginStatus('身份文件已加载，连接后将恢复该身份', 'ok');
      }
      return id;
    });
  }
  function clearIdentityFile() {
    state.identityFile = null;
    $('f-identity').value = '';
    var info = $('identity-info');
    info.className = 'hint-box';
    info.textContent = '未加载身份文件，本次登录将生成全新身份';
    $('btn-clear-identity').classList.add('hidden');
  }

  /* ---------- invitation codes ---------- */

  function applyInviteCode(code) {
    var p = C.inviteDecrypt(code.trim());
    if (!p) return false;
    $('f-host').value = p.host;
    $('f-port').value = p.port;
    state.pendingInvite = code.trim();
    loginStatus('邀请码有效：' + p.roomName + '（' + p.inviterName + ' 邀请）· ' +
      p.host + ':' + p.port, 'ok');
    return true;
  }
  function copyRoomInvite() {
    var room = currentRoomObject();
    if (!room || !state.connected) { sysMessage('尚未连接'); return; }
    fetch(httpBase() + '/api/invite/create', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ uid: state.uid, room: room.id, host: state.host, port: state.port })
    }).then(function (r) { return r.json(); }).then(function (j) {
      if (!j.ok) throw new Error(j.error || '生成失败');
      try {
        navigator.clipboard.writeText(j.code);
        sysMessage('完整邀请码已复制（含 IP ' + j.invite.host + ':' + j.invite.port +
          '、邀请人、房间信息）');
      } catch (e) { sysMessage('邀请码: ' + j.code); }
    }).catch(function (e) { sysMessage('生成邀请码失败: ' + e.message); });
  }

  /* ---------- v5: direct E2EE chat inside the lobby (no room created) ---------- */

  function startPrivateChat(m) {
    if (!m.pubKey) { sysMessage('尚未获取到该成员的公钥，请稍后重试'); return; }
    setDirectTarget(m);
  }

  /* ---------- connection ---------- */

  function connect() {
    var inviteCode = $('f-invite').value.trim();
    if (inviteCode.slice(0, P.INVITE_PREFIX.length) === P.INVITE_PREFIX) {
      if (!applyInviteCode(inviteCode)) { loginStatus('邀请码无法解析或已过期', 'err'); return; }
    } else if (inviteCode) {
      state.pendingInvite = null;
    }
    var username = $('f-username').value.trim();
    var host = $('f-host').value.trim();
    var port = parseInt($('f-port').value, 10);
    var proxy = $('f-proxy').value.trim();
    if (!username) { loginStatus('请输入用户名', 'err'); return; }
    if (!host) { loginStatus('请输入服务器 IP 地址', 'err'); return; }
    if (!Number.isInteger(port) || port < 1 || port > 65535) { loginStatus('端口不合法', 'err'); return; }
    if (state.identityFile && state.identityFile.fingerprint &&
        state.identityFile.fingerprint !== state.fingerprint && state.fingerprint) {
      loginStatus('警告：服务器指纹与身份文件记录不一致，可能为伪造服务器', 'err');
    }
    state.saveIdentity = $('f-save-identity').checked;
    var formal = !!(state.saveIdentity || state.identityFile);
    state.baseNickname = username;
    state.tempStamp = formal ? '' : makeTempStamp();
    state.username = composeNickname(username, formal);
    state.host = host; state.port = port;
    state.proxy = proxy; state.manualClose = false;
    state.savePassword = $('f-save-pass').value;
    state.muted = false; state.banned = false;
    setComposerEnabled(true);
    $('btn-connect').disabled = true;
    loginStatus('正在连接 ' + host + ':' + port + ' …');
    try {
      state.transport = root.ChatNet.create(
        { host: host, port: port, proxy: proxy },
        { onEnvelope: handleEnvelope, onStatus: handleStatus }
      );
    } catch (e) {
      loginStatus('创建连接失败: ' + e.message, 'err');
      $('btn-connect').disabled = false;
    }
  }
  function handleStatus(s) {
    if (s === 'open') {
      state.connected = true;
      setConn(true, '已连接 · 认证中');
      loginStatus('连接已建立，正在请求服务器公钥…');
      state.transport.send(P.makeEnvelope(P.MSG.HELLO, {}));
    } else if (s === 'error') {
      if (!state.connected) loginStatus('连接出错，请检查 IP、端口与防火墙', 'err');
    } else if (s === 'closed') {
      state.connected = false;
      setConn(false, '连接已断开');
      $('btn-connect').disabled = false;
      if (state.manualClose) return;
      sysMessage('连接已断开，3 秒后自动重连…');
      if (state.reconnectTimer) clearTimeout(state.reconnectTimer);
      state.reconnectTimer = setTimeout(function () {
        resetSessionState();
        loginStatus('正在自动重连…');
        connect();
      }, 3000);
    }
  }

  /* ---------- protocol ---------- */

  function handleEnvelope(env) {
    if (!P.isValidEnvelope(env)) return;
    var d = env.data || {};
    switch (env.type) {
      case P.MSG.WELCOME: return onWelcome(d);
      case P.MSG.REGISTERED: return onRegistered(d);
      case P.MSG.ROOM_JOINED: return onRoomJoined(d);
      case P.MSG.ROOM_LIST_DATA: return onRoomList(d);
      case P.MSG.ROOM_MEMBERS: return onMembers(d);
      case P.MSG.MESSAGE_BROADCAST: return onBroadcast(d);
      case P.MSG.DIRECT_MESSAGE_BROADCAST: return onDirectBroadcast(d);
      case P.MSG.ROOM_INVITE_OFFER: return onInviteOffer(d);
      case P.MSG.SERVER_CONFIG_UPDATE: return onServerConfig(d);
      case P.MSG.ROOM_UPDATED: return onRoomUpdated(d);
      case P.MSG.NICKNAME_UPDATED: return onNicknameUpdated(d);
      case P.MSG.HISTORY_DATA: return onHistory(d);
      case P.MSG.ROOM_DELETED: return onRoomDeleted(d);
      case P.MSG.USER_STATUS: return onUserStatus(d);
      case P.MSG.WEBRTC: return onWebrtcSignal(d.from, d.fromName, d.signal);
      case P.MSG.NOTICE: return sysMessage(d.text || '系统提示', d.room);
      case P.MSG.ERROR: return onError(d);
      case P.MSG.PING:
        state.transport.send(P.makeEnvelope(P.MSG.PONG, { ts: Date.now() }));
        return;
      default: return;
    }
  }
  function onError(d) {
    var msg = '错误 [' + (d.code || 'UNKNOWN') + '] ' + (d.message || '');
    if ($('view-chat').classList.contains('hidden')) loginStatus(msg, 'err');
    else sysMessage(msg);
    if (d.code === P.ERR.MUTED) { state.muted = true; setComposerEnabled(false); }
    if (d.code === P.ERR.BANNED) { state.banned = true; setComposerEnabled(false); }
    if (d.code === P.ERR.REGISTER_FAILED || d.code === P.ERR.NOT_AUTHENTICATED ||
        d.code === P.ERR.IDENTITY_INVALID) {
      $('btn-connect').disabled = false;
    }
  }
  function onWelcome(d) {
    state.serverPubPem = d.pubKey;
    state.fingerprint = d.fingerprint;
    state.challenge = d.challenge;
    state.salt = d.salt;
    if (d.server) applyServerBrand(d.server);
    loginStatus('已获取服务器公钥（指纹 ' + d.fingerprint + '），正在准备身份密钥…', 'ok');
    $('fp-label').textContent = '指纹 ' + d.fingerprint + ' · AES-256-GCM';
    setTimeout(function () {
      try {
        if (state.identityFile) {
          state.privateKey = C.privateKeyFromPem(state.identityFile.privateKeyPem);
          state.publicKeyPem = state.identityFile.publicKeyPem;
          state.privateKeyPem = state.identityFile.privateKeyPem;
        } else {
          var kp = C.generateKeyPair();
          state.privateKey = kp.privateKey;
          state.publicKeyPem = C.publicKeyPem(kp);
          state.privateKeyPem = C.privateKeyPem(kp);
        }
        var inner = {
          v: P.PROTOCOL_VERSION,
          username: state.username,
          browserId: C.browserId(),
          ts: Date.now(),
          nonce: C.b64(C.randomBytes(P.CRYPTO.NONCE_BYTES)),
          challenge: state.challenge,
          clientPub: state.publicKeyPem,
          permanent: !!(state.saveIdentity || state.identityFile),
          sig: ''
        };
        if (state.identityFile) {
          inner.resume = {
            uid: state.identityFile.uid,
            proof: C.signCanonical(state.privateKey,
              C.resumeCanonical(state.identityFile.uid, inner.ts, state.challenge))
          };
        }
        inner.sig = C.signCanonical(state.privateKey, C.canonicalRegister(inner));
        var blob = C.hybridEncrypt(state.serverPubPem, JSON.stringify(inner));
        state.transport.send(P.makeEnvelope(P.MSG.REGISTER, { blob: blob }));
        loginStatus(state.identityFile ? '已提交身份恢复证明，等待校验…' :
          '已提交 RSA-OAEP 加密注册包，等待身份认证…', 'ok');
      } catch (e) {
        loginStatus('准备身份密钥失败: ' + e.message, 'err');
        $('btn-connect').disabled = false;
      }
    }, 60);
  }
  function onRegistered(d) {
    try {
      state.uid = d.uid;
      state.permanent = !!d.permanent;
      state.username = d.username || state.username;
      state.dmSeq = {};
      clearDirectTarget();
      state.keys[d.room.id] = C.unwrapKey(state.privateKey, d.wrappedLobbyKey);
      state.historyEnabled = !!(d.server && d.server.historyEnabled);
      if (d.server) applyServerBrand(d.server);
      upsertRoom(d.room);
      state.openRooms = [d.room.id];
      state.roomState = {};
      var rs = ensureRoomState(d.room.id);
      rs.members = d.members || [];
      state.currentRoom = d.room.id;
      state.seq[d.room.id] = 0;
      state.muted = false; state.banned = false;
      setComposerEnabled(true);
      $('me-name').textContent = d.username || state.username;
      $('me-name').className = 'me-name ' + (state.permanent ? 'formal' : 'temp');
      $('me-uid').textContent = '身份码 ' + state.uid.slice(0, 20) + '…' +
        (d.permanent ? ' · 正式用户' : ' · 临时 ' + state.tempStamp);
      $('view-login').classList.add('hidden');
      $('view-chat').classList.remove('hidden');
      $('btn-connect').disabled = false;
      setConn(true, '已加密连接');
      renderMessages(d.room.id);
      showRoom(d.room);
      renderMembers();
      sysMessage(d.permanent ? '身份认证通过，已恢复正式用户身份。' :
        '身份认证通过。本次为临时身份，昵称已追加随机时间戳 ' + state.tempStamp + '。', d.room.id);

      if (state.saveIdentity && !state.identityFile && state.privateKeyPem) {
        var doc = {
          host: state.host, port: state.port, fingerprint: state.fingerprint,
          uid: state.uid, nickname: d.username, createdAt: Date.now(),
          privateKeyPem: state.privateKeyPem, publicKeyPem: state.publicKeyPem
        };
        var xml = ID.build(doc, state.savePassword || null);
        ID.download(xml, ID.filename(doc));
        var rec = ID.vaultSave({
          host: state.host, port: state.port, uid: state.uid, nickname: d.username,
          createdAt: doc.createdAt, xml: xml,
          enc: state.savePassword ? 'password' : 'none'
        });
        if (rec && state.savePassword) state.vaultPasswords[rec.id] = state.savePassword;
        renderVault();
        sysMessage('身份文件已保存到浏览器下载目录并加入身份库' +
          (state.savePassword ? '（已用本地口令加密）' : '（明文，建议设置口令）'), d.room.id);
      }
      requestRoomList();
      rs.historyLoaded = true;
      if (state.historyEnabled) requestHistory(d.room.id);
      if (state.pendingInvite) {
        var code = state.pendingInvite;
        state.pendingInvite = null;
        state.transport.send(P.makeEnvelope(P.MSG.ROOM_JOIN, { invite: code }));
        sysMessage('正在通过邀请码进入指定房间…', d.room.id);
      }
      $('msg-input').focus();
    } catch (e) {
      loginStatus('解封会话密钥失败: ' + e.message, 'err');
      $('btn-connect').disabled = false;
    }
  }
  function onRoomJoined(d) {
    try {
      state.keys[d.room.id] = C.unwrapKey(state.privateKey, d.wrappedKey);
      upsertRoom(d.room);
      var rs = ensureRoomState(d.room.id);
      rs.members = d.members || [];
      rs.historyLoaded = false;
      state.seq[d.room.id] = state.seq[d.room.id] || 0;
      if (!openRoom(d.room)) return;
      sysMessage('已加入 ' + d.room.name + (d.room.e2ee
        ? '，端到端加密会话密钥已由发起方交付（服务端不可解密）'
        : '，房间会话密钥已安全交付'), d.room.id);
      renderMembers();
      rs.historyLoaded = true;
      if (state.historyEnabled) requestHistory(d.room.id);
    } catch (e) {
      sysMessage('房间密钥解封失败: ' + e.message);
    }
  }
  function onRoomList(d) {
    (d.rooms || []).forEach(upsertRoom);
    renderRooms();
    renderRoomTabs();
  }
  function onMembers(d) {
    var rs = ensureRoomState(d.room);
    rs.members = d.members || [];
    for (var i = 0; i < state.rooms.length; i++) {
      if (state.rooms[i].id === d.room) { state.rooms[i].members = rs.members.length; break; }
    }
    if (d.room === state.currentRoom) renderMembers();
    if (state.call && state.call.active && d.room === state.call.room) callSyncMembers();
    renderRooms();
    renderRoomTabs();
  }
  function onRoomDeleted(d) {
    state.rooms = state.rooms.filter(function (r) { return r.id !== d.room; });
    delete state.keys[d.room];
    delete state.roomState[d.room];
    delete state.seq[d.room];
    state.openRooms = state.openRooms.filter(function (x) { return x !== d.room; });
    if (state.currentRoom === d.room) {
      state.currentRoom = '';
      switchToRoom(state.openRooms[0] || P.LOBBY_ID);
    } else { renderRooms(); renderRoomTabs(); }
    sysMessage('房间 ' + (d.name || d.room) + ' 已被管理员删除');
  }
  function onUserStatus(d) {
    state.muted = !!d.muted;
    state.banned = !!d.banned;
    setComposerEnabled(!state.muted && !state.banned);
    sysMessage('管理员更新了你的权限：' +
      (d.banned ? '禁止登录' : d.muted ? '禁止发言' : '已恢复正常') +
      (d.grants && d.grants.length ? ' · 房间权限：' + d.grants.join(', ') : ''));
  }
  function decryptEnvelope(d, isHistory) {
    /* v5: direct messages are archived as E2EE ciphertext. They cannot be
     * decrypted with the room key, so skip them silently in history replies. */
    if (d.e2ee) return;
    var key = state.keys[d.room];
    if (!key) return;
    try {
      var aad = C.messageAad(d.room, d.from, d.seq, d.ts);
      var obj = JSON.parse(C.aesDecrypt(key, d, aad));
      appendMessage({
        name: d.fromName || '未知', text: obj.text, ts: d.ts,
        self: d.from === state.uid, history: isHistory,
        formal: !!d.fromPermanent,
        bot: String(d.from).indexOf('bot_') === 0,
        kind: obj.kind || 'text', file: obj.file || null, room: d.room
      }, isHistory);
    } catch (e) {
      sysMessage('收到一条无法校验的密文，已丢弃', d.room);
    }
  }
  function onDirectBroadcast(d) {
    try {
      var key = C.unwrapKey(state.privateKey, d.wrappedKey);
      var obj = JSON.parse(C.aesDecrypt(key, d, C.directAad(d.room, d.from, d.seq, d.ts)));
      appendMessage({
        name: d.fromName || '未知', text: obj.text, ts: d.ts,
        self: false, formal: !!d.fromPermanent, direct: true, room: d.room
      });
    } catch (e) {
      sysMessage('收到一条无法解封的私聊密文，已丢弃', d.room);
    }
  }
  function onServerConfig(d) {
    applyServerBrand(d.server);
    sysMessage('聊天室名称 / 版权信息已更新：' + state.serverName);
  }
  function onRoomUpdated(d) {
    if (!d.room) return;
    upsertRoom(d.room);
    renderRooms();
    renderRoomTabs();
    if (d.room.id === state.currentRoom) showRoom(d.room);
    sysMessage('房间名称已更新为「' + d.room.name + '」', d.room.id);
  }
  function onNicknameUpdated(d) {
    state.username = d.nickname;
    state.permanent = !!d.permanent;
    $('me-name').textContent = d.nickname;
    $('me-name').className = 'me-name ' + (state.permanent ? 'formal' : 'temp');
    $('me-uid').textContent = '身份码 ' + state.uid.slice(0, 20) + '…' +
      (state.permanent ? ' · 正式用户' : ' · 临时 ' + state.tempStamp);
    sysMessage('昵称已更新为 ' + d.nickname +
      (state.tempStamp ? '（已保留随机时间戳 ' + state.tempStamp + '）' : ''));
  }

  /* ---------- v5.2: drag-to-room invite ---------- */
  function onInviteOffer(d) {
    if (!d || !d.token) return;
    state.inviteQueue.push(d);
    renderInviteModal();
  }
  function renderInviteModal() {
    if (state.inviteBusy) return;
    var d = state.inviteQueue.shift();
    if (!d) { $('invite-modal').classList.add('hidden'); return; }
    state.inviteBusy = d;
    $('invite-from').textContent = d.inviterName || '有人';
    $('invite-sub').textContent = (d.inviterPermanent ? '正式用户 · ' : '') + '邀请你加入房间';
    $('invite-room').textContent = (d.roomName || '房间') + (d.private ? ' · 私密房间' : '');
    var av = $('invite-av');
    av.textContent = (d.inviterName || '?').slice(0, 1).toUpperCase();
    av.className = 'invite-av ' + avColorClass(d.inviterName || '?');
    $('invite-count').textContent = state.inviteQueue.length
      ? ('还有 ' + state.inviteQueue.length + ' 个待处理') : '';
    $('invite-modal').classList.remove('hidden');
  }
  function answerInvite(accept) {
    var d = state.inviteBusy;
    if (!d) return;
    state.inviteBusy = null;
    if (state.transport && state.connected) {
      state.transport.send(P.makeEnvelope(P.MSG.ROOM_INVITE_REPLY,
        { token: d.token, accept: !!accept }));
    }
    $('invite-modal').classList.add('hidden');
    if (!accept) sysMessage('已拒绝加入「' + (d.roomName || '房间') + '」');
    setTimeout(renderInviteModal, 200);
  }
  function sendDragInvite(roomId, uid, name) {
    if (!state.transport || !state.connected) { sysMessage('未连接服务器'); return; }
    if (roomId === P.LOBBY_ID) { sysMessage('大厅无需邀请，所有在线用户都在大厅中'); return; }
    var r = fallbackRoom(roomId);
    state.transport.send(P.makeEnvelope(P.MSG.ROOM_DRAG_INVITE,
      { room: roomId, to: uid }));
    sysMessage('已向 ' + (name || '对方') + ' 发出加入「' + (r.name || '房间') + '」的邀请，等待对方确认');
  }
  function wireDropTarget(el, roomId) {
    el.addEventListener('dragover', function (e) {
      if (!state.dragUid || roomId === P.LOBBY_ID) return;
      e.preventDefault();
      e.dataTransfer.dropEffect = 'link';
      el.classList.add('drop-ok');
    });
    el.addEventListener('dragleave', function () { el.classList.remove('drop-ok'); });
    el.addEventListener('drop', function (e) {
      e.preventDefault();
      el.classList.remove('drop-ok');
      if (!state.dragUid || roomId === P.LOBBY_ID) return;
      var uid = state.dragUid, name = state.dragName;
      state.dragUid = ''; state.dragName = '';
      sendDragInvite(roomId, uid, name);
    });
  }
  function onBroadcast(d) {
    if (!state.keys[d.room]) return;   /* not a room we hold a key for */
    decryptEnvelope(d, false);
  }
  function onHistory(d) {
    var list = d.messages || [];
    if (!list.length) return;
    appendMessage({ sys: true, text: '以下为服务端加密归档的历史消息',
      room: d.room, ts: Date.now() }, true);
    list.forEach(function (m) { decryptEnvelope(m, true); });
  }

  /* ---------- sending ---------- */

  function sendMessage() {
    var input = $('msg-input');
    var text = input.value.trim();
    if (!text || state.muted || state.banned) return;
    if (!state.connected || !state.transport) { sysMessage('尚未连接，无法发送'); return; }
    if (state.directMode && state.directTo) return sendDirectMessage(text);
    var room = state.currentRoom;
    var key = state.keys[room];
    if (!key) { sysMessage('尚未获得该房间的会话密钥'); return; }
    var seq = (state.seq[room] || 0) + 1;
    var ts = Date.now();
    try {
      var aad = C.messageAad(room, state.uid, seq, ts);
      var enc = C.aesEncrypt(key, JSON.stringify({ text: text, kind: 'text' }), aad);
      state.transport.send(P.makeEnvelope(P.MSG.MESSAGE,
        { room: room, seq: seq, ts: ts, iv: enc.iv, ct: enc.ct, tag: enc.tag }));
      state.seq[room] = seq;
      appendMessage({ name: state.username, text: text, ts: ts, self: true, room: room });
      input.value = '';
    } catch (e) { sysMessage('加密失败: ' + e.message); }
  }
  /* v5: direct message in the current room. A fresh AES key is wrapped with
   * the recipient's public key, so even the server cannot read the content. */
  function sendDirectMessage(text) {
    var input = $('msg-input');
    var room = state.currentRoom;
    var target = state.directTo;
    if (!target || !target.pubKey) { sysMessage('请先选择私聊对象'); return; }
    var seq = (state.dmSeq[room] || 0) + 1;
    var ts = Date.now();
    try {
      var key = C.randomBytes(P.CRYPTO.AES_KEY_BYTES);
      var wrapped = C.wrapKeyFor(target.pubKey, key);
      var enc = C.aesEncrypt(key, JSON.stringify({ text: text, kind: 'text' }),
        C.directAad(room, state.uid, seq, ts));
      state.transport.send(P.makeEnvelope(P.MSG.DIRECT_MESSAGE, {
        room: room, to: target.uid, seq: seq, ts: ts,
        iv: enc.iv, ct: enc.ct, tag: enc.tag, wrappedKey: wrapped
      }));
      state.dmSeq[room] = seq;
      appendMessage({
        name: state.username, text: text, ts: ts, self: true,
        formal: state.permanent, direct: true,
        directTo: target.username, room: room
      });
      input.value = '';
    } catch (e) { sysMessage('私聊加密失败: ' + e.message); }
  }

  /* ---------- v5: online nickname change (keeps the temp timestamp) ---------- */

  function updateRenamePreview() {
    var base = $('f-new-nickname').value.trim();
    var shown = state.permanent ? base : composeNickname(base, false);
    $('rename-preview').textContent = base
      ? '将显示为：' + shown + (state.tempStamp ? '（保留随机时间戳 ' + state.tempStamp + '）' : '')
      : '请输入新的昵称';
  }
  function openRename() {
    if (!state.connected) { sysMessage('请先连接服务器'); return; }
    $('f-new-nickname').value = state.baseNickname || state.username;
    updateRenamePreview();
    $('rename-modal').classList.remove('hidden');
    $('f-new-nickname').focus();
  }
  function applyRename() {
    var base = $('f-new-nickname').value.trim();
    if (!base) { sysMessage('昵称不能为空'); return; }
    state.baseNickname = base;
    var next = state.permanent
      ? base.slice(0, P.LIMITS.MAX_USERNAME)
      : composeNickname(base, false);
    state.transport.send(P.makeEnvelope(P.MSG.NICKNAME_CHANGE, { nickname: next }));
    $('rename-modal').classList.add('hidden');
  }

  function sendFileMessage(file, isVoice) {
    var room = state.currentRoom;
    var key = state.keys[room];
    var seq = (state.seq[room] || 0) + 1;
    var ts = Date.now();
    var aad = C.messageAad(room, state.uid, seq, ts);
    var enc = C.aesEncrypt(key, JSON.stringify({
      text: isVoice ? '[语音消息]' : '[文件] ' + file.name,
      kind: isVoice ? 'voice' : 'file', file: file
    }), aad);
    state.transport.send(P.makeEnvelope(P.MSG.MESSAGE,
      { room: room, seq: seq, ts: ts, iv: enc.iv, ct: enc.ct, tag: enc.tag }));
    state.seq[room] = seq;
    appendMessage({ name: state.username, text: '', ts: ts, self: true,
      kind: isVoice ? 'voice' : 'file', file: file, room: room });
  }
  function uploadFile(file, opts) {
    opts = opts || {};
    if (!file || state.muted || state.banned) return;
    if (opts.voice && !voiceAllowed()) { sysMessage('语音仅可在房间内、公聊模式下发送'); return; }
    var ext = String(file.name).split('.').pop().toLowerCase();
    if (P.ALLOWED_FILE_EXTS.indexOf(ext) === -1) {
      sysMessage('只允许 png / pdf / zip / 音频格式'); return;
    }
    if (file.size > P.LIMITS.MAX_FILE_BYTES) {
      sysMessage('文件超过 8 MB 限制'); return;
    }
    var room = state.currentRoom;
    var key = state.keys[room];
    if (!key) { sysMessage('尚未获得该房间的会话密钥'); return; }
    sysMessage(opts.voice ? '正在加密并上传语音…' : '正在加密并上传 ' + file.name + ' …');
    fileToBytes(file).then(function (bytes) {
      var ts = Date.now();
      var aad = ['file', room, state.uid, ts].join('|');
      var enc = C.aesEncryptBytes(key, bytes, aad);
      return fetch(httpBase() + '/api/file/upload', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          uid: state.uid, room: room, name: file.name, ext: ext, size: file.size,
          iv: enc.iv, ct: enc.ct, tag: enc.tag, aad: aad
        })
      }).then(function (r) { return r.json(); });
    }).then(function (j) {
      if (!j.ok) throw new Error(j.error || '上传失败');
      if (opts.voice) { j.file.kind = 'voice'; j.file.duration = opts.duration || 0; }
      sendFileMessage(j.file, !!opts.voice);
      sysMessage(opts.voice ? '加密语音已发送（服务端仅保存密文）'
        : '文件已发送（服务端仅保存密文）');
    }).catch(function (e) { sysMessage('文件上传失败: ' + e.message); });
  }

  /* ---------- v5.3: encrypted voice clips (room-only) ---------- */

  function pickVoiceFormat() {
    if (!window.MediaRecorder) return null;
    var list = [
      { mime: 'audio/webm;codecs=opus', ext: 'webm' },
      { mime: 'audio/ogg;codecs=opus', ext: 'ogg' },
      { mime: 'audio/mp4', ext: 'm4a' },
      { mime: 'audio/webm', ext: 'webm' }
    ];
    for (var i = 0; i < list.length; i++) {
      try { if (MediaRecorder.isTypeSupported(list[i].mime)) return list[i]; }
      catch (e) { /* older browsers */ }
    }
    return { mime: '', ext: 'webm' };
  }
  function startVoice() {
    if (state.recording) { stopVoice(); return; }
    if (!voiceAllowed()) { sysMessage('语音仅可在非大厅房间、公聊模式下使用'); return; }
    if (!window.isSecureContext) {
      sysMessage('麦克风需要 HTTPS 或 localhost 安全环境，请通过 https:// 访问本页'); return;
    }
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia || !window.MediaRecorder) {
      sysMessage('当前浏览器不支持录音（需 Chrome / Edge / Safari 较新版本）'); return;
    }
    var fmt = pickVoiceFormat();
    if (!fmt) { sysMessage('当前浏览器不支持可用的音频编码'); return; }
    navigator.mediaDevices.getUserMedia({ audio: true }).then(function (stream) {
      var chunks = [];
      var rec;
      try {
        rec = fmt.mime ? new MediaRecorder(stream, { mimeType: fmt.mime })
          : new MediaRecorder(stream);
      } catch (e) { rec = new MediaRecorder(stream); }
      state.recording = {
        rec: rec, stream: stream, chunks: chunks, ext: fmt.ext,
        mime: fmt.mime, started: Date.now()
      };
      rec.ondataavailable = function (e) { if (e.data && e.data.size) chunks.push(e.data); };
      rec.onstop = function () { finalizeVoice(); };
      rec.start(200);
      state.voiceTimer = setTimeout(function () {
        if (state.recording) { sysMessage('已达 60 秒上限，自动发送'); stopVoice(); }
      }, P.LIMITS.MAX_VOICE_MS);
      $('voice-rec').classList.remove('hidden');
      updateVoiceUI();
      sysMessage('正在录音… 再次点击「停止录音」即可加密发送');
    }).catch(function (e) {
      sysMessage('无法访问麦克风: ' + (e && e.message ? e.message : e));
    });
  }
  function stopVoice() {
    var r = state.recording;
    if (!r) return;
    try { if (r.rec.state !== 'inactive') r.rec.stop(); } catch (e) { /* noop */ }
  }
  function finalizeVoice() {
    var r = state.recording;
    if (!r) return;
    state.recording = null;
    if (state.voiceTimer) { clearTimeout(state.voiceTimer); state.voiceTimer = null; }
    try { r.stream.getTracks().forEach(function (t) { t.stop(); }); } catch (e) { /* noop */ }
    $('voice-rec').classList.add('hidden');
    updateVoiceUI();
    if (!r.chunks.length) { sysMessage('未录到音频，已取消'); return; }
    var dur = Math.max(1, Math.round((Date.now() - r.started) / 1000));
    var blob = new Blob(r.chunks, { type: r.mime || 'audio/webm' });
    if (blob.size > P.LIMITS.MAX_FILE_BYTES) { sysMessage('语音超过 8 MB，已取消'); return; }
    var file = new File([blob], 'voice-' + Date.now() + '.' + r.ext, { type: blob.type });
    uploadFile(file, { voice: true, duration: dur });
  }
  function disconnect() {
    if (state.call && state.call.active) endVideoCall(true);
    state.manualClose = true;
    if (state.reconnectTimer) clearTimeout(state.reconnectTimer);
    resetSessionState();
    $('view-chat').classList.add('hidden');
    $('view-login').classList.remove('hidden');
    setConn(false, '未连接');
    loginStatus('已断开连接');
  }

  /* ---------- v5.4: in-room mesh video call (WebRTC, E2EE via DTLS-SRTP) ---------- */

  /* Public STUN servers so peers behind typical NATs discover reflexive
   * addresses. Media is peer-to-peer and never touches the server; for
   * symmetric-NAT networks a TURN relay is required (add one to ICE_SERVERS). */
  var ICE_SERVERS = [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' }
  ];

  function videoAllowed() {
    return !!(state.connected && state.uid && state.currentRoom &&
      state.currentRoom !== P.LOBBY_ID && !state.directMode &&
      !state.muted && !state.banned);
  }
  function updateVideoUI() {
    var btn = $('btn-video');
    if (!btn) return;
    var allowed = videoAllowed();
    btn.disabled = !allowed;
    btn.classList.toggle('calling', !!(state.call && state.call.active));
    btn.textContent = (state.call && state.call.active) ? '退出视频' : '视频';
    btn.title = allowed
      ? ((state.call && state.call.active) ? '点击退出当前视频通话'
        : '仅房间内可用，点击发起或加入视频通话')
      : '视频仅在非大厅房间、公聊模式下可用';
  }
  function newCallState(room) {
    return { active: true, room: room, localStream: null, peers: {}, tiles: {},
      nameMap: {}, micOn: true, camOn: true };
  }
  function ensureLocalMedia() {
    if (state.call.localStream) return Promise.resolve(state.call.localStream);
    if (!window.isSecureContext) {
      return Promise.reject(new Error('视频需要 HTTPS 或 localhost 安全环境，请通过 https:// 访问本页'));
    }
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia ||
        !window.RTCPeerConnection) {
      return Promise.reject(new Error('当前浏览器不支持 WebRTC（需较新版本 Chrome / Edge / Firefox / Safari）'));
    }
    return navigator.mediaDevices.getUserMedia({ video: true, audio: true })
      .catch(function () {
        sysMessage('未获得摄像头权限，将以纯语音方式通话');
        return navigator.mediaDevices.getUserMedia({ audio: true });
      })
      .then(function (stream) {
        state.call.localStream = stream;
        var lv = document.getElementById('local-video');
        if (lv) lv.srcObject = stream;
        return stream;
      });
  }
  function callAddLocalTracks(pc) {
    var s = state.call.localStream;
    if (s) s.getTracks().forEach(function (t) { pc.addTrack(t, s); });
  }
  function sendSignal(toUid, signal) {
    if (!state.call || !state.call.active) return;
    state.transport.send(P.makeEnvelope(P.MSG.WEBRTC, {
      room: state.call.room, to: toUid, signal: signal
    }));
  }
  function callMakePeer(uid, polite) {
    var pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
    var rec = { pc: pc, polite: polite, makingOffer: false, remoteSet: false,
      pending: [], remoteStream: null };
    state.call.peers[uid] = rec;
    pc.onicecandidate = function (e) {
      if (e.candidate) sendSignal(uid, { kind: 'candidate', candidate: e.candidate });
    };
    pc.ontrack = function (e) {
      if (!rec.remoteStream) {
        rec.remoteStream = new MediaStream();
        attachPeerTile(uid, rec.remoteStream);
      }
      rec.remoteStream.addTrack(e.track);
    };
    pc.onconnectionstatechange = function () {
      if (pc.connectionState === 'failed' || pc.connectionState === 'closed') {
        var t = state.call.tiles[uid];
        if (t && t.label) t.label.textContent = (state.call.nameMap[uid] || '对方') + '（连接断开）';
      }
    };
    pc.onnegotiationneeded = async function () {
      try {
        rec.makingOffer = true;
        var offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        sendSignal(uid, { kind: 'description', description: pc.localDescription });
      } catch (e) { /* noop */ }
      finally { rec.makingOffer = false; }
    };
    callAddLocalTracks(pc);
    return rec;
  }
  function attachPeerTile(uid, stream, name) {
    if (name) state.call.nameMap[uid] = name;
    var grid = $('video-grid');
    if (!grid) return;
    var tile = document.getElementById('tile-' + uid);
    if (!tile) {
      tile = document.createElement('div');
      tile.className = 'video-tile';
      tile.id = 'tile-' + uid;
      grid.appendChild(tile);
    }
    if (!tile.querySelector('video')) {
      var v = document.createElement('video');
      v.autoplay = true; v.playsInline = true;
      tile.appendChild(v);
      var label = document.createElement('span');
      label.className = 'video-label';
      tile.appendChild(label);
      state.call.tiles[uid] = { tile: tile, video: v, label: label };
    }
    var rec = state.call.tiles[uid];
    rec.label.textContent = (state.call.nameMap[uid] || uid.slice(0, 12)) +
      (stream ? '' : '（连接中…）');
    if (stream) rec.video.srcObject = stream;
  }
  function removePeer(uid) {
    var rec = state.call && state.call.peers[uid];
    if (rec) { try { rec.pc.close(); } catch (e) { /* noop */ } delete state.call.peers[uid]; }
    var t = state.call && state.call.tiles[uid];
    if (t && t.tile && t.tile.parentNode) t.tile.parentNode.removeChild(t.tile);
    if (state.call) delete state.call.tiles[uid];
  }
  async function startVideoCall() {
    if (state.call && state.call.active) { endVideoCall(false); return; }
    if (!videoAllowed()) { sysMessage('视频仅可在非大厅房间、公聊模式下使用'); return; }
    var room = state.currentRoom;
    state.call = newCallState(room);
    $('video-title').textContent = '视频通话 · ' + (roomName(room) || '房间');
    $('video-overlay').classList.remove('hidden');
    updateVideoUI();
    var members = (ensureRoomState(room).members || []).filter(function (m) {
      return m.uid !== state.uid;
    });
    try { await ensureLocalMedia(); }
    catch (e) {
      sysMessage('无法开启摄像头/麦克风: ' + e.message);
      closeCallLocal();
      return;
    }
    sysMessage('正在呼叫房间内的其他成员…');
    members.forEach(function (m) {
      var polite = state.uid > m.uid;
      callMakePeer(m.uid, polite);
      attachPeerTile(m.uid, null, m.username);
    });
  }
  async function onWebrtcSignal(from, fromName, signal) {
    if (!signal) return;
    if (!(state.call && state.call.active)) {
      /* An incoming call can only begin with an offer; ignore stray ICE. */
      if (!signal.kind || signal.kind !== 'description' ||
          !signal.description || signal.description.type !== 'offer') return;
      try { await startVideoCall(); }
      catch (e) { sysMessage('无法接听视频: ' + e.message); return; }
    }
    var rec = state.call.peers[from];
    if (!rec) {
      var polite = state.uid > from;
      rec = callMakePeer(from, polite);
      attachPeerTile(from, null, fromName);
    }
    try {
      if (signal.kind === 'description') {
        var desc = signal.description;
        var collision = desc.type === 'offer' &&
          (rec.makingOffer || rec.pc.signalingState !== 'stable');
        var ignore = !rec.polite && collision;
        if (ignore) return;
        await rec.pc.setRemoteDescription(desc);
        if (!rec.remoteSet) {
          rec.remoteSet = true;
          var pend = rec.pending; rec.pending = [];
          pend.forEach(function (c) { try { rec.pc.addIceCandidate(c); } catch (e) { /* noop */ } });
        }
        if (desc.type === 'offer') {
          await ensureLocalMedia();
          callAddLocalTracks(rec.pc);
          var answer = await rec.pc.createAnswer();
          await rec.pc.setLocalDescription(answer);
          sendSignal(from, { kind: 'description', description: rec.pc.localDescription });
        }
      } else if (signal.kind === 'candidate') {
        if (rec.remoteSet) {
          try { await rec.pc.addIceCandidate(signal.candidate); } catch (e) { /* noop */ }
        } else {
          rec.pending.push(signal.candidate);
        }
      } else if (signal.kind === 'hangup') {
        removePeer(from);
      }
    } catch (e) { /* perfect-negotiation: transient errors are expected */ }
  }
  function callSyncMembers() {
    if (!state.call || !state.call.active) return;
    var rs = ensureRoomState(state.call.room);
    var list = rs.members || [];
    var ids = {};
    list.forEach(function (m) {
      ids[m.uid] = true;
      if (m.uid === state.uid) return;
      if (!state.call.peers[m.uid]) {
        var polite = state.uid > m.uid;
        callMakePeer(m.uid, polite);
        attachPeerTile(m.uid, null, m.username);
      }
    });
    Object.keys(state.call.peers).forEach(function (uid) {
      if (!ids[uid]) removePeer(uid);
    });
  }
  function endVideoCall(silent) {
    if (!state.call || !state.call.active) { closeCallLocal(); return; }
    if (!silent) {
      Object.keys(state.call.peers).forEach(function (uid) { sendSignal(uid, { kind: 'hangup' }); });
    }
    closeCallLocal();
  }
  function closeCallLocal() {
    if (!state.call) return;
    Object.keys(state.call.peers).forEach(function (uid) { removePeer(uid); });
    if (state.call.localStream) {
      state.call.localStream.getTracks().forEach(function (t) { t.stop(); });
    }
    var grid = $('video-grid');
    if (grid) {
      Array.prototype.slice.call(grid.querySelectorAll('.video-tile:not(.local)'))
        .forEach(function (t) { if (t.parentNode) t.parentNode.removeChild(t); });
    }
    var lv = document.getElementById('local-video');
    if (lv) lv.srcObject = null;
    state.call = null;
    var ov = $('video-overlay');
    if (ov) ov.classList.add('hidden');
    updateVideoUI();
  }
  function callToggleMic() {
    if (!state.call || !state.call.localStream) return;
    var a = state.call.localStream.getAudioTracks()[0];
    if (!a) return;
    state.call.micOn = !state.call.micOn;
    a.enabled = state.call.micOn;
    $('btn-video-mic').textContent = state.call.micOn ? '静音' : '取消静音';
    $('btn-video-mic').classList.toggle('off', !state.call.micOn);
  }
  function callToggleCam() {
    if (!state.call || !state.call.localStream) return;
    var v = state.call.localStream.getVideoTracks()[0];
    if (!v) { sysMessage('本次通话未启用摄像头（仅有语音）'); return; }
    state.call.camOn = !state.call.camOn;
    v.enabled = state.call.camOn;
    $('btn-video-cam').textContent = state.call.camOn ? '关闭摄像头' : '开启摄像头';
    $('btn-video-cam').classList.toggle('off', !state.call.camOn);
  }
  function roomName(id) {
    for (var i = 0; i < state.rooms.length; i++) {
      if (state.rooms[i].id === id) return state.rooms[i].name;
    }
    return id === P.LOBBY_ID ? '大厅' : '';
  }

  /* ---------- wiring ---------- */

  function toggleSidebar(force) {
    var s = $('sidebar');
    var next = typeof force === 'boolean' ? force : !s.classList.contains('show');
    s.classList.toggle('show', next);
    $('sidebar-mask').classList.toggle('hidden', !next);
  }
  function wireDrop() {
    var main = $('chat-main'), overlay = $('drop-overlay'), depth = 0;
    ['dragenter', 'dragover'].forEach(function (ev) {
      main.addEventListener(ev, function (e) {
        if (!e.dataTransfer) return;
        e.preventDefault(); e.stopPropagation();
        if (ev === 'dragenter') depth++;
        overlay.classList.remove('hidden');
      });
    });
    main.addEventListener('dragleave', function (e) {
      e.preventDefault(); e.stopPropagation();
      depth = Math.max(0, depth - 1);
      if (!depth) overlay.classList.add('hidden');
    });
    main.addEventListener('drop', function (e) {
      e.preventDefault(); e.stopPropagation();
      depth = 0; overlay.classList.add('hidden');
      var f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
      if (f) uploadFile(f);
    });
    root.addEventListener('dragover', function (e) { e.preventDefault(); });
    root.addEventListener('drop', function (e) { e.preventDefault(); });
  }
  function initDefaults() {
    var isHttp = /^https?:$/.test(location.protocol);
    /* When the page is reached on a default port (https=443 / http=80),
     * location.port is an empty string, so fall back to the scheme's standard
     * port instead of a hardcoded 8080 — otherwise a visitor opening
     * https://example.com would be seeded with :8080 and fail to connect. */
    var defPort = location.protocol === 'https:' ? '443' : '80';
    $('f-host').value = isHttp && location.hostname ? location.hostname : '127.0.0.1';
    $('f-port').value = isHttp && location.port ? location.port : defPort;
    $('btn-sidebar').classList.toggle('hidden', window.innerWidth > 760);
    if (isHttp) {
      var q = new URLSearchParams(location.search);
      if (q.get('invite')) $('f-invite').value = q.get('invite');
    }
    renderVault();
    setDirectMode(false);
    bgApply();
  }
  function wire() {
    $('btn-connect').addEventListener('click', connect);
    $('btn-disconnect').addEventListener('click', disconnect);
    $('btn-send').addEventListener('click', sendMessage);
    $('btn-history').addEventListener('click', function () {
      if (state.currentRoom && state.historyEnabled) {
        ensureRoomState(state.currentRoom).messages = [];
        $('messages').textContent = '';
        requestHistory(state.currentRoom);
      } else sysMessage('服务端已关闭历史消息');
    });
    $('btn-create-room').addEventListener('click', function () {
      if (state.openRooms.length >= P.LIMITS.MAX_ACTIVE_ROOMS) {
        sysMessage('请先关闭一个房间标签再创建新房间'); return;
      }
      var el = $('room-name-input');
      var name = el.value.trim() || ('房间 ' + Math.floor(Math.random() * 900 + 100));
      var isPrivate = $('f-private-room').checked;
      state.transport.send(P.makeEnvelope(P.MSG.ROOM_CREATE,
        { name: name, private: isPrivate }));
      el.value = '';
      if (isPrivate) sysMessage('已创建私密房间，可通过「复制邀请码」分享给他人');
    });
    $('btn-join-invite').addEventListener('click', function () {
      if (state.openRooms.length >= P.LIMITS.MAX_ACTIVE_ROOMS) {
        sysMessage('请先关闭一个房间标签再加入新房间'); return;
      }
      var el = $('invite-input');
      var code = el.value.trim();
      if (!code) { sysMessage('请输入邀请码'); return; }
      state.transport.send(P.makeEnvelope(P.MSG.ROOM_JOIN, { invite: code }));
      el.value = '';
    });
    $('btn-copy-invite').addEventListener('click', copyRoomInvite);
    $('btn-voice').addEventListener('click', startVoice);
    $('btn-video').addEventListener('click', function () {
      startVideoCall().catch(function (e) { sysMessage('视频通话出错: ' + e.message); });
    });
    $('btn-video-hangup').addEventListener('click', function () { endVideoCall(false); });
    $('btn-video-mic').addEventListener('click', callToggleMic);
    $('btn-video-cam').addEventListener('click', callToggleCam);
    $('btn-sidebar').addEventListener('click', function () { toggleSidebar(); });
    $('sidebar-mask').addEventListener('click', function () { toggleSidebar(false); });

    /* topbar "更多" dropdown menu */
    (function () {
      var more = $('btn-more'), menu = $('more-menu');
      if (!more || !menu) return;
      more.addEventListener('click', function (e) {
        e.stopPropagation();
        var willOpen = menu.classList.contains('hidden');
        menu.classList.toggle('hidden');
        more.setAttribute('aria-expanded', willOpen ? 'true' : 'false');
      });
      menu.addEventListener('click', function (e) {
        if (e.target.closest('button')) {
          menu.classList.add('hidden');
          more.setAttribute('aria-expanded', 'false');
        }
      });
      document.addEventListener('click', function (e) {
        if (menu.classList.contains('hidden')) return;
        if (!menu.contains(e.target) && e.target !== more && !more.contains(e.target)) {
          menu.classList.add('hidden');
          more.setAttribute('aria-expanded', 'false');
        }
      });
      document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && !menu.classList.contains('hidden')) {
          menu.classList.add('hidden'); more.setAttribute('aria-expanded', 'false');
        }
      });
    })();

    /* login page: intro toggle + live client info from /api/client-info */
    (function () {
      var toggle = $('intro-toggle'), intro = $('intro');
      if (toggle && intro) {
        toggle.addEventListener('click', function () {
          if (intro.open) { intro.removeAttribute('open'); }
          else { intro.setAttribute('open', ''); }
        });
        intro.addEventListener('toggle', function () {
          toggle.textContent = intro.open ? '收起说明 ▴' : '使用说明 ▾';
        });
      }
      function size(n){ return n < 1048576 ? (n/1024).toFixed(1)+' KB' : (n/1048576).toFixed(2)+' MB'; }
      fetch('/api/client-info').then(function(r){ return r.json(); }).then(function(d){
        if (!d || !d.ok) throw new Error((d && d.error) || '读取失败');
        var set = function(id,v){ var el = $(id); if (el) el.textContent = v; };
        set('intro-size', size(d.bytes));
        set('intro-ver', 'v' + d.version);
        set('intro-port', d.port);
        set('intro-sha', d.sha256);
        var fp = $('intro-fp'); if (fp) { fp.textContent = '服务器公钥指纹：' + d.fingerprint; fp.classList.add('ok'); }
        set('intro-addrs', '本服务器地址：' + (d.addresses || []).join('   ') + '   （本机也可用 http://127.0.0.1:' + d.port + '/）');
        var cp = $('intro-copy');
        if (cp) cp.addEventListener('click', function () {
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(d.sha256).then(function(){ cp.textContent='已复制'; }, function(){ cp.textContent='请手动复制'; });
          } else { cp.textContent='请手动复制'; }
        });
      }).catch(function (e) {
        var a = $('intro-addrs'); if (a) a.textContent = '信息读取失败：' + ((e && e.message) || e);
      });
    })();
    $('msg-input').addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && state.directMode) {
        e.preventDefault(); clearDirectTarget(); return;
      }
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
    });

    /* v5: one-click public/private switching and online rename */
    $('btn-mode-public').addEventListener('click', clearDirectTarget);
    $('btn-dm-exit').addEventListener('click', clearDirectTarget);
    $('btn-mode-private').addEventListener('click', function () {
      if (!state.directTo) {
        sysMessage('请点击右侧成员列表中的用户名选择私聊对象；按 Esc 或「公聊」返回');
        if (window.innerWidth <= 760) toggleSidebar(true);
        return;
      }
      setDirectMode(true);
      $('msg-input').focus();
    });
    $('btn-rename').addEventListener('click', openRename);
    $('btn-close-rename').addEventListener('click', function () {
      $('rename-modal').classList.add('hidden');
    });
    $('btn-rename-cancel').addEventListener('click', function () {
      $('rename-modal').classList.add('hidden');
    });
    $('btn-rename-ok').addEventListener('click', applyRename);
    $('f-new-nickname').addEventListener('input', updateRenamePreview);
    $('f-new-nickname').addEventListener('keydown', function (e) {
      if (e.key === 'Enter') { e.preventDefault(); applyRename(); }
      if (e.key === 'Escape') $('rename-modal').classList.add('hidden');
    });

    $('f-identity').addEventListener('change', function (e) {
      var f = e.target.files[0];
      if (!f) return;
      loadIdentityFile(f, $('f-identity-pass').value).catch(function (err) {
        loginStatus('身份文件加载失败: ' + err.message, 'err');
        state.identityFile = null;
      });
    });
    $('f-identity-pass').addEventListener('change', function () {
      var f = $('f-identity').files[0];
      if (f && state.identityFile === null) {
        loadIdentityFile(f, $('f-identity-pass').value).catch(function () { /* keep old status */ });
      }
    });
    $('btn-clear-identity').addEventListener('click', clearIdentityFile);
    $('f-invite').addEventListener('change', function () {
      var code = $('f-invite').value.trim();
      if (code.slice(0, P.INVITE_PREFIX.length) === P.INVITE_PREFIX) applyInviteCode(code);
    });

    $('btn-file').addEventListener('click', function () { $('f-file').click(); });
    $('f-file').addEventListener('change', function (e) {
      var f = e.target.files[0];
      if (f) uploadFile(f);
      e.target.value = '';
    });
    $('btn-close-preview').addEventListener('click', function () {
      $('preview-modal').classList.add('hidden');
    });
    $('btn-download-file').addEventListener('click', function () {
      if (!state.preview) { sysMessage('请先加载文件'); return; }
      var a = document.createElement('a');
      a.href = state.preview.url; a.download = state.preview.name;
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
    });

    /* identity vault / quick switch */
    $('btn-switch-user').addEventListener('click', function () {
      renderVault();
      $('user-modal').classList.remove('hidden');
    });
    $('btn-close-users').addEventListener('click', function () {
      $('user-modal').classList.add('hidden');
    });
    $('btn-import-user').addEventListener('click', function () { $('f-import-user').click(); });
    $('f-import-user').addEventListener('change', function (e) {
      var f = e.target.files[0];
      if (!f) return;
      e.target.value = '';
      f.text().then(function (xml) {
        var enc = /<keys[^>]*enc="password"/.test(xml) ? 'password' : 'none';
        var pass = '';
        if (enc === 'password') {
          pass = root.prompt('该身份文件已加密，请输入本地加密口令：') || '';
          if (!pass) return;
        }
        var id = ID.parse(xml, enc === 'password' ? pass : null);
        var rec = ID.vaultSave({
          host: id.host, port: id.port, uid: id.uid, nickname: id.nickname,
          createdAt: id.createdAt, xml: xml, enc: enc
        });
        if (rec && pass) state.vaultPasswords[rec.id] = pass;
        renderVault();
        root.alert('身份「' + id.nickname + '」已加入身份库，可一键切换。');
      }).catch(function (err) { root.alert('导入失败：' + err.message); });
    });
    $('btn-new-temp').addEventListener('click', function () {
      clearIdentityFile();
      $('f-username').value = '';
      $('user-modal').classList.add('hidden');
      disconnect();
    });

    wireDrop();

    /* v5.1: background picker */
    $('btn-bg').addEventListener('click', openBgModal);
    $('btn-bg-login').addEventListener('click', openBgModal);
    $('btn-close-bg').addEventListener('click', function () {
      $('bg-modal').classList.add('hidden');
    });
    $('btn-bg-reset').addEventListener('click', bgReset);
    $('f-bg-custom').addEventListener('change', function (e) {
      var f = e.target.files[0];
      e.target.value = '';
      bgLoadCustom(f);
    });

    /* v5.2: drag-to-room invite replies */
    $('btn-invite-accept').addEventListener('click', function () { answerInvite(true); });
    $('btn-invite-decline').addEventListener('click', function () { answerInvite(false); });

    ['f-username', 'f-host', 'f-port', 'f-proxy', 'f-invite', 'room-name-input', 'invite-input']
      .forEach(function (id) {
        $(id).addEventListener('keydown', function (e) {
          if (e.key !== 'Enter') return;
          if (id === 'f-username' || id === 'f-host' || id === 'f-port' ||
              id === 'f-proxy' || id === 'f-invite') connect();
          else if (id === 'room-name-input') $('btn-create-room').click();
          else if (id === 'invite-input') $('btn-join-invite').click();
        });
      });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { initDefaults(); wire(); });
  } else { initDefaults(); wire(); }
})(window);
