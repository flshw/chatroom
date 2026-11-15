/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
/*
 * ChatRoom shared protocol constants — CANONICAL SOURCE.
 * UMD-style so the very same file works in Node.js (CommonJS) and in the browser.
 * tools/build-client.js inlines it into the client and syncs a byte-identical
 * copy to server/src/protocol.js so that server/ alone is a deployable unit.
 */
(function (root, factory) {
  var api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.ChatProtocol = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  var PROTOCOL_VERSION = 1;

  var MSG = {
    HELLO: 'hello',
    WELCOME: 'welcome',
    REGISTER: 'register',
    REGISTERED: 'registered',
    ERROR: 'error',
    NOTICE: 'notice',

    ROOM_LIST: 'room_list',
    ROOM_LIST_DATA: 'room_list_data',
    ROOM_CREATE: 'room_create',
    ROOM_JOIN: 'room_join',
    ROOM_JOINED: 'room_joined',
    ROOM_LEAVE: 'room_leave',
    ROOM_MEMBERS: 'room_members',
    ROOM_DELETED: 'room_deleted',
    KEY_DELIVERY: 'key_delivery',
    KEY_ROTATE: 'key_rotate',
    PRIVATE_KEY_OFFER: 'private_key_offer',

    MESSAGE: 'message',
    MESSAGE_BROADCAST: 'message_broadcast',
    HISTORY: 'history',
    HISTORY_DATA: 'history_data',
    USER_STATUS: 'user_status',

    /* v5: live server/room metadata, lobby direct chat and online rename. */
    SERVER_CONFIG_UPDATE: 'server_config_update',
    ROOM_UPDATED: 'room_updated',
    NICKNAME_CHANGE: 'nickname_change',
    NICKNAME_UPDATED: 'nickname_updated',
    DIRECT_MESSAGE: 'direct_message',
    DIRECT_MESSAGE_BROADCAST: 'direct_message_broadcast',

    /* v5.2: drag-to-room invite (member list -> room tab). */
    ROOM_DRAG_INVITE: 'room_drag_invite',
    ROOM_INVITE_OFFER: 'room_invite_offer',
    ROOM_INVITE_REPLY: 'room_invite_reply',

    PING: 'ping',
    PONG: 'pong'
  };

  var ERR = {
    BAD_VERSION: 'E_BAD_VERSION',
    BAD_ENVELOPE: 'E_BAD_ENVELOPE',
    REGISTER_FAILED: 'E_REGISTER_FAILED',
    REPLAY: 'E_REPLAY',
    NOT_IN_ROOM: 'E_NOT_IN_ROOM',
    ROOM_FULL: 'E_ROOM_FULL',
    ROOM_NOT_FOUND: 'E_ROOM_NOT_FOUND',
    FORBIDDEN: 'E_FORBIDDEN',
    RATE_LIMIT: 'E_RATE_LIMIT',
    NOT_AUTHENTICATED: 'E_NOT_AUTHENTICATED',
    INTERNAL: 'E_INTERNAL',
    BANNED: 'E_BANNED',
    MUTED: 'E_MUTED',
    ROOM_FORBIDDEN: 'E_ROOM_FORBIDDEN',
    BAD_FILE_TYPE: 'E_BAD_FILE_TYPE',
    FILE_TOO_LARGE: 'E_FILE_TOO_LARGE',
    FILE_NOT_FOUND: 'E_FILE_NOT_FOUND',
    IDENTITY_INVALID: 'E_IDENTITY_INVALID',
    INVITE_INVALID: 'E_INVITE_INVALID',
    ADMIN_REQUIRED: 'E_ADMIN_REQUIRED',
    ADMIN_AUTH_FAILED: 'E_ADMIN_AUTH_FAILED',
    ROOM_LIMIT: 'E_ROOM_LIMIT',
    DIRECT_TARGET_INVALID: 'E_DIRECT_TARGET_INVALID',
    NICKNAME_INVALID: 'E_NICKNAME_INVALID',
    DRAG_INVITE_INVALID: 'E_DRAG_INVITE_INVALID'
  };

  var CRYPTO = {
    RSA_BITS: 2048,
    RSA_EXPONENT: 0x10001,
    AES_KEY_BYTES: 32,
    IV_BYTES: 12,
    TAG_BYTES: 16,
    SALT_BYTES: 16,
    NONCE_BYTES: 16,
    TIMESTAMP_TOLERANCE_MS: 60000,
    HASH: 'SHA-256',
    OAEP_HASH: 'SHA-256',
    PSS_HASH: 'SHA-256'
  };

  var LIMITS = {
    MAX_ROOMS: 50,
    MAX_MEMBERS_PER_ROOM: 30,
    MAX_USERNAME: 24,
    MAX_MESSAGE_BYTES: 8192,
    MAX_FRAME_BYTES: 65536,
    RELAY_POLL_MS: 300,
    RELAY_IDLE_MS: 120000,
    HEARTBEAT_MS: 30000,
    HEARTBEAT_TIMEOUT_MS: 60000,
    DRAG_INVITE_TTL_MS: 60000,
    MAX_FILE_BYTES: 8 * 1024 * 1024,
    MAX_VOICE_MS: 60000,
    MAX_HTTP_BODY_BYTES: 24 * 1024 * 1024,
    INVITE_TTL_MS: 7 * 24 * 3600 * 1000,
    ADMIN_TOKEN_TTL_MS: 3600000,
    MAX_ACTIVE_ROOMS: 3,
    MAX_ROOM_MESSAGES: 400
  };

  /* v5.3: encrypted voice clips reuse the file channel. Voice is room-only. */
  var ALLOWED_FILE_EXTS = ['png', 'pdf', 'zip', 'webm', 'ogg', 'm4a', 'mp4', 'mp3', 'wav'];
  var VOICE_EXTS = ['webm', 'ogg', 'm4a', 'mp4', 'mp3', 'wav'];
  var INVITE_PREFIX = 'CR1.';
  var IDENTITY_VAULT_KEY = 'chatroom-identity-vault-v4';
  var INVITE_PASSPHRASE = 'chatroom-lan-invite-v1';
  var INVITE_AAD = 'chatroom-invite-v1';
  var IDENTITY_XML_VERSION = 3;
  var RELEASE_VERSION = '5.0.0';
  var DEFAULT_COPYRIGHT = 'CJS flshw@126.com';
  var TEMP_NAME_SEPARATOR = '·';

  var LOBBY_ID = 'r_lobby';

  function makeEnvelope(type, data, id) {
    return {
      v: PROTOCOL_VERSION,
      type: type,
      id: id || ('e_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 8)),
      data: data || {}
    };
  }

  function isValidEnvelope(env) {
    return !!env && typeof env === 'object' &&
      env.v === PROTOCOL_VERSION &&
      typeof env.type === 'string' &&
      env.data && typeof env.data === 'object';
  }

  return {
    PROTOCOL_VERSION: PROTOCOL_VERSION,
    MSG: MSG,
    ERR: ERR,
    CRYPTO: CRYPTO,
    LIMITS: LIMITS,
    ALLOWED_FILE_EXTS: ALLOWED_FILE_EXTS,
    VOICE_EXTS: VOICE_EXTS,
    INVITE_PREFIX: INVITE_PREFIX,
    INVITE_PASSPHRASE: INVITE_PASSPHRASE,
    INVITE_AAD: INVITE_AAD,
    IDENTITY_XML_VERSION: IDENTITY_XML_VERSION,
    IDENTITY_VAULT_KEY: IDENTITY_VAULT_KEY,
    RELEASE_VERSION: RELEASE_VERSION,
    DEFAULT_COPYRIGHT: DEFAULT_COPYRIGHT,
    TEMP_NAME_SEPARATOR: TEMP_NAME_SEPARATOR,
    LOBBY_ID: LOBBY_ID,
    makeEnvelope: makeEnvelope,
    isValidEnvelope: isValidEnvelope
  };
});
