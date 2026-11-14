/*
 * Copyright (c) 2026 CJS flshw@126.com
 * ChatRoom · LAN encrypted chat room. All rights reserved.
 * Licensed for use with this ChatRoom distribution only.
 */
'use strict';
/*
 * Single source of truth for all on-disk paths.
 * CHATROOM_DATA_DIR / CHATROOM_LOG_DIR let operators run multiple isolated
 * instances from one code tree (benchmarks, staging, containers) without
 * touching source files. Defaults keep server/ self-contained.
 */
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const DATA_DIR = path.resolve(process.env.CHATROOM_DATA_DIR || path.join(ROOT, 'data'));
const LOG_DIR = path.resolve(process.env.CHATROOM_LOG_DIR || path.join(ROOT, 'logs'));
const FILES_DIR = path.join(DATA_DIR, 'files');

module.exports = { ROOT, DATA_DIR, LOG_DIR, FILES_DIR };
