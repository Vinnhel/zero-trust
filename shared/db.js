'use strict';
const Database = require('better-sqlite3');
const { paths } = require('./config');

function openDb() {
  const db = new Database(paths.db);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.pragma('busy_timeout = 5000');
  return db;
}
module.exports = { openDb };
