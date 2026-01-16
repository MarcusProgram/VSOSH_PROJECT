CREATE TABLE IF NOT EXISTS licenses (
    license_hash TEXT PRIMARY KEY,
    chat_id INTEGER,
    activated_at TEXT
);

CREATE TABLE IF NOT EXISTS commands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_hash TEXT NOT NULL,
    command_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL,
    acked INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    details TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nonces (
    nonce TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL
);
