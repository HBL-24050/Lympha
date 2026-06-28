import sqlite3
import threading


class Database:
    def __init__(self, db_path: str = "security.db"):
        self.db_path = db_path
        self.lock = threading.Lock()

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.row_factory = sqlite3.Row
        return conn

    def initialize(self):
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS security_events (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   TEXT NOT NULL DEFAULT (datetime('now')),
                    source_ip   TEXT NOT NULL,
                    event_type  TEXT NOT NULL CHECK(event_type IN ('suricata','securebert')),
                    description TEXT,
                    severity    INTEGER DEFAULT 0,
                    raw_data    TEXT
                );
                CREATE TABLE IF NOT EXISTS active_blocks (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip          TEXT NOT NULL UNIQUE,
                    blocked_at  TEXT NOT NULL DEFAULT (datetime('now')),
                    reason      TEXT,
                    is_active   INTEGER DEFAULT 1
                );
                CREATE INDEX IF NOT EXISTS idx_events_ip   ON security_events(source_ip);
                CREATE INDEX IF NOT EXISTS idx_events_time ON security_events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_blocks_ip   ON active_blocks(ip);
            """)

    def insert_event(self, source_ip, event_type, description, severity, raw_data):
        with self.lock:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO security_events (source_ip, event_type, description, severity, raw_data) VALUES (?, ?, ?, ?, ?)",
                    (source_ip, event_type, description, severity, raw_data),
                )

    def insert_block(self, ip, reason):
        with self.lock:
            with self._connect() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO active_blocks (ip, reason, is_active) VALUES (?, ?, 1)",
                    (ip, reason),
                )

    def remove_block(self, ip):
        with self.lock:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE active_blocks SET is_active = 0 WHERE ip = ?", (ip,)
                )

    def get_active_blocks(self):
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM active_blocks WHERE is_active = 1"
            ).fetchall()
            return [dict(r) for r in rows]

    def get_recent_events(self, limit=100):
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM security_events ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]
