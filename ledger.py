"""Session provenance ledger.

Answers one question: did this session create the thing we are about to delete?

Two sources, unioned:
  1. explicit  - every write_file / edit_file / patch call records its path
  2. baseline  - a snapshot of the working tree at session start; anything that
                 appeared afterwards, or whose inode changed, is ours

Everything else is the user's. Unknown counts as the user's, because the
default has to fail toward asking.
"""

from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass

SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    path    TEXT PRIMARY KEY,
    origin  TEXT NOT NULL,          -- 'baseline' | 'created' | 'touched'
    mtime   REAL,
    size    INTEGER,
    inode   INTEGER,
    session TEXT
);
CREATE INDEX IF NOT EXISTS files_origin ON files(origin);
CREATE TABLE IF NOT EXISTS decisions (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL,
    session  TEXT,
    command  TEXT,
    verb     TEXT,
    verdict  TEXT,
    files    INTEGER,
    bytes    INTEGER,
    reason   TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    id      TEXT PRIMARY KEY,
    started REAL
);
"""

BASELINE_SKIP = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "site-packages",
    ".mypy_cache", ".pytest_cache", ".tox", "target", "build", "dist",
    "Library", "Applications", "Pictures", "Movies", "Music",
}
BASELINE_MAX = 50_000
BASELINE_DEPTH = 6


@dataclass
class Provenance:
    path: str
    origin: str  # 'created' | 'baseline' | 'touched' | 'unknown'

    @property
    def ours(self) -> bool:
        return self.origin in ("created", "touched")


class Ledger:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.executescript(SCHEMA)
        self.session_id = ""
        self.session_started = 0.0

    # -- session lifecycle -------------------------------------------------

    def start_session(self, session_id: str) -> None:
        self.session_id = session_id or "default"
        self.session_started = time.time()
        self.conn.execute(
            "INSERT OR REPLACE INTO sessions(id, started) VALUES (?, ?)",
            (self.session_id, self.session_started),
        )
        self.conn.commit()

    def baseline(self, root: str) -> int:
        """Snapshot a tree. Returns how many files were recorded."""
        if not root or not os.path.isdir(root):
            return 0

        rows: list[tuple] = []
        stack = [(root, 0)]
        count = 0

        while stack and count < BASELINE_MAX:
            current, depth = stack.pop()
            try:
                with os.scandir(current) as it:
                    for entry in it:
                        count += 1
                        if count >= BASELINE_MAX:
                            break
                        try:
                            if entry.is_symlink():
                                continue
                            st = entry.stat(follow_symlinks=False)
                            if entry.is_dir(follow_symlinks=False):
                                if depth < BASELINE_DEPTH and entry.name not in BASELINE_SKIP:
                                    stack.append((entry.path, depth + 1))
                                continue
                            rows.append((entry.path, "baseline", st.st_mtime, st.st_size, st.st_ino, ""))
                        except OSError:
                            continue
            except OSError:
                continue

        if rows:
            self.conn.executemany(
                "INSERT OR IGNORE INTO files(path, origin, mtime, size, inode, session) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                rows,
            )
            self.conn.commit()
        return len(rows)

    # -- provenance --------------------------------------------------------

    def record_created(self, path: str) -> None:
        if not path:
            return
        path = os.path.abspath(path)
        try:
            st = os.stat(path, follow_symlinks=False)
            mtime, size, inode = st.st_mtime, st.st_size, st.st_ino
        except OSError:
            mtime, size, inode = time.time(), 0, 0
        self.conn.execute(
            "INSERT INTO files(path, origin, mtime, size, inode, session) "
            "VALUES (?, 'created', ?, ?, ?, ?) "
            "ON CONFLICT(path) DO UPDATE SET origin='created'",
            (path, mtime, size, inode, self.session_id),
        )
        self.conn.commit()

    def record_touched(self, path: str) -> None:
        if not path:
            return
        path = os.path.abspath(path)
        self.conn.execute(
            "INSERT INTO files(path, origin, mtime, size, inode, session) "
            "VALUES (?, 'touched', ?, 0, 0, ?) "
            "ON CONFLICT(path) DO UPDATE SET origin = "
            "CASE WHEN files.origin = 'created' THEN 'created' ELSE 'touched' END",
            (path, time.time(), self.session_id),
        )
        self.conn.commit()

    def provenance(self, path: str) -> Provenance:
        path = os.path.abspath(path)
        row = self.conn.execute("SELECT origin FROM files WHERE path = ?", (path,)).fetchone()
        if row:
            return Provenance(path, row[0])

        # Not in the index. A file that did not exist at baseline and is
        # younger than the session is ours; the baseline only covers the
        # working tree, so mtime is the fallback for everything else.
        try:
            st = os.stat(path, follow_symlinks=False)
        except OSError:
            return Provenance(path, "unknown")

        if self.session_started and st.st_mtime >= self.session_started - 1.0:
            return Provenance(path, "created")
        return Provenance(path, "baseline")

    def count_under(self, prefix: str) -> tuple[int, int]:
        """(ours, foreign) files recorded in the working tree under prefix."""
        prefix = os.path.abspath(prefix).rstrip(os.sep) + os.sep
        row = self.conn.execute(
            "SELECT "
            " SUM(CASE WHEN origin IN ('created','touched') THEN 1 ELSE 0 END), "
            " SUM(CASE WHEN origin = 'baseline' THEN 1 ELSE 0 END) "
            "FROM files WHERE path LIKE ?",
            (prefix + "%",),
        ).fetchone()
        ours = row[0] or 0
        foreign = row[1] or 0
        return ours, foreign

    def ours_under(self, prefix: str) -> int:
        return self.count_under(prefix)[0]

    # -- decisions ---------------------------------------------------------

    def record_decision(self, *, command: str, verb: str, verdict: str,
                        files: int, bytes_: int, reason: str) -> None:
        self.conn.execute(
            "INSERT INTO decisions(ts, session, command, verb, verdict, files, bytes, reason) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (time.time(), self.session_id, command[:2000], verb, verdict, files, bytes_, reason[:500]),
        )
        self.conn.commit()

    def recent(self, limit: int = 10) -> list[tuple]:
        return list(
            self.conn.execute(
                "SELECT ts, verdict, verb, files, bytes, reason FROM decisions "
                "WHERE session = ? ORDER BY id DESC LIMIT ?",
                (self.session_id, limit),
            )
        )

    def summary(self) -> dict[str, int]:
        row = self.conn.execute(
            "SELECT verdict, COUNT(*) FROM decisions WHERE session = ? GROUP BY verdict",
            (self.session_id,),
        ).fetchall()
        return {k: v for k, v in row}


def open_ledger() -> Ledger:
    """Open the plugin's database through Hermes, falling back locally."""
    try:
        from plugins.plugin_storage import plugin_db  # type: ignore

        return Ledger(plugin_db("custody"))
    except Exception:
        home = os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes")
        directory = os.path.join(home, "plugin-data", "custody")
        os.makedirs(directory, exist_ok=True)
        conn = sqlite3.connect(os.path.join(directory, "ledger.db"), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        return Ledger(conn)
