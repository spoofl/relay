"""Paired sessions and the in-memory frame queues that join their two peers.

Pairings are persisted so restarting the service does not unpair every device;
they hold only identifiers and token hashes. Frames are never persisted. They
exist to be handed to a peer that is connected right now, and keeping them on
disk would only widen what a seized server can produce.
"""

import asyncio
import hashlib
import hmac
import secrets
import sqlite3
import time

from .config import FRAME_TTL_SECONDS, MAX_QUEUE_BYTES, MAX_QUEUE_FRAMES

DESKTOP = "desktop"
PHONE = "phone"
ROLES = (DESKTOP, PHONE)


def peer_role(role):
    return PHONE if role == DESKTOP else DESKTOP


def token_hash(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def now_seconds():
    return time.time_ns() // 1_000_000_000


class QueueFull(Exception):
    """The receiving peer is not draining; the sender should retry later."""


class ReplayedSequence(Exception):
    """A sequence number did not advance, so the frame is stale or replayed."""


class Inbox:
    """Frames waiting for one role, with a waiter its sender can wake.

    Sequence numbers are assigned by the sender because they also derive that
    frame's encryption nonce. Refusing one that does not advance keeps a
    replayed frame out of the queue and mirrors the check the receiver makes
    before it opens the seal.
    """

    def __init__(self):
        self.frames = []
        self.bytes = 0
        self.last_seq = 0
        self.arrival = asyncio.Event()

    def _expire(self, now):
        kept = [frame for frame in self.frames if now - frame[2] < FRAME_TTL_SECONDS]
        if len(kept) != len(self.frames):
            self.frames = kept
            self.bytes = sum(len(ct) for _, ct, _ in kept)

    def add(self, seq, ciphertext, now=None):
        now = now_seconds() if now is None else now
        self._expire(now)
        if seq <= self.last_seq:
            raise ReplayedSequence
        if len(self.frames) >= MAX_QUEUE_FRAMES or self.bytes + len(ciphertext) > MAX_QUEUE_BYTES:
            raise QueueFull
        self.frames.append((seq, ciphertext, now))
        self.bytes += len(ciphertext)
        self.last_seq = seq
        self.arrival.set()

    def drain(self, after, now=None):
        """Frames past `after`, dropping everything it acknowledges."""
        now = now_seconds() if now is None else now
        self._expire(now)
        kept = [frame for frame in self.frames if frame[0] > after]
        if len(kept) != len(self.frames):
            self.frames = kept
            self.bytes = sum(len(ct) for _, ct, _ in kept)
        return [{"seq": seq, "ct": ciphertext} for seq, ciphertext, _ in kept]

    async def wait(self, timeout):
        try:
            await asyncio.wait_for(self.arrival.wait(), timeout)
        except asyncio.TimeoutError:
            pass


class Sessions:
    def __init__(self, path, ttl_seconds):
        self.ttl_seconds = ttl_seconds
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                desktop_hash TEXT NOT NULL UNIQUE,
                phone_hash TEXT NOT NULL UNIQUE,
                created_at INTEGER NOT NULL,
                seen_at INTEGER NOT NULL
            );
        """)
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO metadata VALUES ('server_id', ?)", (secrets.token_hex(16),))
        self.server_id = self.db.execute("SELECT value FROM metadata WHERE name = 'server_id'").fetchone()[0]
        self.inboxes = {}

    def create(self):
        """Register a pairing and return its tokens; they are never stored."""
        session_id = secrets.token_hex(16)
        tokens = {role: secrets.token_hex(32) for role in ROLES}
        now = now_seconds()
        with self.db:
            self.db.execute(
                "INSERT INTO sessions VALUES (?, ?, ?, ?, ?)",
                (session_id, token_hash(tokens[DESKTOP]), token_hash(tokens[PHONE]), now, now),
            )
        return session_id, tokens

    def authenticate(self, token):
        """The (session, role) a bearer token names, or None."""
        if not token:
            return None
        digest = token_hash(token)
        row = self.db.execute(
            "SELECT session_id, desktop_hash, phone_hash FROM sessions WHERE desktop_hash = ? OR phone_hash = ?",
            (digest, digest),
        ).fetchone()
        if row is None:
            return None
        session_id, desktop_hash, phone_hash = row
        # Compared rather than trusted to the query so a future index or
        # collation change cannot quietly decide which role a token holds.
        if hmac.compare_digest(digest, desktop_hash):
            role = DESKTOP
        elif hmac.compare_digest(digest, phone_hash):
            role = PHONE
        else:
            return None
        with self.db:
            self.db.execute("UPDATE sessions SET seen_at = ? WHERE session_id = ?", (now_seconds(), session_id))
        return session_id, role

    def inbox(self, session_id, role):
        return self.inboxes.setdefault((session_id, role), Inbox())

    def forget(self, session_id):
        for role in ROLES:
            self.inboxes.pop((session_id, role), None)

    def delete(self, session_id):
        with self.db:
            deleted = self.db.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,)).rowcount
        self.forget(session_id)
        return bool(deleted)

    def purge(self, now=None):
        """Drop pairings idle past the retention window."""
        now = now_seconds() if now is None else now
        cutoff = now - self.ttl_seconds
        stale = [row[0] for row in self.db.execute("SELECT session_id FROM sessions WHERE seen_at < ?", (cutoff,))]
        for session_id in stale:
            self.delete(session_id)
        return len(stale)

    def count(self):
        return self.db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
