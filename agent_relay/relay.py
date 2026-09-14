"""Management and session routes, and the connection loop that serves them."""

import asyncio
import contextlib
import hmac
import json
import logging
import re
import time
from urllib.parse import parse_qs, urlsplit

from .config import (
    CIPHERTEXT,
    MAX_CIPHERTEXT,
    MAX_CONNECTIONS,
    POLL_SECONDS,
    SESSION_ID,
    TIMEOUT,
)
from .http import HttpError, bearer, http_response, read_request
from .log import log_text, peer_address, request_label
from .safety import audit, neutralize, wire_json
from .sessions import QueueFull, ReplayedSequence, peer_role

logger = logging.getLogger(__name__)

MAX_SEQ = 2**63 - 1


class Relay:
    def __init__(self, sessions, api_key, poll_seconds=POLL_SECONDS):
        if not re.fullmatch(r"[!-~]{32,512}", api_key):
            raise ValueError("API key must contain 32-512 visible ASCII characters")
        audit(api_key.encode())
        self.sessions = sessions
        self.api_key = api_key
        self.poll_seconds = poll_seconds
        self.active = 0

    def info(self):
        return {"version": 1, "serverId": self.sessions.server_id}

    async def api(self, method, target, fields, body):
        parsed = urlsplit(target)
        path = parsed.path
        token = bearer(fields)
        if path.startswith("/v1/session/"):
            identity = self.sessions.authenticate(token)
            if identity is None:
                raise HttpError(401)
            session_id, role = identity
            if method == "POST" and path == "/v1/session/send":
                return self._send(session_id, role, json.loads(body))
            if method == "GET" and path == "/v1/session/recv":
                return await self._recv(session_id, role, parse_qs(parsed.query, strict_parsing=True))
            raise HttpError(404)
        if not hmac.compare_digest(token.encode("latin1"), self.api_key.encode("latin1")):
            raise HttpError(401)
        if method == "GET" and path == "/v1/status":
            return {**self.info(), "sessions": self.sessions.count()}
        if method == "POST" and path == "/v1/sessions":
            return self._create()
        if method == "DELETE" and path.startswith("/v1/sessions/"):
            return self._delete(path[len("/v1/sessions/"):])
        raise HttpError(404)

    def _create(self):
        session_id, tokens = self.sessions.create()
        logger.info("PAIR    created session=%s | sessions=%d", session_id, self.sessions.count())
        return {
            **self.info(),
            "sessionId": session_id,
            "desktopToken": tokens["desktop"],
            "phoneToken": tokens["phone"],
        }

    def _delete(self, session_id):
        if not SESSION_ID.fullmatch(session_id):
            raise HttpError(400)
        deleted = self.sessions.delete(session_id)
        logger.info("PAIR    %s session=%s | sessions=%d",
                    "deleted" if deleted else "no such", session_id, self.sessions.count())
        return {**self.info(), "deleted": deleted}

    def _send(self, session_id, role, args):
        seq, ciphertext = args["seq"], args["ct"]
        if type(seq) is not int or not 1 <= seq <= MAX_SEQ:
            raise HttpError(400)
        if not isinstance(ciphertext, str) or not 1 <= len(ciphertext) <= MAX_CIPHERTEXT:
            raise HttpError(400)
        if not CIPHERTEXT.fullmatch(ciphertext):
            raise HttpError(400)
        # A correct peer re-seals under the next sequence number rather than
        # emitting base64 that happens to spell a reserved marker, so one that
        # arrives here is a protocol error and never something to rewrite:
        # rewriting it would destroy the ciphertext it claims to protect.
        audit(ciphertext.encode("ascii"))
        inbox = self.sessions.inbox(session_id, peer_role(role))
        try:
            inbox.add(seq, ciphertext)
        except ReplayedSequence:
            raise HttpError(409)
        except QueueFull:
            raise HttpError(503)
        return {**self.info(), "accepted": True, "seq": seq}

    async def _recv(self, session_id, role, args):
        if any(len(values) != 1 for values in args.values()) or args.keys() - {"after"}:
            raise HttpError(400)
        raw_after = args["after"][0]
        if not re.fullmatch(r"[0-9]{1,19}", raw_after):
            raise HttpError(400)
        after = int(raw_after)
        if after > MAX_SEQ:
            raise HttpError(400)
        inbox = self.sessions.inbox(session_id, role)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.poll_seconds
        while True:
            # Cleared before draining so a frame that arrives during the drain
            # still leaves the waiter armed instead of losing its wake-up.
            inbox.arrival.clear()
            frames = inbox.drain(after)
            remaining = deadline - loop.time()
            if frames or remaining <= 0:
                return {**self.info(), "frames": frames}
            await inbox.wait(remaining)

    async def http(self, reader, writer):
        peer = writer.get_extra_info("peername")
        address = peer_address(peer)
        logger.debug("HTTP    connection opened | peer=%s", address)
        if self.active >= MAX_CONNECTIONS:
            logger.warning("HTTP    connection rejected | peer=%s | connection limit reached", address)
            writer.close()
            return
        self.active += 1
        request = None
        status = "-"
        detail = ""
        outcome = "failed"
        started = time.monotonic()
        try:
            audit(str(peer[0]).encode())
            request = await asyncio.wait_for(read_request(reader), TIMEOUT)
            # Not bounded by TIMEOUT: a held poll is meant to stay open.
            value = await asyncio.wait_for(
                self.api(request[0], request[1], request[4], request[-1]),
                self.poll_seconds + TIMEOUT,
            )
            detail = self._detail(value)
            head, body = http_response(200, wire_json(value), "application/json")
            status = 200
            writer.write(audit(neutralize(head + body)))
            await asyncio.wait_for(writer.drain(), TIMEOUT)
            outcome = "sent"
        except (HttpError, ValueError, KeyError, TypeError, RecursionError) as error:
            outcome = "refused"
            status = error.status if isinstance(error, HttpError) else 400
            try:
                safe_head, safe_body = http_response(status)
                writer.write(audit(safe_head + safe_body))
                await asyncio.wait_for(writer.drain(), TIMEOUT)
            except (OSError, asyncio.TimeoutError):
                outcome = "error response failed"
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError) as error:
            outcome = "timed out" if isinstance(error, asyncio.TimeoutError) else "connection closed"
        finally:
            level = logging.DEBUG if outcome == "sent" else logging.WARNING
            logger.log(level, "HTTP    %s -> %s | peer=%s%s | %s | %.1fms",
                       request_label(request), status, address, detail, outcome,
                       (time.monotonic() - started) * 1000)
            self.active -= 1
            writer.close()
            with contextlib.suppress(OSError, asyncio.TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), 1)

    @staticmethod
    def _detail(value):
        """Frame counts and sequence numbers only; never the sealed payload."""
        if "frames" in value:
            return f" | frames={len(value['frames'])}"
        if "seq" in value:
            return f" | seq={value['seq']}"
        if "sessionId" in value:
            return f" | session={log_text(value['sessionId'])}"
        return ""
