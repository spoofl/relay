import asyncio
import base64
import json
import logging
import os
from pathlib import Path
import sys
import tempfile
import unittest

import relay as service

# Route logs are exercised above; keep a failing run's output readable.
logging.disable(logging.CRITICAL)


KEY = "k" * 32
CIPHERTEXT = base64.b64encode(b"sealed frame").decode()


def reader_for(data):
    reader = asyncio.StreamReader(limit=service.MAX_HEAD)
    reader.feed_data(data)
    reader.feed_eof()
    return reader


class MemoryWriter:
    def __init__(self, fail=False):
        self.data = b""
        self.closed = False
        self.fail = fail

    def get_extra_info(self, name):
        return ("127.0.0.1", 12345)

    def write(self, data):
        self.data += data

    async def drain(self):
        if self.fail:
            raise OSError("Connection lost")

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


class SafetyTests(unittest.TestCase):
    def test_wire_filter_covers_mixed_case_keys_values_and_frames(self):
        sealed = service.wire_json({"SiMhOt": "a CrAwLeR frame", "nested": ["SIMHOT"]})
        self.assertNotIn(b"simhot", sealed.lower())
        self.assertNotIn(b"crawler", sealed.lower())
        self.assertIn(b"client", sealed)
        self.assertIn(b"browser", sealed)

    def test_audit_refuses_encoded_identity_markers(self):
        for value in (b"%73imhot", b"%2563RaWlEr", b"%25%37%33imhot"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    service.audit(value)

    def test_audit_terminates_on_base64_without_markers(self):
        clean = base64.b64encode(os.urandom(4096)).decode().encode("ascii")
        self.assertEqual(service.audit(clean), clean)


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.sessions = service.Sessions(":memory:", 3600)
        self.addCleanup(self.sessions.db.close)

    def test_tokens_authenticate_to_their_own_role_only(self):
        session_id, tokens = self.sessions.create()
        self.assertEqual(self.sessions.authenticate(tokens["desktop"]), (session_id, service.DESKTOP))
        self.assertEqual(self.sessions.authenticate(tokens["phone"]), (session_id, service.PHONE))
        self.assertIsNone(self.sessions.authenticate("f" * 64))
        self.assertIsNone(self.sessions.authenticate(""))

    def test_plaintext_tokens_are_never_stored(self):
        _, tokens = self.sessions.create()
        stored = self.sessions.db.execute("SELECT desktop_hash, phone_hash FROM sessions").fetchone()
        self.assertNotIn(tokens["desktop"], stored)
        self.assertNotIn(tokens["phone"], stored)
        self.assertEqual(stored[0], service.token_hash(tokens["desktop"]))

    def test_delete_drops_the_pairing_and_its_queues(self):
        session_id, tokens = self.sessions.create()
        self.sessions.inbox(session_id, service.PHONE).add(1, CIPHERTEXT)
        self.assertTrue(self.sessions.delete(session_id))
        self.assertIsNone(self.sessions.authenticate(tokens["desktop"]))
        self.assertEqual(self.sessions.inbox(session_id, service.PHONE).frames, [])
        self.assertFalse(self.sessions.delete(session_id))

    def test_purge_drops_only_pairings_idle_past_the_window(self):
        fresh, _ = self.sessions.create()
        stale, _ = self.sessions.create()
        self.sessions.db.execute("UPDATE sessions SET seen_at = 0 WHERE session_id = ?", (stale,))
        self.assertEqual(self.sessions.purge(), 1)
        self.assertEqual(self.sessions.count(), 1)
        self.assertEqual(
            self.sessions.db.execute("SELECT session_id FROM sessions").fetchone()[0], fresh)

    def test_pairings_survive_a_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "pairings.sqlite3")
            first = service.Sessions(path, 3600)
            session_id, tokens = first.create()
            server_id = first.server_id
            first.db.close()
            second = service.Sessions(path, 3600)
            self.addCleanup(second.db.close)
            self.assertEqual(second.server_id, server_id)
            self.assertEqual(second.authenticate(tokens["phone"]), (session_id, service.PHONE))


class InboxTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.inbox = service.Inbox()

    def test_sequence_numbers_must_advance(self):
        self.inbox.add(5, CIPHERTEXT)
        for seq in (5, 4, 1):
            with self.subTest(seq=seq):
                with self.assertRaises(service.ReplayedSequence):
                    self.inbox.add(seq, CIPHERTEXT)
        self.inbox.add(6, CIPHERTEXT)
        self.assertEqual([frame["seq"] for frame in self.inbox.drain(0)], [5, 6])

    def test_a_cursor_acknowledges_everything_behind_it(self):
        for seq in (1, 2, 3):
            self.inbox.add(seq, CIPHERTEXT)
        self.assertEqual([frame["seq"] for frame in self.inbox.drain(2)], [3])
        self.assertEqual(len(self.inbox.frames), 1)
        self.assertEqual(self.inbox.bytes, len(CIPHERTEXT))

    def test_a_full_queue_refuses_rather_than_dropping_a_frame(self):
        for seq in range(1, service.MAX_QUEUE_FRAMES + 1):
            self.inbox.add(seq, CIPHERTEXT)
        with self.assertRaises(service.QueueFull):
            self.inbox.add(service.MAX_QUEUE_FRAMES + 1, CIPHERTEXT)
        self.assertEqual(len(self.inbox.frames), service.MAX_QUEUE_FRAMES)

    def test_expired_frames_are_dropped(self):
        self.inbox.add(1, CIPHERTEXT, now=0)
        self.assertEqual(self.inbox.drain(0, now=service.FRAME_TTL_SECONDS), [])
        self.assertEqual(self.inbox.bytes, 0)

    async def test_waiting_is_woken_by_an_arriving_frame(self):
        async def deliver():
            await asyncio.sleep(0.01)
            self.inbox.add(1, CIPHERTEXT)

        self.inbox.arrival.clear()
        task = asyncio.create_task(deliver())
        await asyncio.wait_for(self.inbox.wait(5), 5)
        await task
        self.assertEqual(len(self.inbox.drain(0)), 1)


class RouteTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.sessions = service.Sessions(":memory:", 3600)
        self.addCleanup(self.sessions.db.close)
        self.relay = service.Relay(self.sessions, KEY, poll_seconds=1)

    async def exchange(self, request, fail=False):
        writer = MemoryWriter(fail)
        # Held polls from other tasks may be in flight, so the count has to
        # return to where it started rather than to zero.
        before = self.relay.active
        await self.relay.http(reader_for(request), writer)
        self.assertTrue(writer.closed)
        self.assertEqual(self.relay.active, before)
        head, _, body = writer.data.partition(b"\r\n\r\n")
        return int(head.split()[1]), json.loads(body) if body else None

    def request(self, method, target, token=None, body=None):
        head = f"{method} {target} HTTP/1.1\r\n"
        if token:
            head += f"Authorization: Bearer {token}\r\n"
        payload = json.dumps(body).encode() if body is not None else b""
        if body is not None:
            head += f"Content-Length: {len(payload)}\r\n"
        return head.encode() + b"\r\n" + payload

    async def pair(self):
        status, value = await self.exchange(self.request("POST", "/v1/sessions", KEY))
        self.assertEqual(status, 200)
        return value

    async def test_management_routes_require_the_api_key(self):
        for token in (None, "wrong" * 8):
            with self.subTest(token=token):
                status, _ = await self.exchange(self.request("GET", "/v1/status", token))
                self.assertEqual(status, 401)
        status, value = await self.exchange(self.request("GET", "/v1/status", KEY))
        self.assertEqual(status, 200)
        self.assertEqual(value["version"], 1)
        self.assertEqual(value["serverId"], self.sessions.server_id)

    async def test_session_routes_refuse_the_api_key_and_unknown_tokens(self):
        for token in (KEY, "f" * 64, None):
            with self.subTest(token=token):
                status, _ = await self.exchange(
                    self.request("POST", "/v1/session/send", token, {"seq": 1, "ct": CIPHERTEXT}))
                self.assertEqual(status, 401)

    async def test_a_frame_reaches_the_peer_and_not_its_sender(self):
        pairing = await self.pair()
        self.assertTrue(service.SESSION_ID.fullmatch(pairing["sessionId"]))
        self.assertTrue(service.TOKEN.fullmatch(pairing["desktopToken"]))
        status, value = await self.exchange(
            self.request("POST", "/v1/session/send", pairing["desktopToken"], {"seq": 1, "ct": CIPHERTEXT}))
        self.assertEqual((status, value["accepted"], value["seq"]), (200, True, 1))

        status, value = await self.exchange(
            self.request("GET", "/v1/session/recv?after=0", pairing["phoneToken"]))
        self.assertEqual((status, value["frames"]), (200, [{"seq": 1, "ct": CIPHERTEXT}]))

        status, value = await self.exchange(
            self.request("GET", "/v1/session/recv?after=0", pairing["desktopToken"]))
        self.assertEqual((status, value["frames"]), (200, []))

    async def test_a_replayed_sequence_number_is_refused(self):
        pairing = await self.pair()
        send = self.request("POST", "/v1/session/send", pairing["desktopToken"], {"seq": 7, "ct": CIPHERTEXT})
        self.assertEqual((await self.exchange(send))[0], 200)
        self.assertEqual((await self.exchange(send))[0], 409)

    async def test_send_rejects_malformed_frames(self):
        pairing = await self.pair()
        oversize = "A" * (service.MAX_CIPHERTEXT + 1)
        cases = [
            {"seq": 0, "ct": CIPHERTEXT},
            {"seq": -1, "ct": CIPHERTEXT},
            {"seq": 1.5, "ct": CIPHERTEXT},
            {"seq": True, "ct": CIPHERTEXT},
            {"seq": 1, "ct": ""},
            {"seq": 1, "ct": oversize},
            {"seq": 1, "ct": "not base64!"},
            {"seq": 1, "ct": 17},
            {"seq": 1},
        ]
        for body in cases:
            with self.subTest(body=str(body)[:60]):
                status, _ = await self.exchange(
                    self.request("POST", "/v1/session/send", pairing["desktopToken"], body))
                self.assertEqual(status, 400)

    async def test_ciphertext_naming_a_reserved_marker_is_refused_not_rewritten(self):
        pairing = await self.pair()
        # The relay cannot open a frame, so it judges only the bytes it will
        # actually transmit. Base64 that spells a marker is a protocol error a
        # correct peer avoids by re-sealing under the next sequence number;
        # rewriting it here would destroy the ciphertext it claims to protect.
        for ct in ("QUFB" + "SIMHOT", "Y3Jhd2xlcg" + "CrAwLeR", "AA" + "siMHot" + "BB"):
            with self.subTest(ct=ct):
                status, _ = await self.exchange(
                    self.request("POST", "/v1/session/send", pairing["desktopToken"], {"seq": 1, "ct": ct}))
                self.assertEqual(status, 400)
        self.assertEqual(self.sessions.inbox(pairing["sessionId"], service.PHONE).frames, [])

        # Ciphertext that merely decodes to a marker is ordinary opaque
        # payload: the desktop neutralized the plaintext before sealing it.
        status, _ = await self.exchange(self.request(
            "POST", "/v1/session/send", pairing["desktopToken"],
            {"seq": 1, "ct": base64.b64encode(b"simhot").decode()}))
        self.assertEqual(status, 200)

    async def test_a_held_poll_answers_empty_and_is_woken_by_a_frame(self):
        pairing = await self.pair()
        poll = asyncio.create_task(
            self.exchange(self.request("GET", "/v1/session/recv?after=0", pairing["phoneToken"])))
        await asyncio.sleep(0.05)
        self.assertFalse(poll.done())
        await self.exchange(
            self.request("POST", "/v1/session/send", pairing["desktopToken"], {"seq": 1, "ct": CIPHERTEXT}))
        status, value = await asyncio.wait_for(poll, 5)
        self.assertEqual((status, len(value["frames"])), (200, 1))

        status, value = await asyncio.wait_for(
            self.exchange(self.request("GET", "/v1/session/recv?after=1", pairing["phoneToken"])), 5)
        self.assertEqual((status, value["frames"]), (200, []))

    async def test_recv_rejects_a_malformed_cursor(self):
        pairing = await self.pair()
        for query in ("", "?after=", "?after=x", "?after=-1", "?after=0&after=1", "?after=0&extra=1",
                      "?after=" + "9" * 20):
            with self.subTest(query=query):
                status, _ = await self.exchange(
                    self.request("GET", "/v1/session/recv" + query, pairing["phoneToken"]))
                self.assertEqual(status, 400)

    async def test_deleting_a_pairing_revokes_both_tokens(self):
        pairing = await self.pair()
        status, value = await self.exchange(
            self.request("DELETE", "/v1/sessions/" + pairing["sessionId"], KEY))
        self.assertEqual((status, value["deleted"]), (200, True))
        for role in ("desktopToken", "phoneToken"):
            with self.subTest(role=role):
                status, _ = await self.exchange(
                    self.request("GET", "/v1/session/recv?after=0", pairing[role]))
                self.assertEqual(status, 401)

    async def test_unknown_routes_and_methods_are_refused(self):
        pairing = await self.pair()
        cases = [
            (self.request("GET", "/", KEY), 404),
            (self.request("POST", "/v1/status", KEY), 404),
            (self.request("DELETE", "/v1/sessions/short", KEY), 400),
            (self.request("GET", "/v1/session/send", pairing["desktopToken"]), 404),
            (b"CONNECT / HTTP/1.1\r\n\r\n", 405),
            (b"GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", 400),
            (b"GET / HTTP/1.1\r\nContent-Encoding: gzip\r\n\r\n", 415),
        ]
        for request, status in cases:
            with self.subTest(status=status):
                self.assertEqual((await self.exchange(request))[0], status)

    async def test_a_lost_connection_does_not_leave_the_relay_busy(self):
        status, _ = await self.exchange(self.request("GET", "/v1/status", KEY), fail=True)
        self.assertEqual(status, 200)


class ConfigTests(unittest.TestCase):
    def test_relay_must_bind_loopback(self):
        self.assertEqual(service.numeric_address("127.0.0.1:8787", loopback=True), ("127.0.0.1", 8787))
        with self.assertRaises(ValueError):
            service.numeric_address("0.0.0.0:8787", loopback=True)
        with self.assertRaises(ValueError):
            service.numeric_address("relay.example.com:8787")

    def test_api_key_must_be_a_usable_secret(self):
        sessions = service.Sessions(":memory:", 3600)
        self.addCleanup(sessions.db.close)
        for key in ("short", "k" * 513, "key with spaces" + "k" * 32):
            with self.subTest(key=key[:20]):
                with self.assertRaises(ValueError):
                    service.Relay(sessions, key)


class ServiceTests(unittest.IsolatedAsyncioTestCase):
    async def test_the_service_refuses_a_non_loopback_listener(self):
        with tempfile.TemporaryDirectory() as directory:
            key_file = Path(directory) / "api.key"
            key_file.write_text(KEY)
            args = type("Args", (), {
                "listen": "0.0.0.0:8787", "api_key_file": str(key_file),
                "database": ":memory:", "poll_seconds": 25, "session_ttl_hours": 720,
            })()
            with self.assertRaises(ValueError):
                await service.run(args)


if __name__ == "__main__":
    unittest.main()
