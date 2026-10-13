import asyncio
import errno
import json
from pathlib import Path
import signal
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from agent_relay import cli


class ListenerTests(unittest.IsolatedAsyncioTestCase):
    async def test_occupied_ports_are_skipped_until_binding_succeeds(self):
        server = object()
        handler = object()
        start_server = AsyncMock(side_effect=[
            OSError(errno.EADDRINUSE, "Address already in use"),
            OSError(errno.EADDRINUSE, "Address already in use"),
            server,
        ])
        with patch.object(cli.asyncio, "start_server", start_server):
            self.assertIs(await cli._listen(handler, "127.0.0.1", 8787), server)
        self.assertEqual([call.args for call in start_server.await_args_list], [
            (handler, "127.0.0.1", 8787),
            (handler, "127.0.0.1", 8788),
            (handler, "127.0.0.1", 8789),
        ])

    async def test_last_port_falls_back_to_a_system_selected_port(self):
        server = object()
        start_server = AsyncMock(side_effect=[
            OSError(errno.EADDRINUSE, "Address already in use"), server,
        ])
        with patch.object(cli.asyncio, "start_server", start_server):
            self.assertIs(await cli._listen(None, "::1", 65535), server)
        self.assertEqual([call.args[2] for call in start_server.await_args_list], [65535, 0])

    async def test_other_bind_errors_are_not_retried(self):
        error = OSError(errno.EACCES, "Permission denied")
        start_server = AsyncMock(side_effect=error)
        with patch.object(cli.asyncio, "start_server", start_server):
            with self.assertRaises(OSError) as caught:
                await cli._listen(None, "127.0.0.1", 8787)
        self.assertIs(caught.exception, error)
        self.assertEqual(start_server.await_count, 1)

    async def test_failed_system_port_selection_is_not_retried_forever(self):
        error = OSError(errno.EADDRINUSE, "No available port")
        start_server = AsyncMock(side_effect=error)
        with patch.object(cli.asyncio, "start_server", start_server):
            with self.assertRaises(OSError):
                await cli._listen(None, "127.0.0.1", 0)
        self.assertEqual(start_server.await_count, 1)


class ServiceListenerTests(unittest.IsolatedAsyncioTestCase):
    async def check_listener(self, preferred_port):
        with tempfile.TemporaryDirectory() as directory:
            key = "k" * 32
            key_file = Path(directory) / "api.key"
            key_file.write_text(key)
            args = SimpleNamespace(
                listen=f"127.0.0.1:{preferred_port}", api_key_file=str(key_file),
                database=str(Path(directory) / "pairings.sqlite3"),
                poll_seconds=25, session_ttl_hours=720,
                background=False, log_file=None,
            )
            ready = asyncio.Event()
            stop_handlers = {}
            loop = asyncio.get_running_loop()
            with patch.object(loop, "add_signal_handler", side_effect=stop_handlers.__setitem__):
                task = asyncio.create_task(cli.run(args, ready.set))
                try:
                    await asyncio.wait_for(ready.wait(), timeout=5)
                    host, selected_port = args.listen.rsplit(":", 1)
                    self.assertNotEqual(int(selected_port), preferred_port)
                    self.assertGreater(int(selected_port), 0)
                    for background in (False, True):
                        args.background = background
                        self.assertIn(f"on {args.listen};", cli.started(args))
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, int(selected_port)), timeout=5)
                    try:
                        writer.write(
                            f"GET /v1/status HTTP/1.1\r\nHost: localhost\r\n"
                            f"Authorization: Bearer {key}\r\n\r\n".encode())
                        await writer.drain()
                        response = await asyncio.wait_for(reader.read(), timeout=5)
                    finally:
                        writer.close()
                        await writer.wait_closed()
                    head, body = response.split(b"\r\n\r\n", 1)
                    self.assertTrue(head.startswith(b"HTTP/1.1 200 "), response)
                    self.assertEqual(json.loads(body)["sessions"], 0)
                finally:
                    if signal.SIGTERM in stop_handlers:
                        stop_handlers[signal.SIGTERM]()
                    else:
                        task.cancel()
                    try:
                        await asyncio.wait_for(task, timeout=5)
                    except asyncio.CancelledError:
                        pass

    async def test_service_serves_and_reports_a_new_port_when_preferred_port_is_occupied(self):
        with socket.socket() as occupied:
            occupied.bind(("127.0.0.1", 0))
            occupied.listen()
            await self.check_listener(occupied.getsockname()[1])

    async def test_port_zero_reports_the_system_selected_port(self):
        await self.check_listener(0)


if __name__ == "__main__":
    unittest.main()
