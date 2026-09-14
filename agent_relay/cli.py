"""Command-line arguments and service listener lifecycle."""

import argparse
import asyncio
import contextlib
import logging
import os
from pathlib import Path
import signal
import sqlite3

from .background import begin
from .config import MAX_HEAD, numeric_address
from .log import peer_address
from .relay import Relay
from .sessions import Sessions

logger = logging.getLogger(__name__)

PURGE_INTERVAL_SECONDS = 3600


async def _purge_idle(sessions):
    while True:
        await asyncio.sleep(PURGE_INTERVAL_SECONDS)
        dropped = sessions.purge()
        if dropped:
            logger.info("PAIR    purged %d idle session(s) | sessions=%d", dropped, sessions.count())


async def run(args, ready=None):
    loop = asyncio.get_running_loop()
    bind = numeric_address(args.listen, loopback=True)
    if not 1 <= args.poll_seconds <= 300:
        raise ValueError("Held polls must last between 1 and 300 seconds")
    if args.session_ttl_hours < 1:
        raise ValueError("Pairings must be retained for at least one hour")
    key = Path(args.api_key_file).read_text().strip()
    sessions = Sessions(args.database, args.session_ttl_hours * 3600)
    relay = Relay(sessions, key, args.poll_seconds)
    sessions.purge()
    server = await asyncio.start_server(relay.http, *bind, limit=MAX_HEAD)
    purge = asyncio.create_task(_purge_idle(sessions))
    try:
        logger.info("READY   relay serving %d pairing(s) | server=%s", sessions.count(), sessions.server_id)
        logger.info("HTTP    listening on %s | held polls %ds | session traffic logs at DEBUG",
                    peer_address(server.sockets[0].getsockname()), args.poll_seconds)
        stop = asyncio.Event()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop.set)
        if ready:
            ready()
        await stop.wait()
    finally:
        purge.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await purge
        server.close()
        await server.wait_closed()
    logger.info("STOP    Relay stopped")


def started(args):
    where = f"logs at {args.log_file}" if args.log_file else "logs discarded without --log-file"
    if not args.background:
        return f"Relay started; {where}\n"
    return f"Relay running in the background (PID {os.getpid()}); {where}\nStop it with: kill {os.getpid()}\n"


def main():
    parser = argparse.ArgumentParser(description="Rendezvous relay joining the desktop app and its paired phone")
    parser.add_argument("--listen", default="127.0.0.1:8787",
                        help="Loopback address to serve; publish it through a TLS reverse proxy")
    parser.add_argument("--api-key-file", required=True)
    parser.add_argument("--database", default="pairings.sqlite3")
    parser.add_argument("--poll-seconds", type=int, default=25,
                        help="How long a held poll waits for a frame before answering empty")
    parser.add_argument("--session-ttl-hours", type=int, default=720,
                        help="Drop a pairing after this many hours without contact")
    parser.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
                        default="INFO", type=str.upper, help="Console log level (default: INFO)")
    parser.add_argument("--background", action="store_true",
                        help="Keep relaying after the terminal closes; prints the process ID")
    parser.add_argument("--log-file", help="Append log output to this file instead of the terminal")
    args = parser.parse_args()
    os.umask(0o077)
    if args.background and not hasattr(os, "fork"):
        parser.exit(1, "Background mode needs a system that can fork; use a service manager instead\n")
    try:
        launch = begin(args.background, args.log_file)
    except OSError as error:
        parser.exit(1, f"Could not open the log file: {error}\n")
    logging.basicConfig(level=args.log_level, format="%(asctime)s | %(levelname)-7s | %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S")
    try:
        asyncio.run(run(args, lambda: launch.ready(started(args))))
    except (ValueError, OSError, sqlite3.Error) as error:
        message = f"Relay could not start: {error}\n"
        launch.failed(message)
        parser.exit(1, message)
