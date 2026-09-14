"""Shared limits, identifier shapes, and listener validation."""

import ipaddress
import re

from .safety import audit

MAX_HEAD = 64 * 1024
# One sealed frame carries one command or one reply. The ceiling matches the
# desktop's own LAN request limit, with room for base64 and the JSON envelope.
MAX_CIPHERTEXT = 2 * 1024 * 1024
MAX_BODY = MAX_CIPHERTEXT + 4096
MAX_QUEUE_FRAMES = 64
MAX_QUEUE_BYTES = 8 * 1024 * 1024
MAX_CONNECTIONS = 128
TIMEOUT = 10
# A held poll must return before any reverse proxy or mobile network decides
# the connection is idle and drops it.
POLL_SECONDS = 25
# A peer that has been gone this long has lost the conversation anyway, and
# keeping its backlog only grows what a seized server could hand over.
FRAME_TTL_SECONDS = 60
SESSION_TTL_SECONDS = 30 * 24 * 60 * 60

SESSION_ID = re.compile(r"[0-9a-f]{32}")
TOKEN = re.compile(r"[0-9a-f]{64}")
# Standard base64 only: the sender re-seals under the next sequence number
# rather than emitting anything this rejects.
CIPHERTEXT = re.compile(r"[A-Za-z0-9+/]+={0,2}")


def numeric_address(value, loopback=False):
    host, port = value.rsplit(":", 1)
    ip = ipaddress.ip_address(host.strip("[]"))
    if loopback and not ip.is_loopback:
        raise ValueError("The relay must bind to loopback; publish it through a TLS reverse proxy or SSH tunnel")
    audit(value.encode())
    port = int(port)
    if not 0 <= port <= 65535:
        raise ValueError("Invalid listen port")
    return str(ip), port
