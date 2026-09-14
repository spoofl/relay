#!/usr/bin/env python3
"""CLI entry point and compatibility imports for the rendezvous relay."""

from agent_relay.background import Launch, begin, detach, redirect
from agent_relay.cli import main, run, started
from agent_relay.config import (
    CIPHERTEXT,
    FRAME_TTL_SECONDS,
    MAX_BODY,
    MAX_CIPHERTEXT,
    MAX_CONNECTIONS,
    MAX_HEAD,
    MAX_QUEUE_BYTES,
    MAX_QUEUE_FRAMES,
    POLL_SECONDS,
    SESSION_ID,
    SESSION_TTL_SECONDS,
    TIMEOUT,
    TOKEN,
    numeric_address,
)
from agent_relay.http import HttpError, bearer, http_response, read_request
from agent_relay.relay import Relay
from agent_relay.safety import MARKERS, audit, neutralize, safe_json, safe_text, wire_json
from agent_relay.sessions import (
    DESKTOP,
    PHONE,
    Inbox,
    QueueFull,
    ReplayedSequence,
    Sessions,
    peer_role,
    token_hash,
)


if __name__ == "__main__":
    main()
