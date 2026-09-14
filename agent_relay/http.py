"""HTTP request parsing, content validation, and response framing."""

import asyncio
import re

from .config import MAX_BODY, MAX_HEAD
from .safety import audit, neutralize


def _response_content(body, content_type):
    body = audit(neutralize(body))
    content_type = audit(neutralize(content_type.encode("utf-8")))
    if b"\r" in content_type or b"\n" in content_type:
        raise ValueError("Invalid content type")
    return body, content_type


def http_response(status, body=b"", content_type="text/plain", head_only=False):
    body, content_type = _response_content(body, content_type)
    if status in (204, 304) or status < 200:
        body = b""
    head = (f"HTTP/1.1 {status} Response\r\nConnection: close\r\nCache-Control: no-store\r\nContent-Length: {len(body)}\r\n".encode()
            + b"Content-Type: " + content_type + b"\r\n\r\n")
    return audit(neutralize(head)), b"" if head_only else body


class HttpError(Exception):
    def __init__(self, status):
        self.status = status


async def read_request(reader):
    """Parse one request. Every relay route is authenticated by its router."""
    try:
        raw = await reader.readuntil(b"\r\n\r\n")
    except (asyncio.LimitOverrunError, asyncio.IncompleteReadError):
        raise HttpError(400)
    if len(raw) > MAX_HEAD:
        raise HttpError(431)
    lines = raw[:-4].split(b"\r\n")
    try:
        method, target, version = lines[0].decode("ascii").split(" ")
    except ValueError:
        raise HttpError(400)
    if version not in ("HTTP/1.1", "HTTP/1.0") or len(target) > 8192 or not target.startswith("/") or target.startswith("//"):
        raise HttpError(400)
    if not re.fullmatch(r"[A-Z]+", method) or method == "CONNECT":
        raise HttpError(405)
    headers = []
    fields = {}
    for line in lines[1:]:
        name, sep, value = line.partition(b":")
        if not sep or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) or any(byte < 32 and byte != 9 for byte in value):
            raise HttpError(400)
        name = name.decode("ascii")
        value = value.strip().decode("latin1")
        fields.setdefault(name.lower(), []).append(value)
        headers.append({"name": name, "value": value})
    if (
        any(len(fields.get(key, [])) > 1 for key in ("host", "content-length", "authorization"))
        or fields.keys() & {"transfer-encoding", "upgrade", "expect"}
    ):
        raise HttpError(400)
    if fields.get("content-encoding", ["identity"])[0] != "identity":
        raise HttpError(415)
    raw_length = fields.get("content-length", ["0"])[0]
    if not re.fullmatch(r"[0-9]{1,9}", raw_length):
        raise HttpError(400)
    length = int(raw_length)
    if length > MAX_BODY:
        raise HttpError(413)
    body = await reader.readexactly(length)
    return method, target, version, headers, fields, body


def bearer(fields):
    """The presented bearer credential, or an empty string."""
    value = fields.get("authorization", [""])[0]
    scheme, _, token = value.partition(" ")
    return token.strip() if scheme.lower() == "bearer" else ""
