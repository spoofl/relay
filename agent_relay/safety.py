"""Identity validation and sanitization at external boundaries."""

import json
import re
from urllib.parse import unquote_to_bytes


MARKERS = ((b"simhot", b"client"), (b"crawler", b"browser"))


def neutralize(data):
    for marker, replacement in MARKERS:
        data = re.sub(re.escape(marker), replacement, data, flags=re.I)
    return data


def audit(data):
    current = data
    while True:
        lowered = current.lower()
        if any(marker in lowered for marker, _ in MARKERS):
            raise ValueError("Reserved identity at external boundary")
        decoded = unquote_to_bytes(current)
        if decoded == current:
            return data
        current = decoded


def safe_text(value):
    data = neutralize(value.encode("utf-8"))
    try:
        audit(data)
    except ValueError:
        return "[reserved identity omitted]"
    return data.decode("utf-8")


def safe_json(value):
    if isinstance(value, str):
        return safe_text(value)
    if isinstance(value, list):
        return [safe_json(item) for item in value]
    if isinstance(value, dict):
        return {safe_text(key): safe_json(item) for key, item in value.items()}
    return value


def wire_json(value):
    return audit(neutralize(json.dumps(safe_json(value), ensure_ascii=False, separators=(",", ":")).encode()))
