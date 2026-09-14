"""Small formatting helpers for readable, bounded console logs."""


def peer_address(peer):
    if not peer:
        return "unknown"
    host, port = peer[:2]
    return f"[{host}]:{port}" if ":" in str(host) else f"{host}:{port}"


def log_text(value, limit=160):
    # Escape control characters so request data cannot inject terminal commands
    # or extra log lines. Keep unusually long paths and names bounded.
    if len(value) > limit:
        value = value[:limit] + "..."
    return ascii(value)


def request_label(request):
    if request is None:
        return "request"
    method, target = request[:2]
    # Query strings can contain credentials; log only the path.
    path = target.split("?", 1)[0].split("#", 1)[0]
    # The HTTP parser has already restricted methods to uppercase ASCII letters.
    method = method if len(method) <= 20 else method[:20] + "..."
    return f"{method} {log_text(path)}"
