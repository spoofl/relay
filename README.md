# Agent rendezvous relay

`relay.py` starts a Python 3.10+ service with no third-party dependencies. It
joins a desktop app to its paired phone when neither can accept an inbound
connection — the desktop behind home NAT, the phone on a mobile network. Both
peers dial out to this service and hold a poll open; it matches them by pairing
and forwards sealed frames between them.

The relay never holds a key and never sees a plaintext payload. Frames are
sealed end to end by the two peers, so a seized or compromised relay yields
pairing identifiers and ciphertext, nothing else.

## What it does and does not store

Pairings are persisted in SQLite so restarting the service does not unpair
every device. A pairing row holds a random session identifier, a SHA-256 hash
of each role's bearer token, and two timestamps. Plaintext tokens exist only in
the response that creates them.

Frames are held in memory only, per direction, bounded to 64 frames or 8 MiB
and dropped after 60 seconds. A peer that has been gone longer than that has
lost the conversation anyway, and a backlog on disk would only widen what a
seized server can produce.

## Deployment

Use a neutral hostname you control, for example `relay.example.com`, with an A
record pointing at the VPS. Copy `relay.py` and the `agent_relay/` directory
together to a private directory on the VPS.

The relay serves **loopback only** and refuses any other bind address. Publish
it through a TLS reverse proxy; the desktop refuses a plaintext API URL except
on a numeric loopback address reached through an SSH tunnel.

```sh
umask 077
python3 -c 'import secrets; print(secrets.token_hex(32))' > api.key
python3 relay.py \
  --listen 127.0.0.1:8787 \
  --api-key-file api.key \
  --database pairings.sqlite3
```

`run.sh` does the same and creates `api.key` on first launch with `0600`
permissions, printing the key so you can paste it into the desktop:

```sh
./run.sh --listen 127.0.0.1:8787
```

Set `RELAY_PRINT_API_KEY=0` to suppress that line. Add `--background` to detach
from the terminal and `--log-file PATH` to keep its output. For reboot survival
and automatic restarts, install `agent-relay.service` instead, which manages
the process itself — leave `--background` out of it.

### Nginx

```nginx
server {
    listen 443 ssl;
    server_name relay.example.com;
    ssl_certificate /etc/letsencrypt/live/relay.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay.example.com/privkey.pem;
    server_tokens off;
    client_max_body_size 3m;

    location /v1/ {
        proxy_pass http://127.0.0.1:8787;
        proxy_set_header Host $host;
        proxy_set_header Authorization $http_authorization;
        proxy_http_version 1.1;
        proxy_buffering off;
        # A held poll must outlive the proxy's idle timeout.
        proxy_read_timeout 60s;
    }
    location / { return 404; }
}
```

Keep `proxy_read_timeout` above `--poll-seconds` (default 25). A proxy that
times out first turns every held poll into an error the peers have to retry.

## API

All routes are authenticated. Management routes take the service API key;
session routes take a role token issued at pairing. Every response repeats
`version` and `serverId` so a peer can pin the server's identity for the life
of a connection and refuse a silent substitution.

```text
GET    /v1/status                  -> {version, serverId, sessions}
POST   /v1/sessions                -> {version, serverId, sessionId, desktopToken, phoneToken}
DELETE /v1/sessions/{sessionId}    -> {version, serverId, deleted}

POST   /v1/session/send   {seq, ct} -> {version, serverId, accepted, seq}
GET    /v1/session/recv?after={seq} -> {version, serverId, frames: [{seq, ct}]}
```

`send` enqueues a frame for **the other** role; `recv` drains your own queue and
holds for up to `--poll-seconds` when it is empty, returning as soon as a frame
arrives. `after` is a cursor that also acknowledges: everything at or below it
is dropped.

`seq` is assigned by the sender and must strictly increase per direction,
because it also derives that frame's encryption nonce. A repeated or lowered
sequence number is refused with `409`, which keeps a replayed frame out of the
queue and mirrors the check the receiving peer makes before opening the seal.
A full queue is refused with `503` rather than dropping a frame silently.

### Ciphertext is judged as bytes, not as meaning

`ct` is standard base64 and must not contain a reserved identity marker in any
letter case. The relay cannot open a frame, so it judges only the bytes it will
actually transmit; base64 that merely *decodes* to a marker is ordinary opaque
payload, because the sending peer neutralized its plaintext before sealing.

Base64 of random ciphertext spells a six-letter marker roughly once in tens of
thousands of megabyte frames. A correct peer handles that by re-sealing under
the next sequence number, which changes the ciphertext completely — sequence
numbers must increase but need not be contiguous. The relay refuses such a
frame with `400` rather than rewriting it, because rewriting ciphertext
destroys exactly what it claims to protect.

## Security model

- One compromised relay does not compromise a session. It holds no key
  material and forwards sealed frames.
- A role token authenticates a peer to the relay only. It grants the ability to
  enqueue frames to that pairing's peer and to drain that pairing's own queue —
  not the ability to read a frame.
- Deleting a pairing revokes both tokens at once and drops both queues.
- Pairings idle past `--session-ttl-hours` (default 720, thirty days) are purged
  hourly.

## Limits

| Setting | Default |
|---|---|
| Held poll | 25 s (`--poll-seconds`) |
| Frame ciphertext | 2 MiB |
| Queue per direction | 64 frames / 8 MiB |
| Frame retention | 60 s |
| Concurrent connections | 128 |
| Pairing retention | 720 h (`--session-ttl-hours`) |

## Tests

```sh
python3 -m compileall -q relay.py agent_relay tests
bash -n run.sh
python3 -m unittest discover -s tests
```
