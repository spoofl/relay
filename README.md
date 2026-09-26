# Agent rendezvous relay

`relay.py` is a dependency-free Python 3.10+ service that joins a desktop app
to its paired phone when neither can accept an inbound connection. Both peers
dial out and hold a poll open; the relay matches them by pairing and forwards
frames they have sealed end to end. It never holds a key or sees plaintext, so
a seized or compromised relay yields only pairing identifiers and ciphertext.

## Deployment

Point a neutral hostname you control, such as `relay.example.com`, at a VPS and
copy `relay.py` and `agent_relay/` together into a private directory there. The
relay binds to **loopback only**, so publish it through a TLS reverse proxy; the
desktop refuses a plaintext API URL except on a numeric loopback address
reached through an SSH tunnel.

```sh
./run.sh --listen 127.0.0.1:8787
```

`run.sh` creates `api.key` with `0600` permissions if it is missing and prints
the key to paste into the desktop; set `RELAY_PRINT_API_KEY=0` to suppress it.
Add `--background` to detach and `--log-file PATH` to keep its output. For
automatic restarts and reboot survival, install `agent-relay.service` instead,
and leave `--background` out of it.

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
        # Must exceed --poll-seconds, or the proxy cuts off held polls.
        proxy_read_timeout 60s;
    }
    location / { return 404; }
}
```

## API

Management routes take the service API key; session routes take a role token
issued at pairing. Every response includes `version` and `serverId` so a peer
can pin the server's identity and refuse a silent substitution.

```text
GET    /v1/status                  -> {version, serverId, sessions}
POST   /v1/sessions                -> {version, serverId, sessionId, desktopToken, phoneToken}
DELETE /v1/sessions/{sessionId}    -> {version, serverId, deleted}

POST   /v1/session/send   {seq, ct} -> {version, serverId, accepted, seq}
GET    /v1/session/recv?after={seq} -> {version, serverId, frames: [{seq, ct}]}
```

`send` enqueues a frame for **the other** role; `recv` drains your own queue,
holding for up to `--poll-seconds` while it is empty. `after` is a cursor that
also acknowledges: everything at or below it is dropped.

`seq` is assigned by the sender and must strictly increase per direction, since
it also derives the frame's nonce: a repeated or lower `seq` is refused with
`409`. A full queue is refused with `503`.

`ct` is standard base64, refused with `400` if its text contains a reserved
identity marker in any letter case. The relay never rewrites ciphertext, so a
sender whose ciphertext happens to spell a marker re-seals under a higher
`seq`; sequence numbers need not be contiguous.

## Security model

- Pairings persist in SQLite so a restart does not unpair devices. A row holds
  a random session ID, a SHA-256 hash of each role's token, and two timestamps;
  plaintext tokens appear only in the response that creates them.
- Frames are never written to disk.
- A role token authenticates a peer to the relay only: it can enqueue frames
  for its peer and drain its own queue, but cannot open a frame.
- Deleting a pairing revokes both tokens and drops both queues. Pairings idle
  past `--session-ttl-hours` are purged hourly.

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
python3 -m unittest discover -s tests
```
