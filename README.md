# Agent rendezvous relay

Forwards end-to-end encrypted frames between the desktop app and its paired
phone when neither can accept an inbound connection. Both peers dial out and
long-poll the relay.

Python 3.10+, standard library only.

## Deployment

```sh
./run.sh
```

This starts the relay on `127.0.0.1:8787`. It creates `api.key` on first run
and prints the key for you to paste into the desktop app; set
`RELAY_PRINT_API_KEY=0` to stop printing it. `./run.sh --help` lists the other
options. In production, use the systemd unit `agent-relay.service` instead.

The relay listens only on loopback, so publish it through a TLS reverse proxy
on a neutral hostname you control:

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

Management routes take the API key and session routes take a role token, both
as `Authorization: Bearer <token>`.

| Route | Auth | Response |
|---|---|---|
| `GET /v1/status` | API key | `sessions` |
| `POST /v1/sessions` | API key | `sessionId`, `desktopToken`, `phoneToken` |
| `DELETE /v1/sessions/{sessionId}` | API key | `deleted` |
| `POST /v1/session/send` | role token | `accepted`, `seq` |
| `GET /v1/session/recv?after={seq}` | role token | `frames: [{seq, ct}]` |

Successful responses also carry `version` and `serverId`; peers can pin
`serverId` to detect a substituted relay.

- `send` takes `{seq, ct}` and queues the frame for the other peer. `seq` must
  strictly increase per sender (`409` otherwise). `503` means the other peer's
  queue is full; retry later.
- `recv` returns frames with `seq` above `after`, waiting up to
  `--poll-seconds` if there are none. Frames at or below `after` are
  acknowledged and dropped.
- `ct` is standard base64 and must not contain a reserved marker from
  `agent_relay/safety.py` in any letter case (`400` otherwise). Random
  ciphertext occasionally spells one; re-seal that frame under a higher `seq`.

## Security

The relay holds no keys and never sees plaintext. It stores only pairing
metadata, with tokens hashed; frames stay in memory. Deleting a pairing revokes
both of its tokens.

## Limits

| Limit | Value |
|---|---|
| Held poll | 25 s (`--poll-seconds`) |
| Frame size (`ct`) | 2 MiB |
| Queue per direction | 64 frames / 8 MiB |
| Frame expiry | 60 s |
| Concurrent connections | 128 |
| Idle pairing expiry | 720 h (`--session-ttl-hours`) |

## Tests

```sh
python3 -m unittest discover -s tests
```
