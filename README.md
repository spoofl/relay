# Agent rendezvous relay

Forwards end-to-end encrypted frames between the desktop app and its paired
phone when neither can accept an inbound connection. Both peers dial out and
long-poll the relay.

Python 3.10+, standard library only.

## Deployment

```sh
./run.sh
```

This starts the relay on `127.0.0.1:8787`, trying successive ports if one is
occupied. `--listen` sets the preferred address; port `0` lets the system
choose an available port. The selected address appears in the startup log
and in the startup message when using `--background` or `--log-file`.
It creates `api.key` on first run
and prints the key for you to paste into the desktop app; set
`RELAY_PRINT_API_KEY=0` to stop printing it. `./run.sh --help` lists the other
options. In production, use the systemd unit `agent-relay.service` instead.

The launcher requires Bash and runs in the foreground by default. It works
from any directory; relative key and database paths stay relative to your
current directory. Set `PY=/path/to/python3` to select another Python
interpreter. `make run` is an optional shortcut through the same launcher:

```sh
make run
make run ARGS='--listen 127.0.0.1:8787 --database pairings.sqlite3'
make run ARGS='--help'
```

The relay listens only on loopback, so publish it through a TLS reverse proxy
on a neutral hostname you control. Set `proxy_pass` to the selected address:

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

## Run as a service

Install `run.sh`, `relay.py`, and `agent_relay/` under `/opt/agent-relay/`,
keep `run.sh` executable (`chmod +x /opt/agent-relay/run.sh`), create a
dedicated `agent-relay` user, and store the key in `/etc/agent-relay/api.key`
(readable only by that user and root). Install `agent-relay.service` under
`/etc/systemd/system/`, then enable it:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now agent-relay
sudo systemctl status agent-relay
```

The unit starts the same `run.sh` in the foreground, suppresses API key output,
and sends logs to the journal. Systemd handles background operation, startup on
reboot, and restarts after failures; do not add `--background` or `--log-file`
to its command. Pairings are stored in `/var/lib/agent-relay/pairings.sqlite3`.
Use `sudo systemctl restart agent-relay` after an update,
`sudo systemctl stop agent-relay` to stop it, and
`journalctl -u agent-relay -f` to follow logs. When updating an existing
installation, copy the launcher along with the Python files before installing
the updated unit.

Reserve loopback port 8787 for the relay and point the reverse proxy at it.
When hosting payload-store on the same VPS, use its service's port 8790.

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
