# quic-link

`quic-link` is a small NAT-traversal tunnel written in Go. It lets a client
reach a TCP service (for example an SSH daemon on `127.0.0.1:22`) that lives
behind NAT, by using a public **relay** to introduce the two peers and a
UDP hole-punch to establish a direct **QUIC** connection between them.

```
 ┌────────┐   (1) WS register id + auth    ┌────────┐
 │ server │ ─────────────────────────────▶ │        │
 │ (NAT)  │ ◀── (3) punch request ──────── │  relay │
 └────────┘                                │        │
     │                                     │        │
     │ (4) UDP punch to relay ──────────▶  │        │
     │                                     └────────┘
     │                                          ▲
     │        (2) POST /client {id} + auth      │
     │   ┌──────────────────────────────────────┘
     │   │
     │   │    (5) relay returns server's public UDP addr + fingerprint
     │   ▼
     │  ┌────────┐
     └─▶│ client │  (6) direct QUIC + mTLS (fingerprint-pinned)
        └────────┘
             │
             ▼  stdin/stdout  ⇄  forwarded TCP (e.g. SSH)
```

## Components

All three roles live in the same binary, selected by the first positional
argument (`relay`, `server`, `client`):

| Role   | File        | Purpose |
|--------|-------------|---------|
| relay  | `relay.go`  | Public rendezvous service: HTTP `/server` (WebSocket) for servers, HTTP `/client` for client tunnel requests, UDP listener for hole-punch packets. |
| server | `server.go` | Runs next to the target service. Registers with the relay over WebSocket, listens for punch requests, accepts an inbound QUIC connection and pipes the stream to/from the configured TCP `-forward` address. |
| client | `client.go` | Asks the relay for a tunnel, dials the advertised UDP address over QUIC, and pipes the stream to/from its own `stdin`/`stdout`. |

## Protocol

1. The server opens a WebSocket to `<relay>/server` (carrying
   `Authorization: Token <auth-token>`) and sends a
   `ServiceRequest{id, fingerprint}`.
2. A client POSTs a `ClientTunnelRequest{id, fingerprint}` to
   `<relay>/client` (also carrying `Authorization: Token <auth-token>`).
3. The relay generates a UUID token and forwards a `PunchRequest{token,
   client_fingerprint}` to the matching server over the WebSocket.
4. The server opens a fresh UDP socket and sends the token to the relay's
   UDP port — this makes the NAT mapping visible. The relay remembers the
   public `addr` it saw for that token.
5. The relay replies to the client with `ClientTunnelResponse{address,
   server_fingerprint}`.
6. The client dials that `address` with QUIC. Both sides present
   self-signed certificates and each verifies the other's SHA-256 fingerprint
   against the value the relay delivered.
7. Once the QUIC stream is open, the client bridges it to `stdin`/`stdout`
   and the server bridges it to the TCP `-forward` target.

## Build

```
go build -o quic-link .
```

## Usage

```
quic-link [--quiet] <command> [flags]

Commands:
  relay    Run the rendezvous relay.
  server   Expose a local TCP service through a relay.
  client   Connect to a service via a relay and bridge it to stdin/stdout.
```

The `--quiet` flag is a global flag (parsed before the subcommand) and
suppresses everything below `slog.LevelError`. Use
`quic-link <command> -h` to list command-specific flags.

### Relay

Run on a host with a reachable public IP:

```
quic-link relay -port 9090 [-auth-token SECRET]
```

Listens on **tcp/PORT** (HTTP + WebSocket) and **udp/PORT** (hole-punch).
If `-auth-token` is supplied, both servers and clients must present the
same token in an `Authorization: Token …` header.

### Server

Run next to the service you want to expose:

```
quic-link server \
  -relay ws://relay.example.com:9090 \
  -id my-ssh \
  -forward 127.0.0.1:22 \
  [-auth-token SECRET]
```

### Client

Run where you want to reach the service:

```
quic-link client \
  -relay http://relay.example.com:9090 \
  -id my-ssh \
  [-auth-token SECRET]
```

Because the client bridges the QUIC stream to `stdin`/`stdout`, it
composes with OpenSSH's `ProxyCommand`:

```
ssh -o ProxyCommand='quic-link --quiet client -relay http://relay.example.com:9090 -id my-ssh -auth-token SECRET' user@my-ssh
```

### Flags

Global (must appear before the subcommand):

| Flag       | Default | Description                       |
|------------|---------|-----------------------------------|
| `--quiet`  | `false` | Suppress non-error log output.    |

`relay` subcommand:

| Flag           | Required | Default | Description                                                     |
|----------------|----------|---------|-----------------------------------------------------------------|
| `-port`        | yes      | —       | TCP/UDP port the relay listens on.                              |
| `-auth-token`  | no       | *(none)*| Shared token required from servers/clients via `Authorization`. |

`server` subcommand:

| Flag           | Required | Default | Description                                                       |
|----------------|----------|---------|-------------------------------------------------------------------|
| `-relay`       | yes      | —       | Relay URL, e.g. `ws://host:9090` (WebSocket scheme).              |
| `-id`          | yes      | —       | Service id advertised to the relay.                               |
| `-forward`     | yes      | —       | Local TCP address QUIC streams are forwarded to (e.g. `:22`).     |
| `-auth-token`  | no       | *(none)*| Token sent to the relay in `Authorization`.                       |

`client` subcommand:

| Flag           | Required | Default | Description                                                       |
|----------------|----------|---------|-------------------------------------------------------------------|
| `-relay`       | yes      | —       | Relay URL, e.g. `http://host:9090` (HTTP scheme).                 |
| `-id`          | yes      | —       | Service id to connect to.                                         |
| `-auth-token`  | no       | *(none)*| Token sent to the relay in `Authorization`.                       |

## Example: SSH into a machine behind NAT

Goal: `ssh` from your laptop into `home-box`, which sits behind a home
router with no port forwarding. You control a small VPS with a public IP
(`relay.example.com`) that both machines can reach.

### 1. On the VPS — run the relay

```
# open tcp/9090 and udp/9090 in the VPS firewall first
quic-link relay -port 9090 -auth-token s3cret
```

### 2. On `home-box` — expose sshd

`home-box` already runs `sshd` on `127.0.0.1:22`. Register it with the
relay under the id `home-ssh`:

```
quic-link server \
  -relay ws://relay.example.com:9090 \
  -id home-ssh \
  -forward 127.0.0.1:22 \
  -auth-token s3cret
```

Leave this running under a supervisor of your choice. A minimal systemd
unit:

```ini
# /etc/systemd/system/quic-link-ssh.service
[Unit]
Description=quic-link server for sshd
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/quic-link --quiet server \
  -relay ws://relay.example.com:9090 \
  -id home-ssh \
  -forward 127.0.0.1:22 \
  -auth-token s3cret
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

### 3. On your laptop — SSH through the client

The client bridges the QUIC stream to `stdin`/`stdout`, so it plugs
straight into OpenSSH's `ProxyCommand`. Add to `~/.ssh/config`:

```
Host home-box
    HostName home-ssh
    User     ali
    ProxyCommand quic-link --quiet client \
        -relay http://relay.example.com:9090 \
        -id home-ssh \
        -auth-token s3cret
```

Then just:

```
ssh home-box
```

`HostName home-ssh` is only a label OpenSSH uses for its `known_hosts`
entry — the actual network destination is whatever `ProxyCommand`
produces. Keeping it stable (e.g. matching `-id`) means SSH's host-key
pinning works across IP changes.

### 4. (Optional) scp / rsync / git over ssh

Because SSH is running over a normal OpenSSH connection, everything
that rides on SSH just works:

```
scp    file.tgz         home-box:/tmp/
rsync  -av ./project/   home-box:project/
git    clone ssh://home-box/srv/git/repo.git
```

### Notes / tips

- `sshd` provides its own end-to-end authentication and encryption, so
  even given the `quic-link` caveats in **Security notes** below, an
  attacker who MITMs the tunnel still faces SSH host-key verification
  and user authentication. Verify the host key on first connect.
- Keep the auth token out of `~/.ssh/config` and `ps` by wrapping the
  `ProxyCommand` in a small script that reads it from an env var or a
  file with `0600` permissions.
- For production, terminate TLS on the VPS (nginx/Caddy) and point
  `-relay` at `wss://relay.example.com` / `https://relay.example.com`.

## Dependencies

- [`github.com/quic-go/quic-go`](https://github.com/quic-go/quic-go) — QUIC transport
- [`github.com/gorilla/websocket`](https://github.com/gorilla/websocket) — relay ↔ server control channel
- [`github.com/google/uuid`](https://github.com/google/uuid) — punch tokens

---

## Security notes

This is a prototype. Several issues still make it **risky to expose on the
public Internet as-is**:

1. **`-auth-token` is a single shared secret, and it's optional.** If the
   relay is started without `-auth-token`, any party that can reach it can
   register services and open tunnels. Even with a token, every server and
   every client share the *same* secret, so a compromised client can
   impersonate any server id. The token is also sent in a plain
   `Authorization: Token …` header over unencrypted HTTP/WS (see below),
   so anyone on-path can capture it.

2. **Relay traffic is not encrypted.** Fingerprint pinning is done over
   plain `http://` / `ws://` (`client.go`, `server.go`). Any on-path
   attacker between clients/servers and the relay can swap fingerprints
   (and lift the auth token) and terminate QUIC on their own box. There
   is no built-in TLS on the relay — put it behind a reverse proxy such
   as nginx/Caddy with `https://` + `wss://` if you expose it publicly.

3. **Service slot hijack / starvation.** The relay keeps a list of
   registered servers per id and picks the first non-busy one for each
   tunnel request (`relay.go`). If an attacker holds a valid auth token
   they can register extra "servers" under an existing id and receive
   traffic intended for the legitimate server; its fingerprint is then
   delivered to the client through the same relay response, so the MITM
   is transparent. There is no per-id ownership or signing of
   registrations.

4. **`InsecureSkipVerify: true` on the client** (`client.go`). This is
   *intentional* — verification is delegated to a `VerifyPeerCertificate`
   callback that checks the SHA-256 fingerprint — but it means the
   security of the whole tunnel collapses to the integrity of the
   fingerprint delivered by the relay (see 2 and 3).

5. **No rate limiting or resource caps on the relay.** `punchEntrys` and
   `services` grow under load, UDP punch packets spawn a goroutine each
   (`relay.go`), and `CheckOrigin` is hard-coded to `true` (`relay.go`).
   Trivial to DoS from anywhere on the Internet.

6. **Punch-token leakage.** Any UDP packet sent to the relay's punch port
   with a currently-outstanding token registers the sender as the
   server's public address (`relay.go`). Tokens are UUIDv4 so guessing is
   infeasible, but tokens are logged at `info` level, so anyone with log
   access can redirect clients until the real server punches. Consider
   not logging tokens and binding the punch entry to the expected source.

7. **Verbose debug logging includes payload bytes** (`client.go`,
   `server.go`) — base64 of the forwarded stream is emitted at
   `slog.Debug`. If debug is ever enabled in production this leaks the
   plaintext of the tunnelled protocol.

8. **Ephemeral, unpinned end-to-end identities.** Both ends generate a
   new self-signed cert on every start (`cert.go`). There is no
   persistent identity, so a fingerprint a user might have written down
   is different on every restart; this pushes users toward
   trust-on-every-use, which composes badly with (1)–(3).

### Short version

The **major** risk is that `quic-link`'s end-to-end security relies on
the relay to honestly deliver peer fingerprints, while the only
protection for the relay itself is a single optional shared token sent
in the clear. An attacker who can either (a) reach an un-tokened relay,
(b) sniff the token on the wire, or (c) obtain the token from any
participant can register an imposter service for a given `id` and
receive client tunnels with a fingerprint the client will trust —
transparent MITM. Before using this outside a lab, at minimum: put TLS
(`https://` + `wss://`) in front of the relay, use per-identity rather
than shared tokens, and ideally sign service registrations with a
long-lived key whose public part the client already knows.
