# Telegram VPN Bot

[![github][badge-github]][link-github]
[![license][badge-license]][link-license]
[![version][badge-version]][link-crate]
[![rust-edition][badge-rust]][link-rust]
[![dependencies][badge-deps]][link-cargo]
[![tests][badge-tests]][link-ci]
[![coverage][badge-coverage]][link-coverage]

[badge-github]: https://img.shields.io/badge/github-simon3z/telegram--vpn--bot-6f57b0.svg?logo=github
[badge-license]: https://img.shields.io/badge/license-MIT-blue.svg
[badge-version]: https://img.shields.io/badge/version-0.2.0-ff8000.svg
[badge-rust]: https://img.shields.io/badge/rust-edition_2021-steelblue.svg
[badge-deps]: https://img.shields.io/badge/dependencies-11-green.svg
[badge-tests]: https://img.shields.io/badge/tests-136_passing-brightgreen.svg
[badge-coverage]: https://img.shields.io/badge/coverage-84%25-brightgreen.svg
[link-github]: https://github.com/simon3z/telegram-vpn-bot
[link-license]: LICENSE
[link-crate]: https://crates.io
[link-cargo]: Cargo.toml
[link-rust]: https://www.rust-lang.org
[link-ci]: #quick-start
[link-coverage]: #code-coverage

A Telegram bot that implements **port knocking** for WireGuard VPN access. Users knock by sending `/enable <peer>` — the bot flips the peer from inactive to active on the WireGuard interface. Disabling removes it entirely. On every restart the daemon wipes all peers clean, so the VPN surface stays zero unless someone actively enables it.

For internal design details, see [ARCHITECTURE.md](ARCHITECTURE.md).

See [`config/config.toml.example`](config/config.toml.example) for the full configuration reference.

## How It Works

1. The WireGuard interface exists and is configured by the sysadmin — but no client peers are attached.
2. A whitelisted user sends `/enable peer1` to the bot over Telegram.
3. The bot flips the peer from inactive to active on the interface.
4. The user's WireGuard client (already configured with the peer's credentials) establishes a tunnel.
5. `/disable peer1` removes the peer from the interface entirely.

The "knock" is the Telegram command. The "opened port" is the WireGuard peer on the server. No persistent open tunnels exist outside of an explicit user action.

A background monitor polls the WireGuard interface periodically. Two timeouts govern the lifecycle:

- **First-handshake timeout** (configurable, default 60 s): after `/enable`, the peer must complete its initial handshake within this window or it is auto-disabled.
- **Idle timeout** (hardcoded at 3 min): once connected, if no handshake occurs for 3 minutes — matching WireGuard's typical ~2 minute renewal cycle — the peer is auto-disabled.

In both cases the user receives a Telegram notification.

### Lifecycle

| Phase | Trigger | Effect |
|-------|---------|--------|
| **Initial** | Config loaded | Peer marked disabled |
| **Enable** | `/enable <name>` | Peer added to interface with route |
| **Connect** | First handshake completes | Tunnel established, peer marked connected |
| **Timeout** | 60s without handshake | Peer auto-disabled, user notified |
| **Idle** | 3min without handshake | Peer auto-disabled, user notified |
| **Disable** | `/disable <name>` | Peer removed from interface |
| **Reset** | Startup/Shutdown | All configured peers cleared |

## Commands

| Command | Description |
|---------|-------------|
| `/start` | Welcome message + list your peers |
| `/help` | Show available commands |
| `/status` | List your VPN peers and their active/inactive state |
| `/enable [name]` | Knock: activate a peer |
| `/disable [name]` | Remove the peer from the interface |

`name` is optional. If omitted, the first peer for that user is used.

## Quick Start

```bash
# Build
cargo build --release

# Run
./target/release/telegram-vpn-bot [config.toml]
```

Defaults to `config.toml` in the current directory if no path is given.

### Deploy as a systemd service

Copy the unit file and enable it:

```bash
cp config/telegram-vpn-bot.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now telegram-vpn-bot.service
```

See [`config/telegram-vpn-bot.service`](config/telegram-vpn-bot.service) for the full unit definition.

The daemon does **not** require root — it only needs `CAP_NET_ADMIN` and `CAP_NET_RAW`
to manage WireGuard interfaces.

```bash
useradd -c "Telegram VPN Bot" -d /var/lib/tgvpnbot -r -s /usr/sbin/nologin tgvpnbot
mkdir -m 750 /etc/tgvpnbot /var/lib/tgvpnbot
chown tgvpnbot:tgvpnbot /etc/tgvpnbot /var/lib/tgvpnbot
```

The service file applies additional hardening (`ProtectSystem=strict`,
`PrivateTmp=true`, `RestrictNamespaces=true`, etc.) so even if the binary were
compromised, the attack surface remains tightly bounded.

## Security

- **Port knocking model** — no peer is ever live unless a whitelisted user explicitly knocks via `/enable`
- **Stateless** — every startup and shutdown clears all peers from the interface; nothing persists across restarts
- **Whitelist only** — pre-approved Telegram user IDs can interact
- **Pre-configured keys** — peers use static public keys defined in `config.toml`
- **No key transmission** — users authenticate with existing local credentials; `/enable` only flips the server-side switch
- **Full removal on disable** — `/disable` removes the peer from the kernel interface entirely

## Architecture

```
Telegram (users)
    ◄──►  telegram-vpn-bot (Rust binary)
                    │
                    │  netlink (kernel WireGuard module)
                    ▼
          WireGuard interface (pre-configured, no persistent peers)
               ┌────┴────┐
               │  peers  │  ← transient: only alive during /enable
               └─────────┘
```

Every startup and shutdown performs a full peer cleanup, so the interface never retains client state between runs.

## Monitoring

The bot runs a background reconciliation loop that polls the WireGuard interface
every N seconds (default: 10s). Each cycle runs three phases:

1. **Sync connection state** — captures aggregate VPN health from the kernel.
2. **Health checks** — processes enabled peers on the interface:
   - Tracks first-handshake completion and notifies the user once.
   - Auto-disables peers that don't handshake within the configured timeout (default 60s).
   - Auto-disables idle sessions that go longer than 3 minutes without a new handshake.
3. **Reconcile** — ensures every peer's actual on-interface state matches its declared intent.

Notifications (connect, timeout, idle) are dispatched asynchronously via a separate task.

Configure poll interval and first-handshake timeout via `[vpn].status_poll_interval`
and `[vpn].first_handshake_timeout` in `config.toml`. Idle timeout is hardcoded at
3 minutes.

## Code Coverage

Install [`cargo-llvm-cov`](https://github.com/tafia/cargo-llvm-cov), then:

```bash
./scripts/coverage.sh
```

Prints a coverage summary (lines, functions, branches) and generates:
- `target/coverage/html/index.html` — interactive per-file coverage
- `target/coverage/lcov.info` — LCOV file for CI/bots

## Logging

Logs are written to stderr using the `tracing` crate. When running under systemd, these are captured automatically by journald with timestamps, service names, and structured fields.

Log levels:
- `info!` — normal operations (startup, peer changes, user actions)
- `debug!` — expected-but-unusual paths (idempotent ops, already-present peers)
- `error!` — failures (peer ops, API errors)
- `warn!` — non-fatal warnings (missing keys, degraded state)

Filter logs via `RUST_LOG` environment variable (e.g., `RUST_LOG=info`).

## Comparison with Other Solutions

| Solution | Model | Stealth | Mesh | NAT Traversal | Auth |
|---|---|---|---|---|---|
| **This bot** | Single-server port knocking | ✅ Endpoint hidden | ❌ Star only | ❌ Requires public IP | Telegram whitelist |
| [Tailscale](https://tailscale.com/) | Managed mesh VPN | ❌ Always discoverable | ✅ Full mesh | ✅ DERP relays | SSO (Google/GitHub/Okta) |
| [Headscale](https://github.com/juanfont/headscale) | Self-hosted mesh VPN | ❌ Always discoverable | ✅ Full mesh | ✅ Built-in DERP | Self-managed ACLs |
| [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-tunnel/) | Reverse proxy | 🔶 Partial | ❌ Service-only | ✅ Outbound-only | Cloudflare Access |
| [wg-easy](https://github.com/wg-easy/wg-easy) | Web UI + WireGuard | ❌ UDP port open | ❌ Star only | ❌ Requires public IP | Admin password |
| [KnockGram](https://github.com/rempairamore/KnockGram) | Python Telegram knock bot | ✅ Endpoint hidden | ❌ Star only | ❌ Requires public IP | IP + Telegram whitelist |

### When to pick this bot

- You want a WireGuard endpoint that **does not appear on port scans** — the whole point of port knocking.
- You prefer **zero persistent state** — every restart clears the interface.
- You already have a WireGuard interface and just need an authentication layer on top.
- You want a **minimal binary** (~5 MB) with no web UI, no database, no third-party coordination server.
- Your clients already have WireGuard profiles configured and you control a small set of trusted users.

### When to pick something else

- You need devices behind CGNAT or double-NAT to connect — use [Tailscale](https://tailscale.com/) or [Headscale](https://github.com/juanfont/headscale).
- You want devices to communicate with each other peer-to-peer — use a mesh solution.
- You need a browser-based admin panel or QR code generation for mobile setup — use [wg-easy](https://github.com/wg-easy/wg-easy).
- You need to expose web services publicly without opening router ports — use [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-tunnel/).
- You want per-user isolated VMs rather than shared interface peers — look at ephemeral-server bots like [DonkeyVPN](https://github.com/donkeysharp/donkeyvpn).

## License

MIT
