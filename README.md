# wpmulti

Multi-session WireGuard proxy: **N WireGuard sessions in a single process**, sharing one userspace network stack, exposing one SOCKS5 + one HTTP proxy. Every new connection (flow) is assigned to a tunnel round-robin, so you get **N distinct egress IPs** from a single port pair.

Forked from [windtf/wireproxy](https://github.com/windtf/wireproxy) — the single-session engine (`wireproxy`) is intact; `wpmulti` is the new multi-session binary.

## Why

Cloudflare WARP assigns a **different egress IPv6 per WireGuard session**, even for the same account. Running N `wireproxy` processes for N IPs wastes RAM (one full network stack per process). `wpmulti` runs N sessions in one process with **one shared gVisor netstack**:

| Sessions | RAM (idle) | Startup |
|----------|------------|---------|
| 100      | ~46 MB     | ~2 s    |
| 200      | ~82 MB     | ~4 s    |

(~0.4 MB marginal per session; ~12 MB base for the single stack. 1200 sessions ≈ 500 MB.)

## How it works

- One `netstack.CreateNetTUN` for all sessions.
- Each WireGuard device gets a `deviceTun` wrapper around the shared `tun.Device`.
- A `flowMux` dispatcher reads outbound packets from the stack, extracts the 5-tuple (IP + TCP/UDP ports), and routes each **flow** to a tunnel: round-robin for new flows, sticky affinity afterwards. Sticky matters — a TCP connection split across tunnels would show two source IPs to the server and break.
- Inbound packets from any tunnel go straight back into the shared stack, which demultiplexes by connection tuple. No mapping needed.
- **No netlink route listener**: wireguard-go creates one netlink socket per device for sticky-socket route monitoring, but kernels (notably Android's) cap netlink multicast memberships — killing us at ~75 devices with `EINVAL`. `wpmulti` wraps the bind so the listener is skipped; we don't need route-change notifications for proxied connections.
- **Parallel startup**: sessions come up in 8 parallel workers (~2 s for 100 sessions vs ~90 s sequential).
- One bad config never kills the rest: per-session failures are logged and skipped.

## Usage

```bash
# N WireGuard configs (plain wgcf-profile.conf copies work)
mkdir -p wp-conf
for i in $(seq 1 100); do
  cp wgcf-profile.conf "wp-conf/$(printf 'sess-%04d.conf' "$i")"
done

# One SOCKS5 + one HTTP proxy for all N sessions
./wpmulti --conf-dir ./wp-conf \
  --socks 127.0.0.1:1080 \
  --http 127.0.0.1:2080
```

Test distinct egress IPs:

```bash
for i in $(seq 1 8); do
  curl -s -x http://127.0.0.1:2080 https://api6.ipify.org; echo
done
```

## Endpoint DNS fallback

`StartMultiTun` resolves `Endpoint` hostnames itself: system DNS first, then `1.1.1.1`, then `8.8.8.8` (IPv4 preferred, cached per hostname). Configs are rewritten with literal IPs before parsing, so it works even when the system resolver is dead (e.g. pointing at `[::1]:53` with nothing listening).

## Build

```bash
go build ./cmd/wpmulti/          # host platform
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ./cmd/wpmulti/   # e.g. phones
```

The original `wireproxy` single-session binary is still available via `go build ./cmd/wireproxy/`.

## License

MIT — see [LICENSE](LICENSE). Upstream wireproxy is also MIT (windtf).
