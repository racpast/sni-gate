# sni-gate

A multi-listener TLS gateway that routes each connection by **SNI (TLS) or Host
(HTTP)** to an upstream, and — whenever it terminates TLS — **issues a
certificate for that name and its wildcard on the fly** from a local CA.

Upstreams can be reached four ways: **ECH** (TLS 1.3 Encrypted Client Hello),
plain **TLS**, cleartext **HTTP**, or **raw** TCP passthrough. Configuration is
hierarchical (route → listener → global) for maximum flexibility: almost every
setting can be pinned per route and otherwise inherits outward.

It merges two capabilities:
- **Dynamic per-SNI certificate issuance** — no per-site cert maintenance;
  any subdomain gets a valid (wildcard) cert the first time it is requested,
  from a local CA you trust once. Wildcards are public-suffix-aware; certs are
  persisted and cached.
- **ECH re-origination** — hide the true SNI from the path to a CDN edge, giving
  ECH to clients/environments that can't do it themselves.

## How it works

```
                         issue per-SNI cert (wildcard, cached, persisted)
                         ┌───────────────────────────────────────┐
                         │                                        ▼
 client ──TLS(SNI)/HTTP──▶ sni-gate :443 ── route by SNI/Host ──▶ upstream
                              peek (no consume)                    · ech  → TLS1.3 + ECH
                              exact>wildcard>suffix>regex          · tls  → plain TLS
                                                                   · http → cleartext
                                                                   · raw  → bare TCP (no termination)
```

1. **Peek** the connection without consuming bytes to learn the routing key
   (TLS SNI, or the HTTP `Host` header).
2. **Route** it: `exact` > `wildcard *.x` > `suffix .x` > `regex ~…` > the
   listener's `default_route`.
3. For any type except `raw`, **terminate inbound TLS**, issuing a certificate
   for the SNI (and its wildcard) from the local CA, then **re-originate** to the
   upstream per the route type. `raw` splices the untouched TCP stream through.
4. No route and no `default_route` → apply the global `unmatched` policy.

## Route types

| Type   | Terminates inbound TLS? | Issues cert? | Upstream                         |
|--------|-------------------------|--------------|----------------------------------|
| `ech`  | yes                     | yes          | TLS 1.3 + Encrypted Client Hello |
| `tls`  | yes                     | yes          | plain TLS (optional override SNI)|
| `http` | (cleartext in)          | yes (if TLS) | cleartext HTTP                   |
| `raw`  | no                      | no           | bare TCP byte-pump               |

`override_sni` works for **all** terminating types: unset = use the inbound SNI
verbatim; set = force that name. For `ech` it is the inner (protected) name; for
`tls` it is the SNI presented to the upstream.

## Upstream address

`upstream` names the target to dial. Either part may be defaulted:

| `upstream`          | dial host                       | dial port            |
|---------------------|---------------------------------|----------------------|
| `"host:port"`       | fixed host (IPv6 in `[...]`)    | fixed port           |
| `"host"`            | fixed host                      | this listener's port |
| `"8443"`            | matched source SNI/Host         | `8443`               |
| *(omitted)*         | matched source SNI/Host         | this listener's port |

When the host is defaulted it is the **matched source SNI/Host** — the routing
key the connection matched on (the inbound SNI or Host, with any `:port`
stripped), resolved per connection. This "reflects" each connection back to its
own name, so a listener can forward every matched name to that same name
upstream without a per-route host. `override_sni` does **not** change the dial
target; it only sets the upstream TLS server name for `tls`/`ech`. A connection
routed to a reflecting route that carries no SNI/Host is closed (there is
nothing to reflect).

## Hierarchical configuration

Overridable settings resolve from the most specific scope outward:

```
route.ech  →  route  →  listener  →  global
```

An unset value at a deeper scope inherits the next one out. This applies to
`resolver` / `ech_resolver` / `addr_resolver`, `nat64_prefix`, `address_family`,
`ech_refresh`, `require_ech`, `connect_timeout`, `idle_timeout`, and the fail
policy. So you can set, say, a different `addr_resolver` or `nat64_prefix` on a
single route while everything else inherits the global value.

## DNS resolvers

A resolver spec may appear at any scope and takes one of these forms:

| Form                              | Meaning                         |
|-----------------------------------|---------------------------------|
| `system`                          | the OS resolver                 |
| `https://host[:port]/dns-query`   | DoH                             |
| `tls://host[:port]`               | DoT                             |
| `udp://ip[:port]` / bare `ip[:port]` | plain DNS to an IP           |

`resolver` is the generic default. `ech_resolver` overrides it for ECH
HTTPS-record lookups; `addr_resolver` overrides it for upstream A/AAAA. Each is
independently overridable per scope.

## Upstream address family & NAT64

- `address_family = "dual"` (default) prefers AAAA and falls back to A;
  `"ipv4"` uses A only; `"ipv6"` uses AAAA only.
- `nat64_prefix` (a /96 prefix such as `64:ff9b::` or `2a01:4f8:c2c:123f:64:5`)
  synthesizes an IPv6 target from a resolved IPv4 (RFC 6052). NAT64 is applied
  in `dual`/`ipv4` when only an A record is available; it is **disabled** in
  `ipv6` mode. You can also write a literal IPv6 upstream in bracket form,
  e.g. `upstream = "[2a01:4f8:c2c:123f:64:5:203:405]:443"`.

## ECH

For `type = "ech"` routes, the ECHConfigList is sourced by `[listener.route.ech]`:
- `mode = "static"` — a fixed inline base64 `config`.
- `mode = "doh"` — looked up in the HTTPS record of `ech_domain` (or the inner
  name) via the ECH resolver; refreshed on `ech_refresh` / the record TTL.
- `mode = "doh-with-fallback"` — DoH, falling back to the inline `config`.

The upstream certificate is verified against the **inner (true) name** using the
web-PKI roots. `require_ech` (default true) fails closed unless ECH is
negotiated. **ECH retry**: if the server rejects ECH (its key rotated), the
cached config is invalidated, a fresh one is fetched, and the handshake is
retried up to `max_retries` times before the fail policy applies.

## Download

Each release publishes prebuilt binaries for the major platforms. Linux and
Windows come in two flavors:

- **static** (`*-linux-static`, `*-windows-static.exe`) — no runtime
  dependencies; runs on any Linux (musl) or Windows without the VC++
  redistributable. Best for portability and containers.
- **dynamic** (`*-linux`, `*-windows.exe`) — smaller; links the platform's
  libc / CRT.

macOS ships a single (dynamic) binary per architecture, as libSystem cannot be
linked statically on that platform. `SHA256SUMS` accompanies every release.

## Build

Requires a stable Rust toolchain and (on Windows) NASM + a C toolchain for the
aws-lc-rs dependency, which provides the HPKE suites ECH needs.

```sh
cargo build --release
# or, reproducible & privacy-hardened (strips symbols, remaps build paths):
./build-release.sh

# Fully static Linux build (no glibc dependency):
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
# Fully static Windows CRT (like C's /MT):
RUSTFLAGS="-Ctarget-feature=+crt-static" cargo build --release
```

## Configure and run

```sh
cp sni-gate.example.toml sni-gate.toml
# edit sni-gate.toml
sni-gate.exe               # loads ./sni-gate.toml
sni-gate.exe -c <path>     # or an explicit path
```

See [`sni-gate.example.toml`](sni-gate.example.toml) for every option.

## Trusting the CA

The CA is generated on first run at the `[ca]` paths. Import the **certificate**
(never the key) into each device that should trust issued certs:

```powershell
# this machine, as Administrator
powershell -ExecutionPolicy Bypass -File scripts\install-ca-windows.ps1
```

Or set `ca.install_to_system_root = true` to install it automatically on startup
(idempotent; Administrator required). For other devices, distribute `ca/ca.crt`
and import it into their trusted-root store.

## Security notes

- `ca/ca.key` is a trusted-root private key. Keep it local; it is gitignored.
- Terminating TLS means sni-gate sees plaintext for terminating route types.
- Binding to 443/80 requires Administrator on Windows.

## Logging

`SNI_GATE_LOG` / `RUST_LOG` override the config `log` directive:

```sh
SNI_GATE_LOG=debug sni-gate.exe
```

## License

Dual-licensed under MIT or Apache-2.0.
