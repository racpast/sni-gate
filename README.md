# sni-gate

A multi-listener TLS gateway that routes each connection by **SNI (TLS) or Host
(HTTP)** to an upstream, and — whenever it terminates TLS — **issues a
certificate for that name and its wildcard on the fly** from a local CA.

Upstreams can be reached four ways: **ECH** (TLS 1.3 Encrypted Client Hello),
plain **TLS**, cleartext **HTTP**, or **raw** TCP passthrough. Configuration is
hierarchical (route → listener → global) for maximum flexibility: almost every
setting can be pinned per route and otherwise inherits outward.

It merges two capabilities:
- **Dynamic per-SNI certificate issuance** — no per-site cert maintenance; any
  name gets a valid cert the first time it is requested, from a local CA you trust
  once. Coverage is not guessed: the first handshake is answered exactly, and
  wider coverage is mirrored from the upstream's own certificate. Certs are
  cached and persisted.
- **ECH re-origination** — hide the true SNI from the path to a CDN edge, giving
  ECH to clients/environments that can't do it themselves.

## How it works

```
                    issue per-SNI cert (exact, then mirrored from upstream)
                         ┌────────────────────────────────────────┐
                         │                                        ▼
 client ──TLS(SNI)/HTTP──▶ sni-gate :443 ── route by SNI/Host ──▶ upstream
                              peek (no consume)                    · ech  → TLS1.3 + ECH
                              exact>wildcard>suffix>regex          · tls  → plain TLS
                                                                   · http → cleartext
                                                                   · raw  → bare TCP (no termination)
```

1. **Peek** the connection without consuming bytes to learn the routing key
   (TLS SNI, or the HTTP `Host` header).
2. **Route** it: `exact` > `wildcard *.x` > `suffix .x` > `regex @name` > the
   listener's `default_route`.
3. For any type except `raw`, **terminate inbound TLS**, issuing a certificate
   for the SNI (and its wildcard) from the local CA, then **re-originate** to the
   upstream per the route type. `raw` splices the untouched TCP stream through.
4. No route and no `default_route` → apply the global `unmatched` policy.

## Listener address

Each `[[listener]]` must have an `addr` field. Three accepted forms:

| Form | Example | Result |
|---|---|---|
| Full IPv4 socket address | `"0.0.0.0:443"` | bind exactly as written |
| Full IPv6 socket address | `"[::]:443"` | bind exactly as written |
| Bare port (string or integer) | `"443"` or `443` | `0.0.0.0:<port>` |

The bare-port shorthand binds the **IPv4 wildcard only**, matching nginx's
`listen 443` semantics. On a dual-stack host, add a second listener on
`"[::]:443"` to also accept IPv6 connections. Hostnames are not accepted;
use a literal IP address.

`"443"` and `"0.0.0.0:443"` normalize to the same address, so writing both
in the same config is caught as a duplicate-listener error at startup.

## Route types

| Type   | Terminates inbound TLS? | Issues cert? | Upstream                         | HTTP/2                    |
|--------|-------------------------|--------------|----------------------------------|---------------------------|
| `ech`  | yes                     | yes          | TLS 1.3 + Encrypted Client Hello | mirrors upstream ALPN     |
| `tls`  | yes                     | yes          | plain TLS (optional override SNI)| mirrors upstream ALPN     |
| `http` | (cleartext in)          | yes (if TLS) | cleartext HTTP                   | h2 in → h2c out           |
| `raw`  | no                      | no           | bare TCP byte-pump               | n/a (never terminates)    |

`override_sni` works for **all** terminating types. For `ech` it is the inner
(protected) name; for `tls` it is the SNI presented to the upstream:

| `override_sni`  | SNI sent upstream                        |
|-----------------|------------------------------------------|
| *(omitted)*     | the inbound SNI verbatim                 |
| `"name"`        | exactly `name`                           |
| `""`            | **none** — no `server_name` extension    |

The empty string is deliberately distinct from omitting the field: it suppresses
the extension entirely. That is useful for an upstream addressed by IP or one
that keys only off the certificate it serves, and for ECH, where [RFC 9849 §5]
explicitly allows a ClientHelloInner to carry no SNI. With ECH the ECHConfig's
public name is still sent in the *outer* hello (the client-facing server needs
it); only the protected inner hello omits its `server_name`.

Suppressing SNI changes what is **transmitted**, not what is **trusted**: the
upstream certificate is still verified against the name the route would otherwise
have sent (the fixed name, or the reflected inbound one). An `ech` route with
`override_sni = ""` on a connection that carries no SNI/Host therefore has no
inner name to verify against and is closed.

Because resolution keys on *presence*, a route can blank out a name inherited
from its template with `override_sni = ""`.

[RFC 9849 §5]: https://www.rfc-editor.org/rfc/rfc9849.html#section-5

## Named regular expressions

Regular expressions in `match_sni` must be declared as `[regexes.<name>]` entries
and referenced with an `@` prefix. Each regex carries a `scope_suffix` declaration
that lets mirrored wildcards coexist safely with regex routes.

```toml
[regexes.cdn-upos]
pattern = "^upos-[a-z0-9-]+\\.akamaized\\.net$"
scope_suffix = ["*.akamaized.net"]

[[listener.route]]
match_sni = ["@cdn-upos", ".google.com"]
upstream = "cdn.example.com"
type = "tls"
```

### Why scope_suffix is required

When deciding whether to issue a wildcard certificate like `*.example.com`, the
router must verify that all hosts it would cover route to the same destination.
For exact/wildcard/suffix patterns, this is statically decidable. For regex
patterns, it is not—the program cannot determine which hosts a regex will match.

`scope_suffix` is the operator's declaration: "this regex may match hosts under
these domain suffixes." The router uses this to check for overlaps. If a wildcard
`*.example.com` is requested for route A, and a regex in route B declares
`scope_suffix = ["*.example.com"]`, the wildcard is refused to prevent incorrect
HTTP/2 connection coalescing.

### Syntax

`scope_suffix` uses the same pattern grammar as route matching:

- `"*.domain.com"` — matches only direct subdomains of `domain.com` (one label above it)
- `".domain.com"` — matches `domain.com` itself plus all subdomains at any depth
- `"domain.com"` — matches only the apex domain exactly

A regex may declare multiple suffixes:
```toml
scope_suffix = ["*.cdn1.example.com", "*.cdn2.example.com"]
```

**The operator is responsible for ensuring the pattern does not match hosts outside
the declared scope.** An under-declared scope may allow wildcard certificates that
should be refused, leading to incorrect routing via HTTP/2 connection coalescing.

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

## Upstream certificate verification

A terminating route re-originates the connection, so it decides for itself what
the upstream must prove. By default the upstream's certificate must chain to the
web-PKI roots **and** be valid for the name the route asked for. That is what
almost every route should keep.

It is not always satisfiable, and the reason is structural. This gateway
deliberately separates three things a browser keeps welded together: **who we
dial** (`upstream`), **what name we transmit** (`override_sni`), and **what name
we trust**. Once the second has moved, the third no longer follows from it. A
route with `override_sni = ""` sends no SNI at all, so the upstream answers with
its **default** certificate — issued for whatever name its operator chose, not
for the one the client asked for:

```
upstream TLS handshake: invalid peer certificate: certificate not valid for name
"fra-storage.example.com"; certificate is only valid for DnsName("*.example.net")
```

The handshake is sound; it simply does not prove the proposition the default
policy checks. `[verify]` is where that proposition is stated.

```toml
  [[listener.route]]
  match_sni = [".example.com"]
  type = "tls"
  override_sni = ""                 # send no SNI
    [listener.route.verify]
    name = "default.example.net"    # verify against what the upstream really serves
```

### `mode`

| `mode`    | chains to a trust anchor | certificate name checked |
|-----------|--------------------------|--------------------------|
| `"full"`  | yes                      | yes — **the default**    |
| `"chain"` | yes                      | no                       |
| `"none"`  | no                       | no                       |

### Two fields worth preferring over a weaker mode

- **`name`** — verify against a *different* name, still in `full` mode. Chain,
  expiry and name are all enforced; only the subject of the claim moves. This is
  the right answer whenever the upstream serves a stable default certificate.
  Route scope only (the route's own block or the template it `use`s), like
  `upstream` — it describes one upstream's certificate, so writing it in
  `[global]` or on a listener is a load-time error.
- **`pins`** — SPKI pins, `sha256/<base64>`, the same spelling as
  `curl --pinnedpubkey`. The upstream's end-entity public key must match one of
  them **in addition** to whatever `mode` requires; a pin binds the peer to one
  key, which no CA and no name can be substituted for. Pins are the only
  assurance left under `mode = "none"`, so a pinned `none` is reported as
  information while an unpinned one is a warning. Written as a whole list: a
  deeper scope *replaces* the inherited set rather than adding to it.

```toml
    [listener.route.verify]
    mode = "none"
    pins = ["sha256/YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg="]
```

Get a pin the same way curl documents it:

```sh
openssl s_client -connect host:443 -servername host </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | base64
```

### Private CAs

`ca_file` adds trust anchors from a PEM bundle, and `trust_webpki = false`
narrows trust to *only* those anchors (it therefore requires a `ca_file`).

```toml
    [listener.route.verify]
    ca_file = "corp-root.pem"
    trust_webpki = false
```

### Where it can be written

`[verify]` inherits field-by-field along the usual ladder (see [Hierarchical
configuration](#hierarchical-configuration)), and also applies to the two other
places this gateway performs a TLS handshake of its own:

| scope                     | applies to                                        |
|---------------------------|---------------------------------------------------|
| `[global.verify]`         | every TLS upstream in the document                |
| `[listener.verify]`       | that listener's routes                            |
| `[templates.<n>.verify]`  | whatever `use`s the template                      |
| `[listener.route.verify]` | one route — deepest scope, wins over all above    |
| `[resolvers.<n>.verify]`  | that resolver's own DoH/DoT endpoint certificate  |
| `[pools.<n>.probe.verify]`| that pool's `tls` / `https://` probe              |

A resolver's and a pool probe's blocks inherit from `[global.verify]` only; they
are top-level objects with no listener or route above them. A pool probe is
verified **separately from the routes that use the pool** — the probe measures
its own connection, so weakening a route does not weaken its pool's probing, and
a probe against an edge that answers an unmatched name needs its own `[verify]`.

Anything the active configuration cannot act on is refused by name at load time
rather than ignored: `[verify]` on an `http` or `raw` route (neither verifies a
certificate — a `raw` stream is spliced untouched, so the *client* sees the
upstream's certificate), on a plain-DNS resolver, or on a `tcp`/cleartext probe;
`name` with a mode that checks no name; `ca_file` or `trust_webpki` with
`mode = "none"`, which builds no chain at all.

### What a weakened policy does to mirrored coverage

Nothing is switched off, but the policy becomes part of the route's
[certificate scope](#certificate-scopes). Mirroring keeps working in every mode
— a route under `mode = "none"` still learns its upstream's coverage and still
gets connection coalescing — and what changes is *who it is shared with*: only
names held to the **same** policy against the **same** destination. So coverage
learned from an unauthenticated peer can never reach a certificate that a fully
verified route serves, and a client can never coalesce a strictly verified name
onto a connection whose far end was never checked.

Editing a `[verify]` block therefore moves the partition: the route starts a new
`certs/<scope>/` directory and re-learns coverage under the policy now in force,
rather than re-serving what it learned under the old one.

Every scope that resolves a weakened policy says so at startup, `INFO` when a
real assurance remains and `WARN` when none does:

```
WARN upstream certificate names are NOT checked: any certificate a public CA has
     issued for any name is accepted here [...] scope="route web" policy=chain
```

## Certificate coverage

How much a certificate covers is **not configurable**. Guessing it is what breaks
HTTP/2: a certificate broader than the upstream's own authorizes the browser to
coalesce requests the upstream will answer with `403`. Coverage is therefore
**mirrored from the upstream's real certificate**, never proposed by this gateway.

**Exact first.** The first connection for a host whose upstream has never been
observed is answered with a certificate for that one name — no wildcard. Nothing
can coalesce onto it, so no request can arrive that the upstream has not vouched
for.

**Then mirror what the upstream presented.** When a TLS-terminating route hands
the connection to a TLS/ECH upstream, the upstream's leaf is read as part of the
handshake that was happening anyway — no extra probe, no blocking — and its DNS
SANs become this gateway's coverage for that host. If `edge.example.net` answers
a handshake for `origin.example` with `{origin.example, mzz.origin.example}`,
that is exactly what the client is served, so `t4.origin.example` cannot
coalesce onto it. If the same upstream answers a handshake for
`t4.origin.example` with `{origin.example, *.origin.example}`, that connection
does carry the wildcard — coalescing is preserved precisely where the upstream
accepts it.

Observed SANs are keyed by the **requested** name, so a set learned for
`t4.origin.example` is never served to a client asking for `origin.example`.

**Rotation is handled by comparing every handshake.** The raw observed set is
stored alongside the certificate. When a later handshake presents a different set
— including a *narrower* one, which is the case that reintroduces `403` if ignored
— the cached leaf is invalidated and re-signed against the new set.

**Clipping.** A mirrored name is dropped when the upstream vouches for it but this
listener would route it elsewhere (see [Certificate
scopes](#certificate-scopes)), or when it is a wildcard directly above a public
suffix (`*.com`, `*.co.uk`) — no real upstream needs one, and honoring it would
hand out a certificate for an entire registry. The public-suffix list's **ICANN
section only** decides that: `co.uk` and `co.jp` are boundaries, while
private-section entries (`github.io`, `withgoogle.com`) are ordinary domains, so a
genuine `*.withgoogle.com` from an upstream is mirrored. Dropped names are logged
with the reason. If clipping removes everything, the exact name is served.

Certificates are persisted per `(scope, host)` as `certs/<scope>/<host>.crt`
together with the observed set that produced them, so a restart resumes mirroring
instead of re-learning it. There is nothing to migrate and no mode to switch: a
leaf that does not match what the upstream currently presents is simply re-issued.

## Certificate scopes

A browser may reuse ("coalesce") an existing HTTP/2 connection for a **second**
origin when both of these hold ([RFC 9113 §9.1.1]):

1. the second origin resolves to an address already in that connection's set, and
2. the certificate on that connection is valid for the second origin.

A coalesced request travels on the **existing** connection: no new TCP, no new TLS
handshake, and therefore **no new SNI**. sni-gate routes per connection, at
handshake time, from the SNI — so it never sees the second name and cannot
re-route it. The request is delivered to whatever upstream that connection was
already wired to.

Every name pointed at this gateway shares its address, so condition 1 always
holds here and condition 2 is the only one sni-gate controls. Hence the invariant:

> A certificate served on a connection routed to some destination is never valid
> for a name this listener would route to a **different** destination.

Two mechanisms hold it, and both are load-bearing:

- **Clipping.** Each proposed name is checked against this listener's routing
  table and dropped unless *every* host it would cover routes into the same scope.
  A wildcard is refused when a sibling is pinned elsewhere, when subdomains fall
  through to a `default_route` in another scope, when they would match no route at
  all, or when a regex route in another scope declares a `scope_suffix` that
  overlaps with the wildcard. The requesting host itself is always covered, so a
  clipped certificate is still usable.
- **Partitioning.** The certificate cache and the on-disk store are keyed by
  scope. Clipping alone would not survive accumulation: a later host under the
  same anchor but a different destination would otherwise be merged into the
  existing certificate, re-widening it after the fact.

A **scope** is a set of names that may share a certificate. Two routes share one
when they forward identically *and* are matched by the same routing table:

- **Forwarding target** — route type, dial host (or the reflecting marker), port,
  `override_sni` policy, `address_family`, `nat64_prefix`, `addr_resolver`, the
  ECH config source, and the [`[verify]` policy](#upstream-certificate-verification).
  Everything that decides where a connection goes, under what name it is
  presented, and what the far end had to prove. Settings that can change none of
  those three (timeouts, `fail`, the HTTP/2 switch, `ech_refresh`) are excluded:
  they would fragment scopes without buying safety.
- **Routing table** — a fingerprint of the listener's routes. A wildcard proven
  confined under one listener's routes may not be confined under another's, so a
  proof is only ever reused where it still holds. Listeners with identical route
  tables (the usual `0.0.0.0:443` + `[::]:443` pair) therefore still share
  certificates.

Certificates are persisted as `certs/<scope>/<registrable>.crt` (plus `.key`).
The scope directory is what stops two destinations from overwriting each other's
file — without it, a reload would serve one certificate to both routes and
re-widen coverage.

Names **within** one scope may share a mirrored wildcard, so a client can still
coalesce between them. That is deliberate: the upstream's own certificate already
permits it, and the request reaches the same configured destination, which
demultiplexes on `:authority` as any origin does. Nothing needs to be turned off
to stay safe — a host whose upstream has not been observed is served an exact
certificate, and an upstream that never presents a wildcard never yields one.

Because the verification policy is part of the scope, "the same destination" also
means "proven the same way". A route that verifies less keeps mirroring; it
simply shares what it learned with fewer names.

Every mirroring decision is logged at `INFO`, including each name clipping
dropped:

```
mirrored upstream certificate coverage (clipped to this route scope)
  scope=ech_edge.example.net_443-1f3a9c07b2d45e18 host=t4.example.com
  sans=["t4.example.com", "example.com"] dropped=["*.example.com"]
```

That is a report, not a failure — routing is unaffected. It means the routing
table sends two names under one registrable domain to different upstreams. To
widen coverage, give the conflicting hosts the same upstream or move them under a
different registrable domain.

**One case this cannot reach:** a `raw` route never terminates TLS, so the client
sees the **upstream's own** certificate and sni-gate cannot narrow it. If that
certificate covers a name routed elsewhere on the same listener, a client may
coalesce onto the raw connection and escape routing. sni-gate detects the shape —
a `raw` route sharing a registrable domain with terminating routes — and warns at
startup; it cannot fix it. Give such a route its own registrable domain, or use a
terminating type.

[RFC 9113 §9.1.1]: https://www.rfc-editor.org/rfc/rfc9113.html#section-9.1.1

## Hierarchical configuration

Overridable settings resolve from the most specific scope outward, with each
scope's optional template sitting just below that scope's own explicit values:

```
route (explicit)  →  route's template  →  listener (explicit)  →
listener's template  →  global
```

An unset value at a deeper scope inherits the next one out. This applies to
`resolver` / `ech_resolver` / `addr_resolver`, `nat64_prefix`, `address_family`,
`ech_refresh`, `require_ech`, `connect_timeout`, `idle_timeout`, and the fail
policy. So you can set, say, a different `addr_resolver` or `nat64_prefix` on a
single route while everything else inherits the global value.

The **`[http2]` block** inherits field-by-field along this same ladder, so
`enabled` / `probe` / `probe_timeout` each resolve independently — see
[HTTP/2](#http2).

The **`[verify]` block** (see [Upstream certificate
verification](#upstream-certificate-verification)) inherits the same way, so
`mode` / `pins` / `ca_file` / `trust_webpki` each resolve independently and a
route can relax one of them without restating the rest. Its `name` is the one
exception: it resolves only from the route's own block and the template that
route `use`s, because it describes a single upstream's certificate.

The entire **`[ech]` block inherits field-by-field along the same ladder**:
`mode`, `config`, `ech_domain`, `max_retries` (and `require_ech` / `ech_refresh`
/ `ech_resolver`) each resolve independently. Put the shared parts in
`[global.ech]` (or `[listener.ech]`) once and let each ECH route override only
what differs — a route may even omit `[ech]` entirely and inherit the whole thing.

## Templates

A `[templates.<name>]` table is a reusable bundle of settings referenced by a
single `use = "<name>"` on a `route`, `default_route`, or `listener`:

```toml
[templates.ech-edge]
type = "ech"
  [templates.ech-edge.ech]
  mode = "doh"
  ech_domain = "ech.example"

[[listener]]
addr = "0.0.0.0:443"
  [[listener.route]]
  match_sni = [".site-b.example", ".site-c.example"]
  use = "ech-edge"
  address_family = "ipv4"
  nat64_prefix = "64:ff9b::"
```

A template may carry every reusable field — `type`, `upstream`, `override_sni`,
the pinned `cert_file`/`key_file`, a whole `[ech]` block, `fail`, and all the
overridable knobs — but not the route *identity* (`name`, `match_sni`). It sits
in the ladder just below its scope's explicit values (see above), so a route's
own setting always wins over its template. Each scope references at most one
template, and templates cannot reference other templates (no nesting). An
unknown template name is a load-time error. `upstream` in a template only
applies when the template is used by a *route* (listeners have no upstream).

## DNS resolvers

### Quick reference: Inline resolver specs

A resolver spec may appear at any scope and takes one of these forms:

| Form                              | Meaning                         |
|-----------------------------------|---------------------------------|
| `system`                          | the OS resolver                 |
| `https://host[:port]/dns-query`   | DoH                             |
| `tls://host[:port]`               | DoT                             |
| `udp://host[:port]` or `tcp://host[:port]` | plain DNS with hostname (requires bootstrap) |
| `ip[:port]` (bare IP)             | plain DNS to an IP              |

`resolver` is the generic default. `ech_resolver` overrides it for ECH
HTTPS-record lookups; `addr_resolver` overrides it for upstream A/AAAA. Each is
independently overridable per scope.

### Named resolvers: `[resolvers.<name>]`

**Named resolvers** let you declare DNS resolvers as first-class configuration
entities with full transport control, including bootstrap chains, upstream
overrides, and ECH-on-ECH protection. Reference them by name anywhere a resolver
spec is accepted.

#### Why named resolvers?

1. **Bootstrap chains** — When the resolver endpoint itself is blocked or
   requires circumvention, resolve its hostname through a different resolver:
   ```toml
   [resolvers.bootstrap]
   endpoint = "1.1.1.1"
   
   [resolvers.primary]
   endpoint = "https://dns.blocked.example/dns-query"
   bootstrap = "@bootstrap"  # Resolve dns.blocked.example via bootstrap
   ```

2. **Upstream override (CDN fronting)** — Dial a CDN edge while presenting the
   real resolver's TLS server name:
   ```toml
   [resolvers.fronted]
   endpoint = "https://dns.blocked.example/dns-query"
   upstream = "cdn-edge.cloudfront.net"
   # Dials cdn-edge.cloudfront.net, but TLS SNI remains dns.blocked.example
   ```

3. **ECH-on-ECH** — Protect the resolver's own TLS handshake with Encrypted
   Client Hello:
   ```toml
   [resolvers.secure]
   endpoint = "https://doh.example/dns-query"
   bootstrap = "@bootstrap"
     [resolvers.secure.ech]
     mode = "doh"
     require_ech = true
   ```

#### Configuration reference

```toml
[resolvers.<name>]
endpoint = "..."           # Required: transport spec (see formats below)
upstream = "..."           # Optional: override dial target (host, port, or both)
override_sni = "..."       # Optional: TLS server name (omit=reflect, "name"=fixed, ""=suppress)
bootstrap = "..."          # Optional: @resolver-name or inline spec for endpoint resolution
address_family = "..."     # Optional: dual/ipv4/ipv6 (inherits from [global])
nat64_prefix = "..."       # Optional: e.g. "64:ff9b::/96" (inherits from [global])
connect_timeout = "..."    # Optional: per-query timeout (inherits from [global])

[resolvers.<name>.ech]     # Optional: ECH for this resolver's handshake
mode = "doh"               # or "static", "doh-with-fallback"
config = "<base64>"        # Required for static/fallback modes
ech_domain = "..."         # Override HTTPS lookup name
require_ech = true         # Fail rather than GREASE (default: true)
max_retries = 2            # ECH rejection retry budget
ech_refresh = "1h"         # Proactive rotation interval
ech_resolver = "..."       # @resolver-name or inline spec for ECH config fetch
```

#### Endpoint formats

- `system` or `""` — OS resolver (default bootstrap)
- `https://host[:port][/path]` — DNS-over-HTTPS (default port 443, path `/dns-query`)
- `tls://host[:port]` — DNS-over-TLS (default port 853)
- `udp://hostname:port` or `tcp://hostname:port` — Plain DNS with hostname (resolved via bootstrap)
- `ip[:port]` — Plain DNS to literal IP address (default port 53, no bootstrap needed)

**Note:** Bare words (without prefix) must be IP addresses to avoid collision with
resolver references. Use `udp://` or `tcp://` prefix to specify a hostname.

#### Using named resolvers

Reference by name with `@` prefix anywhere a resolver spec is accepted:

```toml
[global]
resolver = "@my-doh"          # Default for everything
addr_resolver = "@fast"       # Override for A/AAAA lookups
ech_resolver = "@secure"      # Override for HTTPS/ECH lookups

[resolvers.my-doh]
endpoint = "https://1.1.1.1/dns-query"

[resolvers.fast]
endpoint = "1.1.1.1"
address_family = "ipv4"

[resolvers.secure]
endpoint = "https://dns.google/dns-query"
```

**Fallback order:**
- `addr_resolver` → `resolver` → system
- `ech_resolver` → `addr_resolver` → `resolver` → system

#### Inheritance rules

| Setting | Inherits from `[global]` | Notes |
|---------|--------------------------|-------|
| `address_family` | ✅ Yes | IP version preference |
| `nat64_prefix` | ✅ Yes | IPv6 synthesis |
| `connect_timeout` | ✅ Yes | Per-query timeout |
| `[ech]` fields | ✅ Yes (field-by-field) | Only if `[ech]` block declared |
| `[ech]` presence | ❌ No | Must opt-in explicitly |
| `bootstrap` | ❌ No | Dependency edge, never inherited |
| `ech_resolver` | ❌ No | Dependency edge, never inherited |

**Dependency edges** (`bootstrap`, `ech_resolver`) are never inherited to prevent
implicit cycles. The `[ech]` block itself must be explicitly declared, but its
fields then inherit from `[global.ech]` field-by-field.

#### Validation

Named resolvers are validated at load time:

- **Cycle detection**: `a → b → a` dependency cycles are rejected
- **Unknown references**: `bootstrap = "@typo"` when no such resolver exists
- **Self-bootstrap**: `bootstrap = "@self"` is rejected

#### Advanced example: Multi-layer bootstrap chain

```toml
[global]
resolver = "@layer-3"

# Layer 1: IP-addressed, no dependencies
[resolvers.layer-1]
endpoint = "1.1.1.1"

# Layer 2: First DoH hop
[resolvers.layer-2]
endpoint = "https://doh-a.example/dns-query"
bootstrap = "@layer-1"

# Layer 3: Final resolver with ECH
[resolvers.layer-3]
endpoint = "https://doh-b.example/dns-query"
bootstrap = "@layer-2"
  [resolvers.layer-3.ech]
  mode = "doh"
  require_ech = true
  ech_resolver = "@layer-2"  # layer-2 fetches layer-3's ECH config
```

#### ECH rotation mechanism

Named resolvers with ECH support automatic key rotation:

**Reactive (on rejection):**
1. Query fails with ECH rejection error
2. Resolver detects the error pattern
3. Re-resolves dial address through bootstrap
4. Fetches fresh ECHConfigList via `ech_resolver`
5. Builds new resolver with new config
6. Atomically swaps the resolver
7. Retries the query (up to `max_retries`)

**Proactive (on timer):**
1. Timer fires every `ech_refresh` interval
2. Re-runs full build plan
3. Byte-compares new ECHConfigList against current
4. If unchanged: no-op (keeps existing resolver)
5. If changed: atomic swap to new resolver

Concurrent rebuilds are idempotent via generation counters.

## Upstream address family & NAT64

- `address_family = "dual"` (default) queries both families and, when both
  answer, **races** the two addresses (RFC 8305 "Happy Eyeballs"): IPv6 is
  dialed first and IPv4 joins it 250 ms later, with the first connection to
  complete carrying the traffic. A published AAAA record says the *destination*
  has IPv6, not that this host can route to it, so a dual-stack upstream stays
  reachable when the local IPv6 path is broken — including the usual case where
  the path silently drops packets instead of returning an error. The route's
  `connect_timeout` bounds the race as a whole, not each attempt.
  `"ipv4"` uses A only; `"ipv6"` uses AAAA only, and neither races.
- `nat64_prefix` (a /96 prefix such as `64:ff9b::` or `2a01:4f8:c2c:123f:64:5`)
  synthesizes an IPv6 target from a resolved IPv4 (RFC 6052). NAT64 is applied
  in `dual`/`ipv4` when only an A record is available; it is **disabled** in
  `ipv6` mode. You can also write a literal IPv6 upstream in bracket form,
  e.g. `upstream = "[2a01:4f8:c2c:123f:64:5:203:405]:443"`.
  A prefix also **turns the race off**: it declares a v6-only host, so a
  synthesized address is another IPv6 address over the same stack rather than a
  second path, and the raw IPv4 it came from is unroutable there. In `dual` with
  a prefix set, an AAAA answer therefore ends the lookup and no A query is sent.

## Upstream pools

A **pool** is a set of endpoints that all serve the same role. sni-gate probes
them in the background and routes each connection to the lowest-RTT healthy one,
failing over when it degrades and recovering without intervention. Reference one
with an `@` prefix, exactly like a named resolver or regex:

```toml
[pools.cf]
targets = ["cf.example.com", "104.16.0.0/12[4]", "172.64.0.0/13[4]"]
fallback = 0

[pools.cf.probe]
mode = "http"
url = "https://cloudflare.com/cdn-cgi/trace"
expect_status = [200]

[[listener.route]]
type = "ech"
match_sni = [".x.com"]
upstream = "@cf"
select = ["ipv4"]
```

### Targets and candidates

Two layers, and the distinction is what makes every index unambiguous:

- A **target** is one `targets` entry. It has a stable zero-based index, and that
  index is the *only* addressing unit in the config — `fallback`, `nat64.from`
  and `select` all name targets.
- A **candidate** is one probed address. One target yields several: a domain
  yields one per A/AAAA record, a CIDR one per sampled address, and the NAT64
  projection adds one per (IPv4 candidate × prefix).

Tags belong to candidates, because that is where they are knowable: whether a
domain contributes an `ipv4` or an `ipv6` endpoint is a fact about its DNS answer.
So an integer in `select` matches a **target** (selecting all its candidates)
while a string matches a **candidate tag**. For the same reason, indices are
bounds-checked at load time but tags are not — an unmatched tag simply yields no
candidates, and cannot be told apart at load from one that will match once DNS
answers.

| Target form | Type | Yields |
|---|---|---|
| `"cf.example.com"` | domain | one candidate per A/AAAA record |
| `"1.2.3.4"`, `"2606:4700::1"` | literal | one candidate |
| `"104.16.0.0/12[4]"` | CIDR, sampled | 4 candidates |
| `{ addr = "...", tags = ["edge"] }` | any of the above | custom tags appended |

`[N]` draws N random addresses. Omitting it expands the range and is **refused
above 64 addresses** — a `/12` holds a million. Samples are drawn once at startup
so RTT measurements survive; a sample that never answers is eventually replaced.

### Probing

| Mode | Tests | RTT measured to | Takes |
|---|---|---|---|
| `tcp` | TCP connect | connect completion | `port` |
| `tls` | + TLS handshake | handshake completion | `port`, **`sni`**, `[ech]` |
| `http` | + HTTP GET | first response byte | **`url`**, **`expect_status`**, `[ech]` |

Bold fields are required. Every mode also takes `timeout`, `interval`,
`degraded_interval` and `fail_threshold`.

A field a mode cannot act on is **rejected, not ignored** — `expect_status` on a
`tls` probe would otherwise leave you believing the response is checked when the
probe stops at the handshake.

An `http` probe has no `sni` or `port` of its own: the `url` already carries the
scheme, host, port and path, so there is one place to look and no way for them to
disagree. RTT stops at the first response byte, so a large body never inflates
the measurement.

`sni` and `port` belong to the **pool**, not to any consuming route: the probe
measures link quality to an edge node, not the response for one specific host. A
route then applies its own port to the address the pool chose, which is why
`upstream = "@cf:8443"` needs no second pool.

| Field | Default | Meaning |
|---|---|---|
| `port` | `443` | probed port (`tcp` / `tls`; `http` takes it from the URL) |
| `timeout` | `3s`, `5s` for `http` | per-candidate deadline |
| `interval` | `5m` | cycle for a healthy candidate |
| `degraded_interval` | `30s` | **first** retry delay, doubling up to `interval` |
| `fail_threshold` | `2` | consecutive failures before degradation |

#### Probing behind ECH

A `tls` or `https://` probe can hide its own SNI, using the same `[ech]` block
routes and resolvers use:

```toml
[pools.cf.probe.ech]
mode = "doh"                          # static | doh | doh-with-fallback
ech_domain = "crypto.cloudflare.com"  # HTTPS record queried for `ech=`
ech_resolver = "@cloudflare"          # default: the pool's own resolver
```

Its fields inherit from `[global.ech]` field-by-field, but its **presence never
does** — exactly as for a resolver, so a `[global.ech]` written for your routes
will not silently start hiding every probe. `ech_resolver` is a dependency edge
and is never inherited either.

The ECHConfigList is fetched once per probe SNI and refreshed on the HTTPS
record's own TTL (bounded by `ech_refresh`, default `1h`), never per probe. If
the server rejects ECH because its published key rotated, the probe refetches and
retries up to `max_retries` (default `2`). `require_ech` defaults to `true`; set
to `false` and a probe with no published ECHConfig falls back to GREASE, which
sends the SNI in the clear.

### How selection stays stable

- **RTT is a moving average**, not the last sample, so one unlucky measurement
  never hands the top of the ranking to a worse endpoint.
- **Switching requires a margin** of 20% or 5ms, whichever is larger. Two
  endpoints a millisecond apart would otherwise trade places every cycle, moving
  traffic for no gain and invalidating the mirrored-certificate cache each time.
- **Backoff is per-candidate and exponential.** Sampling a CIDR routinely draws
  an address nothing answers on; a single pool-wide "degraded cadence" would let
  one dead candidate pin the whole pool to the fast cycle forever.
- **The data path never probes.** `select` is resolved when routes are built, so
  serving a connection is one lock-free read of a published ranking — no
  filtering, no DNS, no I/O. A traffic burst cannot become a probe burst.

### Adaptive throughput-aware routing

By default, pools rank by **RTT alone** — lowest round-trip time wins. This works
well for latency-sensitive workloads (APIs, small requests), but for large
transfers (images, videos, downloads), **throughput matters more than handshake
latency**.

Enable composite `rtt + payload/throughput` scoring to let the pool learn which
candidates are fast for bulk transfers:

```toml
[pools.cdn.probe]
score_payload_bytes = 1_000_000  # 1 MB reference payload
```

The gateway learns throughput from completed connections and uses **Thompson
Sampling** to balance routing to known-good candidates (exploitation) with
discovering better alternatives (exploration). Candidates with uncertain
throughput occasionally draw optimistic samples and get traffic. Each connection
samples every eligible candidate once; feedback is consumed independently of
active-probe scheduling. Learning depends on the traffic actually observed.

**Hierarchical priors:** Candidates are grouped by `/24` (IPv4) or `/48` (IPv6)
subnet. Observations on one candidate improve the initial estimate for siblings
in the same subnet, accelerating learning in large pools.

**Default:** `score_payload_bytes = 0` is pure RTT ranking and disables transfer
telemetry. RTT smoothing uses Kalman, so exact rankings can differ from the earlier
EWMA estimator. Set it to your typical transfer size (100 KB
for images, 10 MB for video) to enable adaptive routing.

### NAT64 projection

```toml
[pools.cf.nat64]
prefixes = ["64:ff9b::"]
from = [1, 2]        # target indices; omit for all
timeout = "8s"       # optional: NAT64 carries an extra hop
```

Not a separate pool — an address-family projection of the same one. Synthesized
addresses are tagged `nat64` + `ipv6` and ranked **independently** of their IPv4
originals, since a slow NAT64 gateway says nothing about the native path.

### Fallback

`fallback` is a target index, used before anything is healthy and whenever
everything matching a consumer's `select` is degraded, then retired the moment one
recovers. It is drawn under the consumer's own filter, so a `select = ["nat64"]`
route falls back to a synthesized address rather than a bare IPv4 its host may not
be able to reach.

With no fallback and nothing healthy, the route's `fail` policy applies. A pool
never invents a destination.

### What a pool takes over

A pool resolves its own targets, so `address_family`, `nat64_prefix` and
`addr_resolver` are **rejected** on a route whose upstream is a pool — set them on
the pool (which has its own `resolver`) instead. Values merely *inherited* from a
broader scope are ignored rather than an error, so a global default stays usable.
`select` is likewise rejected on a non-pool upstream, where it would silently do
nothing.

Two consequences worth knowing:

- **The h2c probe is skipped** for pool upstreams. A pool has no settled address
  at startup and its choice changes afterwards, so validating one candidate would
  attest to something the data path may never dial.
- **`tls`/`ech` routes need a name.** A pool selects an address, and no hostname
  describes it, so the upstream certificate is verified against the route's SNI
  (`override_sni`, or the reflected inbound name). If neither exists the
  connection is refused with an error naming `override_sni` — verification is
  never skipped.

## ECH

For `type = "ech"` routes, the ECHConfigList is sourced by an `[ech]` block. Its
fields inherit field-by-field from `[listener.ech]` and `[global.ech]` (and any
template), so shared settings need to be written only once; a route's `[ech]`
overrides only what differs, and may be omitted entirely when the enclosing
scopes already provide a complete config:
- `mode = "static"` — a fixed inline base64 `config`.
- `mode = "doh"` — looked up in the HTTPS record of `ech_domain` (or the inner
  name) via the ECH resolver; refreshed on `ech_refresh` / the record TTL.
- `mode = "doh-with-fallback"` — DoH, falling back to the inline `config`.

An omitted `mode` inherits (it is *not* silently `doh`); `static` and
`doh-with-fallback` require a `config` to be resolvable from some scope, checked
at load time. The upstream certificate is verified against the **inner (true) name** using the
web-PKI roots. `require_ech` (default true) fails closed unless ECH is
negotiated. **ECH retry**: if the server rejects ECH (its key rotated), the
cached config is invalidated, a fresh one is fetched, and the handshake is
retried up to `max_retries` times before the fail policy applies.

## HTTP/2

HTTP/2 is opt-in per route via an inheriting `[http2]` block:

```toml
[global.http2]
enabled = false        # opt-in
probe = "warn"         # off | warn | require   (http routes only)
probe_timeout = "3s"

[[listener.route]]
type = "http"
match_sni = [".web.example"]
upstream = "127.0.0.1:8080"
  [listener.route.http2]
  enabled = true
```

**Inbound and upstream always speak the same protocol.** sni-gate splices bytes
rather than parsing HTTP, so it cannot translate between framings: there is no
"HTTP/2 in, HTTP/1.1 out" mode. `enabled` is a single coupled switch. (Doing
otherwise would mean reassembling requests, remapping streams and handling
trailers, upgrades and CONNECT — a different program.) In exchange, the data path
stays a transparent byte pump, so WebSockets and other upgrades keep working.

How the protocol is chosen depends on whether the upstream speaks ALPN:

- **`tls` / `ech` — ALPN mirroring.** The upstream is dialed *first*, offering
  the intersection of what the client offered and what sni-gate can carry
  (`h2`, `http/1.1`). Whatever the upstream selects is then advertised verbatim
  on the inbound handshake. A mismatch is structurally impossible, and an
  upstream that only does HTTP/1.1 transparently downgrades that connection —
  decided per connection against the live upstream, never from a cached guess.
  Note this dials the upstream slightly earlier in the connection's life than a
  non-HTTP/2 route does.
- **`http` — the client decides.** The upstream is cleartext and has no ALPN to
  mirror, so `[h2, http/1.1]` is offered inbound (h2 preferred). If the client
  picks h2, the decrypted bytes are spliced to the backend as **prior-knowledge
  h2c** (RFC 9113 §3.4), which is byte-identical to h2 over TLS. The backend must
  therefore be configured for h2c.
- **`raw`** never terminates TLS, so there is no ALPN to negotiate. Enabling
  `http2` on a `raw` route is a load-time error; a value merely *inherited* from
  a broader scope is ignored, so a global `enabled = true` coexists fine with
  `raw` routes.

### The h2c probe

Because nothing in the `http` data path can discover that a backend only speaks
HTTP/1.1, that one case is checked at startup: sni-gate opens a connection,
sends the HTTP/2 preface, and expects a `SETTINGS` frame back.

The probe **validates; it never decides.** No mode silently downgrades a route to
HTTP/1.1 — a probe result goes stale the moment the backend is reconfigured (an
`nginx reload` that drops `http2 on` would leave a cached verdict quietly wrong),
and a silent downgrade would hide exactly the misconfiguration this exists to
surface.

| `probe`   | On failure                                                        |
|-----------|-------------------------------------------------------------------|
| `off`     | no probe                                                          |
| `warn`    | log loudly, keep HTTP/2 enabled as configured *(default)*         |
| `require` | fail startup                                                      |

`warn` is the default so that a backend which merely has not started yet cannot
stop the gateway from booting. Backends are deduplicated, probed concurrently,
and each *attempt* is bounded by `probe_timeout`. A backend that resolved in
both address families is probed on the second only if the first could not be
reached — the data path races both, so condemning a route over one unreachable
family would be a verdict it never actually earns — which makes `2 ×
probe_timeout` the worst case for such a backend. Routes that reflect the
source SNI/Host have no fixed upstream at startup and are skipped.

Cleartext (non-TLS) inbound connections cannot use HTTP/2: a prior-knowledge h2c
request carries its `:authority` in HPACK-compressed HEADERS, which cannot be
read without decoder state, so there is no routing key. Such connections carry no
key and fall through to `default_route`.

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

```sh
# this machine; generates the CA first if needed
# Windows: needs Administrator
# macOS/Linux: needs root/sudo
sni-gate.exe --install-ca          # Windows
sudo ./sni-gate --install-ca       # macOS/Linux
```

**Windows** writes to the Local Machine Trusted Root Certification Authorities
store through CryptoAPI in-process — no PowerShell, no `certutil`, no temp
file. **macOS** uses the standard `security add-trusted-cert` tool.
**Linux** detects your distribution (Debian/Ubuntu/RHEL/Fedora/Arch) and uses
the appropriate certificate-management command (`update-ca-certificates`,
`update-ca-trust`, or `trust extract-compat`).

Installation is idempotent across all platforms: if a certificate with the same
fingerprint is already trusted, the store is left untouched. Restart the
browser afterwards to pick up the change.

Setting `ca.install_to_system_root = true` does the same thing on every startup
instead, and only warns if the store cannot be reached, so the gateway still
serves traffic. For other devices, distribute `ca/ca.crt` and import it into
their trusted-root store.

## Security notes

- `ca/ca.key` is a trusted-root private key. Keep it local; it is gitignored.
- Terminating TLS means sni-gate sees plaintext for terminating route types.
- Binding to 443/80 requires elevated privileges: Administrator on Windows,
  root/sudo on macOS/Linux.
- Upstream certificates are fully verified unless you say otherwise. A
  [`[verify]`](#upstream-certificate-verification) block that weakens this is
  reported at startup, and it is worth understanding what it costs: the client
  still sees a certificate this gateway's CA signed, so it cannot tell that the
  far end was not checked. `verify.name` and `verify.pins` both keep a real
  assurance in place and are almost always the better answer than
  `mode = "chain"` or `"none"`.

## Logging

`SNI_GATE_LOG` / `RUST_LOG` override the config `log` directive:

```sh
SNI_GATE_LOG=debug sni-gate.exe
```

## License

Dual-licensed under MIT or Apache-2.0.
