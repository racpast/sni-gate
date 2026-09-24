//! End-to-end tests for named resolvers: proving `[resolvers.<name>]` actually
//! works through hermetic mock DNS servers that log every query received.

mod common;

use common::{
    eventually, free_port, preamble, spawn_mock_backend, spawn_sni_gate, tempdir, wait_port,
    MockDns,
};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, TcpStream};

/// DNS question types the mock logs.
const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;

/// A named resolver answers a route's upstream lookup, and the mock DNS log
/// proves it was asked.
#[test]
fn named_resolver_answers_upstream_lookup() {
    let dir = tempdir();
    let mock = MockDns::builder()
        .a("upstream.test", Ipv4Addr::new(127, 0, 0, 1))
        .start();
    let (backend_port, _bh) = spawn_mock_backend();
    let listen = free_port();

    let config = format!(
        r#"
[global]
resolver = "@test-dns"
address_family = "ipv4"
{preamble}

[resolvers.test-dns]
endpoint = "127.0.0.1:{dns_port}"

[[listener]]
addr = "127.0.0.1:{listen}"
  [[listener.route]]
  type = "raw"
  name = "x"
  match_sni = ["x.test"]
  upstream = "upstream.test:{backend_port}"
"#,
        preamble = preamble(),
        dns_port = mock.port(),
        listen = listen,
        backend_port = backend_port
    );

    let _gw = spawn_sni_gate(&config, dir.path());
    wait_port(listen);

    let mut s = TcpStream::connect(("127.0.0.1", listen)).unwrap();
    s.write_all(b"GET / HTTP/1.0\r\nHost: x.test\r\n\r\n")
        .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();

    assert!(resp.contains("200 OK"), "backend not reached: {resp}");
    assert!(mock.asked("upstream.test"), "resolver was not asked");
    assert_eq!(mock.count(), 1, "should be exactly one query");
}

/// Bootstrap chain: resolver A's endpoint host is resolved by resolver B (the
/// bootstrap), and the query log proves B was asked for A's host.
#[test]
fn bootstrap_resolver_answers_endpoint_lookup() {
    let dir = tempdir();

    let bootstrap_mock = MockDns::builder()
        .a("resolver-a.example", Ipv4Addr::new(127, 0, 0, 1))
        .start();

    let resolver_a_mock = MockDns::builder()
        .a("upstream.test", Ipv4Addr::new(127, 0, 0, 1))
        .start();

    let (backend_port, _bh) = spawn_mock_backend();
    let listen = free_port();

    let config = format!(
        r#"
[global]
resolver = "@resolver-a"
address_family = "ipv4"
{preamble}

[resolvers.bootstrap]
endpoint = "127.0.0.1:{bootstrap_port}"

[resolvers.resolver-a]
endpoint = "udp://resolver-a.example:{resolver_a_port}"
bootstrap = "@bootstrap"

[[listener]]
addr = "127.0.0.1:{listen}"
  [[listener.route]]
  type = "raw"
  name = "x"
  match_sni = ["x.test"]
  upstream = "upstream.test:{backend_port}"
"#,
        preamble = preamble(),
        bootstrap_port = bootstrap_mock.port(),
        resolver_a_port = resolver_a_mock.port(),
        listen = listen,
        backend_port = backend_port
    );

    let _gw = spawn_sni_gate(&config, dir.path());
    wait_port(listen);

    let mut s = TcpStream::connect(("127.0.0.1", listen)).unwrap();
    s.write_all(b"GET / HTTP/1.0\r\nHost: x.test\r\n\r\n")
        .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();

    assert!(resp.contains("200 OK"), "backend not reached");
    assert!(
        eventually(|| bootstrap_mock.asked("resolver-a.example")),
        "bootstrap resolver was not asked for the endpoint host"
    );
    assert!(
        eventually(|| resolver_a_mock.asked("upstream.test")),
        "resolver-a was not asked for upstream"
    );
}

/// `upstream` override dials a different target while the endpoint name stays
/// unchanged (for TLS transports, SNI and authority remain the original).
#[test]
fn upstream_override_changes_dial_target() {
    let dir = tempdir();
    let mock = MockDns::builder()
        .a("edge.cdn.test", Ipv4Addr::new(127, 0, 0, 1))
        .a("upstream.test", Ipv4Addr::new(127, 0, 0, 1))
        .start();
    let (backend_port, _bh) = spawn_mock_backend();
    let listen = free_port();

    // Use a plain DNS endpoint with hostname, where upstream override
    // changes the dial target.
    let config = format!(
        r#"
[global]
resolver = "@test-dns"
address_family = "ipv4"
{preamble}

[resolvers.test-dns]
endpoint = "udp://dns.original.test:{dns_port}"
upstream = "edge.cdn.test"
bootstrap = "@boot"

[resolvers.boot]
endpoint = "127.0.0.1:{dns_port}"

[[listener]]
addr = "127.0.0.1:{listen}"
  [[listener.route]]
  type = "raw"
  name = "x"
  match_sni = ["x.test"]
  upstream = "upstream.test:{backend_port}"
"#,
        preamble = preamble(),
        dns_port = mock.port(),
        listen = listen,
        backend_port = backend_port
    );

    let _gw = spawn_sni_gate(&config, dir.path());
    wait_port(listen);

    let mut s = TcpStream::connect(("127.0.0.1", listen)).unwrap();
    s.write_all(b"GET / HTTP/1.0\r\nHost: x.test\r\n\r\n")
        .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();

    assert!(resp.contains("200 OK"), "backend not reached");
    assert!(
        mock.asked("edge.cdn.test"),
        "bootstrap was not asked for the upstream override target"
    );
    assert!(
        mock.asked("upstream.test"),
        "test-dns was not asked for upstream"
    );
}

/// A dual-stack upstream whose AAAA record leads nowhere must still be reached
/// over IPv4.
///
/// This is the failure that motivates racing the two families: the name
/// publishes an AAAA, so address selection prefers it, but no host can route to
/// the documentation prefix in `2001:db8::/32` — the connect is either refused
/// outright or silently dropped. Dialing the preferred family and waiting for
/// it to fail would stall or lose the connection; the A record is right there.
#[test]
fn a_dead_aaaa_record_does_not_sink_a_dual_stack_upstream() {
    let dir = tempdir();
    let mock = MockDns::builder()
        .aaaa(
            "upstream.test",
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        )
        .a("upstream.test", Ipv4Addr::new(127, 0, 0, 1))
        .start();
    let (backend_port, _bh) = spawn_mock_backend();
    let listen = free_port();

    let config = format!(
        r#"
[global]
resolver = "@test-dns"
address_family = "dual"
{preamble}

[resolvers.test-dns]
endpoint = "127.0.0.1:{dns_port}"

[[listener]]
addr = "127.0.0.1:{listen}"
  [[listener.route]]
  type = "raw"
  name = "x"
  match_sni = ["x.test"]
  upstream = "upstream.test:{backend_port}"
"#,
        preamble = preamble(),
        dns_port = mock.port(),
        listen = listen,
        backend_port = backend_port
    );

    let _gw = spawn_sni_gate(&config, dir.path());
    wait_port(listen);

    let mut s = TcpStream::connect(("127.0.0.1", listen)).unwrap();
    s.write_all(b"GET / HTTP/1.0\r\nHost: x.test\r\n\r\n")
        .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();

    assert!(
        resp.contains("200 OK"),
        "the IPv4 leg should have carried the connection: {resp}"
    );
    assert!(
        mock.asked_type("upstream.test", QTYPE_AAAA) && mock.asked_type("upstream.test", QTYPE_A),
        "a dual-stack lookup must ask for both families: {:?}",
        mock.queries()
    );
}

/// With a NAT64 prefix configured, an answered AAAA ends the lookup.
///
/// The prefix declares a v6-only host, so a synthesized A record would be
/// another IPv6 address over the same stack — no second path, nothing to race,
/// and therefore no reason to spend a round trip asking for it.
#[test]
fn nat64_does_not_ask_for_an_a_record_it_cannot_use() {
    let dir = tempdir();
    let mock = MockDns::builder()
        .aaaa("upstream.test", Ipv6Addr::LOCALHOST)
        .a("upstream.test", Ipv4Addr::new(127, 0, 0, 1))
        .start();
    let (backend_port, _bh) = spawn_mock_backend();
    let listen = free_port();

    let config = format!(
        r#"
[global]
resolver = "@test-dns"
address_family = "dual"
nat64_prefix = "64:ff9b::"
{preamble}

[resolvers.test-dns]
endpoint = "127.0.0.1:{dns_port}"

[[listener]]
addr = "127.0.0.1:{listen}"
  [[listener.route]]
  type = "raw"
  name = "x"
  match_sni = ["x.test"]
  upstream = "upstream.test:{backend_port}"
"#,
        preamble = preamble(),
        dns_port = mock.port(),
        listen = listen,
        backend_port = backend_port
    );

    let _gw = spawn_sni_gate(&config, dir.path());
    wait_port(listen);

    // The AAAA is ::1 and the mock backend listens on 127.0.0.1, so the dial
    // itself fails. That is beside the point — what the test pins down is the
    // shape of the lookup, which the query log records either way.
    let mut s = TcpStream::connect(("127.0.0.1", listen)).unwrap();
    s.write_all(b"GET / HTTP/1.0\r\nHost: x.test\r\n\r\n")
        .unwrap();
    let mut resp = String::new();
    let _ = s.read_to_string(&mut resp);

    assert!(
        eventually(|| mock.asked_type("upstream.test", QTYPE_AAAA)),
        "the AAAA record was never requested: {:?}",
        mock.queries()
    );
    assert!(
        !mock.asked_type("upstream.test", QTYPE_A),
        "an A record is unusable under NAT64 once AAAA answered, but was still requested: {:?}",
        mock.queries()
    );
}
