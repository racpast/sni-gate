//! Exercise selection and passive learning through the binary, with no active
//! re-probe during the experiment. Both edges pass identical TCP health probes;
//! only completed application transfers distinguish their observed rates.
mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use common::{free_port, preamble, spawn_sni_gate, tempdir, wait_port};

struct Backend {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Backend {
    fn spawn(listener: TcpListener, byte: u8, delay: Duration) -> Self {
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let signal = stop.clone();
        let thread = thread::spawn(move || {
            while !signal.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        thread::spawn(move || {
                            stream
                                .set_read_timeout(Some(Duration::from_secs(5)))
                                .unwrap();
                            let mut request = [0u8; 4096];
                            if stream.read(&mut request).unwrap_or(0) == 0 {
                                return;
                            }
                            thread::sleep(delay);
                            let header = b"HTTP/1.1 200 OK\r\nContent-Length: 8192\r\nConnection: close\r\n\r\n";
                            let _ = stream.write_all(header);
                            let _ = stream.write_all(&[byte; 8192]);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1))
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

fn request(port: u16) -> Option<u8> {
    let mut connection = TcpStream::connect(("127.0.0.1", port)).ok()?;
    connection
        .set_read_timeout(Some(Duration::from_secs(5)))
        .ok()?;
    connection
        .write_all(b"GET / HTTP/1.1\r\nHost: data.pool.test\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut response = Vec::new();
    connection.read_to_end(&mut response).ok()?;
    let split = response.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    if response.len() - split != 8192 {
        return None;
    }
    response.get(split).copied()
}

fn request_until_success(port: u16) -> Option<u8> {
    for _ in 0..20 {
        if let Some(response) = request(port) {
            return Some(response);
        }
        thread::sleep(Duration::from_millis(25));
    }
    None
}

#[test]
fn connections_explore_and_learn_before_the_next_probe_cycle() {
    let dir = tempdir();
    let ipv4 = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream = ipv4.local_addr().unwrap().port();
    let ipv6 = TcpListener::bind(("::1", upstream)).unwrap();
    let _fast = Backend::spawn(ipv4, b'F', Duration::from_millis(30));
    let _slow = Backend::spawn(ipv6, b'S', Duration::from_millis(150));
    let listen = free_port();
    let config = format!(
        r#"{}
[pools.edges]
targets = ["127.0.0.1", "::1"]
[pools.edges.probe]
mode = "tcp"
port = {upstream}
interval = "5m"
timeout = "1s"
score_payload_bytes = 1_000_000

[[listener]]
addr = "127.0.0.1:{listen}"
[[listener.route]]
type = "http"
match_sni = [".pool.test"]
upstream = "@edges:{upstream}"
"#,
        preamble()
    );
    let _gateway = spawn_sni_gate(&config, dir.path());
    wait_port(listen);
    let mut ready = false;
    for _ in 0..100 {
        if request_until_success(listen).is_some() {
            ready = true;
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(ready, "pool never became ready");
    let mut fast = 0;
    let mut slow = 0;
    let mut late_fast = 0;
    for i in 0..112 {
        match request_until_success(listen).expect("healthy pool failed repeated requests") {
            b'F' => {
                fast += 1;
                if i >= 32 {
                    late_fast += 1;
                }
            }
            b'S' => slow += 1,
            unexpected => panic!("unexpected backend byte {unexpected}"),
        }
        // Let the receiver process the previous completed connection. This is
        // orders of magnitude shorter than the configured five-minute probe cycle.
        thread::sleep(Duration::from_millis(2));
    }
    assert!(
        fast > 0 && slow > 0,
        "no per-connection exploration: fast={fast}, slow={slow}"
    );
    assert!(
        late_fast >= 60,
        "passive learning failed: fast={fast}, slow={slow}, late_fast={late_fast}/80"
    );
}
