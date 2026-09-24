//! Bidirectional copying with cancellation-safe transfer accounting. The guard
//! outlives both pumps, so already forwarded bytes survive errors and cancellation.

use anyhow::{anyhow, Context, Result};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::time::timeout;

use crate::pool::PoolHandle;

struct Report<'a> {
    observer: Option<(&'a PoolHandle, IpAddr)>,
    started: Instant,
    upload: u64,
    download: u64,
}

impl Drop for Report<'_> {
    fn drop(&mut self) {
        let Some((pool, addr)) = self.observer else {
            return;
        };
        let bytes = self.upload.saturating_add(self.download);
        if bytes == 0 {
            return;
        }
        // TCP EOF says nothing about application-level completion. Keep the
        // entire forwarding lifetime for every exit, including normal EOF,
        // so a missing or truncated response cannot hide its waiting time.
        let elapsed = self.started.elapsed().max(Duration::from_nanos(1));
        pool.observe_transfer(addr, bytes, elapsed);
    }
}

pub(super) async fn splice<A, B>(
    a: A,
    b: B,
    idle: Duration,
    observer: Option<(&PoolHandle, IpAddr)>,
) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    let activity = Notify::new();
    let mut report = Report {
        observer,
        started: Instant::now(),
        upload: 0,
        download: 0,
    };
    let tracked = report.observer.is_some();
    let both = async {
        let a2b = async {
            pump(&mut ar, &mut bw, &activity, &mut report.upload, tracked)
                .await
                .context("proxying data (c->u)")
        };
        let b2a = async {
            pump(&mut br, &mut aw, &activity, &mut report.download, tracked)
                .await
                .context("proxying data (u->c)")
        };
        // EOF in one direction still allows the other to finish. An I/O error
        // ends the splice immediately, including when idle timeout is disabled.
        tokio::try_join!(a2b, b2a)?;
        Ok(())
    };
    tokio::select! {
        result = both => result,
        _ = idle_guard(&activity, idle) => Err(anyhow!("idle timeout")),
    }
}

async fn pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    activity: &Notify,
    bytes: &mut u64,
    tracked: bool,
) -> Result<()> {
    let mut buf = vec![0u8; super::COPY_BUF_SIZE];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        let mut sent = 0;
        while sent < n {
            let written = writer.write(&buf[sent..n]).await?;
            if written == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into());
            }
            if tracked {
                *bytes = bytes.saturating_add(written as u64);
            }
            sent += written;
            activity.notify_one();
        }
    }
}

async fn idle_guard(activity: &Notify, idle: Duration) {
    if idle.is_zero() {
        std::future::pending::<()>().await;
    }
    while timeout(idle, activity.notified()).await.is_ok() {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context as TaskContext, Poll};
    use tokio::io::ReadBuf;

    fn assert_stalled_sample_is_slow(obs: &crate::pool::PassiveObs, wait: Duration) {
        use crate::scoring::{default_nig_prior, score};
        use rand::SeedableRng;

        assert!(obs.elapsed >= wait);
        let mut stalled = default_nig_prior();
        let mut responsive = default_nig_prior();
        for _ in 0..30 {
            stalled.observe(obs.bytes as f64 / obs.elapsed.as_secs_f64(), 0.95);
            responsive.observe(8192.0 / 0.03, 0.95);
        }
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let rtt = Duration::from_millis(1);
        let stalled_wins = (0..10_000)
            .filter(|_| {
                score(rtt, &stalled, 1_000_000, &mut rng)
                    < score(rtt, &responsive, 1_000_000, &mut rng)
            })
            .count();
        assert!(
            stalled_wins < 100,
            "stalled upstream won {stalled_wins}/10000"
        );
    }

    #[tokio::test]
    async fn idle_timeout_keeps_counts_and_waiting_time() {
        let (handle, mut observations) = crate::pool::test_support::observer();
        let (mut client, gate_client) = tokio::io::duplex(8192);
        let (gate_upstream, mut upstream) = tokio::io::duplex(8192);
        let worker = tokio::spawn(async move {
            splice(
                gate_client,
                gate_upstream,
                Duration::from_millis(100),
                Some((&handle, "127.0.0.1".parse().unwrap())),
            )
            .await
        });
        let payload = [42u8; 4096];
        upstream.write_all(&payload).await.unwrap();
        let mut received = [0u8; 4096];
        client.read_exact(&mut received).await.unwrap();
        assert_eq!(received, payload);
        assert!(worker
            .await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("idle timeout"));
        let obs = observations.recv().await.unwrap();
        assert_eq!(obs.bytes, 4096);
        assert!(obs.elapsed >= Duration::from_millis(100));
        assert!(
            observations.try_recv().is_err(),
            "reported the same connection twice"
        );
    }

    #[tokio::test]
    async fn cancellation_still_reports_already_forwarded_bytes() {
        let (handle, mut observations) = crate::pool::test_support::observer();
        let (mut client, gate_client) = tokio::io::duplex(128);
        let (gate_upstream, mut upstream) = tokio::io::duplex(128);
        let worker = tokio::spawn(async move {
            splice(
                gate_client,
                gate_upstream,
                Duration::ZERO,
                Some((&handle, "127.0.0.1".parse().unwrap())),
            )
            .await
        });
        upstream.write_all(b"response").await.unwrap();
        let mut received = [0u8; 8];
        client.read_exact(&mut received).await.unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        worker.abort();
        assert!(worker.await.unwrap_err().is_cancelled());
        let obs = observations.recv().await.unwrap();
        assert_eq!(obs.bytes, 8);
        assert!(obs.elapsed >= Duration::from_millis(40));
    }

    #[tokio::test]
    async fn stalled_responses_do_not_learn_faster_than_successful_transfers() {
        // Cover both a silent upstream and one that sends only a response prefix.
        for response in [b"".as_slice(), b"HTTP/1.1 200 OK\r\n"] {
            let (handle, mut observations) = crate::pool::test_support::observer();
            let (mut client, gate_client) = tokio::io::duplex(128);
            let (gate_upstream, mut upstream) = tokio::io::duplex(128);
            let request = b"GET / HTTP/1.1\r\nHost: test\r\n\r\n";
            client.write_all(request).await.unwrap();
            let worker = tokio::spawn(async move {
                splice(
                    gate_client,
                    gate_upstream,
                    Duration::from_millis(40),
                    Some((&handle, "127.0.0.1".parse().unwrap())),
                )
                .await
            });
            let mut received = vec![0; request.len()];
            upstream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, request);
            upstream.write_all(response).await.unwrap();
            let mut received = vec![0; response.len()];
            client.read_exact(&mut received).await.unwrap();
            assert_eq!(received, response);
            assert!(worker
                .await
                .unwrap()
                .unwrap_err()
                .to_string()
                .contains("idle timeout"));

            let obs = observations.try_recv().unwrap();
            assert_eq!(obs.bytes, (request.len() + response.len()) as u64);
            assert_stalled_sample_is_slow(&obs, Duration::from_millis(40));
            assert!(observations.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn normal_eof_does_not_hide_missing_or_truncated_response() {
        for response in [
            b"".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 8192\r\n\r\nx",
        ] {
            let (handle, mut observations) = crate::pool::test_support::observer();
            let (mut client, gate_client) = tokio::io::duplex(128);
            let (gate_upstream, mut upstream) = tokio::io::duplex(128);
            let request = b"GET / HTTP/1.1\r\nHost: test\r\n\r\n";
            client.write_all(request).await.unwrap();
            client.shutdown().await.unwrap();
            let wait = Duration::from_millis(40);
            let (result, ()) = tokio::join!(
                splice(
                    gate_client,
                    gate_upstream,
                    Duration::from_secs(1),
                    Some((&handle, "127.0.0.1".parse().unwrap())),
                ),
                async {
                    let mut received = Vec::new();
                    upstream.read_to_end(&mut received).await.unwrap();
                    assert_eq!(received, request);
                    upstream.write_all(response).await.unwrap();
                    tokio::time::sleep(wait).await;
                    upstream.shutdown().await.unwrap();
                }
            );
            result.unwrap();
            let mut received = Vec::new();
            client.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, response);
            let obs = observations.try_recv().unwrap();
            assert_eq!(obs.bytes, (request.len() + response.len()) as u64);
            assert_stalled_sample_is_slow(&obs, wait);
            assert!(observations.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn clean_close_includes_time_after_the_last_write() {
        let (handle, mut observations) = crate::pool::test_support::observer();
        let (mut client, gate_client) = tokio::io::duplex(128);
        let (gate_upstream, mut upstream) = tokio::io::duplex(128);
        let worker = tokio::spawn(async move {
            splice(
                gate_client,
                gate_upstream,
                Duration::ZERO,
                Some((&handle, "127.0.0.1".parse().unwrap())),
            )
            .await
        });
        upstream.write_all(b"response").await.unwrap();
        let mut received = [0; 8];
        client.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"response");
        tokio::time::sleep(Duration::from_millis(40)).await;
        client.shutdown().await.unwrap();
        upstream.shutdown().await.unwrap();
        worker.await.unwrap().unwrap();
        let obs = observations.try_recv().unwrap();
        assert_eq!(obs.bytes, 8);
        assert!(obs.elapsed >= Duration::from_millis(40));
        assert!(observations.try_recv().is_err());
    }

    #[tokio::test]
    async fn empty_transfers_do_not_create_observations() {
        let (handle, mut observations) = crate::pool::test_support::observer();
        let (mut client, gate_client) = tokio::io::duplex(128);
        let (gate_upstream, mut upstream) = tokio::io::duplex(128);
        client.shutdown().await.unwrap();
        upstream.shutdown().await.unwrap();
        splice(
            gate_client,
            gate_upstream,
            Duration::ZERO,
            Some((&handle, "127.0.0.1".parse().unwrap())),
        )
        .await
        .unwrap();
        assert!(observations.try_recv().is_err());
    }

    struct PartialFailure {
        remaining: usize,
        delay: Duration,
        error_after: Option<Pin<Box<tokio::time::Sleep>>>,
    }

    impl AsyncRead for PartialFailure {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut TaskContext<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for PartialFailure {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.remaining == 0 {
                let delay = self.delay;
                let timer = self
                    .error_after
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(delay)));
                std::task::ready!(timer.as_mut().poll(cx));
                return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
            }
            let n = self.remaining.min(buf.len());
            self.remaining -= n;
            Poll::Ready(Ok(n))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: Pin<&mut Self>,
            _: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn write_failure_keeps_partial_bytes_and_wait_without_waiting_for_peer_eof() {
        let (handle, mut observations) = crate::pool::test_support::observer();
        let (mut client, gate_client) = tokio::io::duplex(128);
        client.write_all(b"partially delivered").await.unwrap();
        let failed = PartialFailure {
            remaining: 7,
            delay: Duration::from_millis(40),
            error_after: None,
        };
        let result = timeout(
            Duration::from_secs(2),
            splice(
                gate_client,
                failed,
                Duration::ZERO,
                Some((&handle, "127.0.0.1".parse().unwrap())),
            ),
        )
        .await
        .expect("I/O failure must finish even if the opposite reader never closes");
        assert_eq!(
            result
                .unwrap_err()
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .kind(),
            std::io::ErrorKind::BrokenPipe
        );
        let obs = observations.try_recv().unwrap();
        assert_eq!(obs.bytes, 7);
        assert!(obs.elapsed >= Duration::from_millis(40));
        assert!(observations.try_recv().is_err());
    }

    #[tokio::test]
    async fn partial_write_before_error_is_counted_exactly() {
        let mut reader = &b"partially delivered"[..];
        let mut writer = PartialFailure {
            remaining: 7,
            delay: Duration::ZERO,
            error_after: None,
        };
        let mut bytes = 0;
        assert!(
            pump(&mut reader, &mut writer, &Notify::new(), &mut bytes, true)
                .await
                .is_err()
        );
        assert_eq!(bytes, 7);
    }
}
