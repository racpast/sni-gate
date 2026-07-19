//! Build the public-suffix list from the configured source and, for the
//! network source, run a background cron-scheduled refresher.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::config::{PslConfig, PslSource};
use crate::suffix::SuffixList;

/// Build the initial [`SuffixList`] according to `cfg`.
pub fn load(cfg: &PslConfig) -> Result<Arc<SuffixList>> {
    let list = match cfg.source {
        PslSource::Embedded => {
            SuffixList::embedded().context("loading embedded public suffix list")?
        }
        PslSource::File => {
            let bytes = std::fs::read(&cfg.path)
                .with_context(|| format!("reading public suffix list {}", cfg.path.display()))?;
            SuffixList::from_file(&bytes)?
        }
        PslSource::Network => {
            // Prefer the on-disk cache; fall back to embedded until the first
            // successful refresh populates it.
            match std::fs::read(&cfg.path) {
                Ok(bytes) => SuffixList::from_file(&bytes).or_else(|err| {
                    tracing::warn!(error = %err, "cached PSL invalid; using embedded list");
                    SuffixList::embedded()
                })?,
                Err(_) => {
                    tracing::info!("no cached PSL yet; using embedded list until first refresh");
                    SuffixList::embedded()?
                }
            }
        }
    };
    Ok(Arc::new(list))
}

/// Spawn the background refresher for `network` mode. No-op otherwise.
pub fn spawn_refresher(cfg: &PslConfig, list: Arc<SuffixList>) {
    if cfg.source != PslSource::Network {
        return;
    }
    let cfg = cfg.clone();
    tokio::spawn(async move {
        run_refresher(cfg, list).await;
    });
}

async fn run_refresher(cfg: PslConfig, list: Arc<SuffixList>) {
    let schedule = match cron::Schedule::from_str(&cfg.cron) {
        Ok(s) => s,
        Err(err) => {
            tracing::error!(error = %err, "invalid PSL cron; refresher disabled");
            return;
        }
    };

    loop {
        let now = chrono::Local::now();
        let Some(next) = schedule.upcoming(chrono::Local).next() else {
            tracing::error!("PSL cron yields no future times; refresher stopping");
            return;
        };
        let wait = (next - now)
            .to_std()
            .unwrap_or_else(|_| Duration::from_secs(60));
        tracing::debug!(next = %next, "next PSL refresh scheduled");
        tokio::time::sleep(wait).await;

        match download(&cfg).await {
            Ok(bytes) => match list.replace_from_bytes(&bytes) {
                Ok(()) => {
                    if let Err(err) = std::fs::write(&cfg.path, &bytes) {
                        tracing::warn!(error = %err, "refreshed PSL but failed to cache to disk");
                    }
                    tracing::info!(bytes = bytes.len(), "refreshed public suffix list");
                }
                Err(err) => tracing::warn!(error = %err, "rejected refreshed PSL; keeping current"),
            },
            Err(err) => {
                tracing::warn!(error = %err, "PSL refresh download failed; keeping current")
            }
        }
    }
}

/// Download the list over HTTP(S). Runs on a blocking thread because `ureq`
/// is synchronous. Uses the configured proxy only if one is set.
async fn download(cfg: &PslConfig) -> Result<Vec<u8>> {
    let url = cfg.url.clone();
    let proxy = cfg.proxy.clone();
    let timeout = Duration::from_secs(cfg.timeout_secs);

    tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
        let mut builder = ureq::config::Config::builder().timeout_global(Some(timeout));
        if !proxy.is_empty() {
            let p = ureq::Proxy::new(&proxy).context("parsing psl.proxy")?;
            builder = builder.proxy(Some(p));
        }
        let agent: ureq::Agent = builder.build().into();
        let mut resp = agent.get(&url).call().context("PSL download request")?;
        let bytes = resp
            .body_mut()
            .read_to_vec()
            .context("reading PSL response body")?;
        anyhow::ensure!(!bytes.is_empty(), "PSL download was empty");
        Ok(bytes)
    })
    .await
    .context("PSL download task panicked")?
}
