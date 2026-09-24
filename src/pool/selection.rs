//! Immutable models shared by route views; the only mutable selection state is
//! an atomic incumbent index in each published view. Every decision scores each
//! eligible endpoint once, independent of its position in the baseline order.

use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::scoring::{score, NigThroughput};

pub(super) struct Model {
    pub addr: IpAddr,
    pub rtt: Duration,
    pub throughput: NigThroughput,
}

pub(super) fn choose(
    models: &[Arc<Model>],
    incumbent: &AtomicUsize,
    payload: u64,
) -> Option<IpAddr> {
    if payload == 0 {
        return models.first().map(|m| m.addr);
    }
    let mut rng = rand::rng();
    choose_with(models, incumbent, |model| {
        score(model.rtt, &model.throughput, payload, &mut rng)
    })
}

fn choose_with(
    models: &[Arc<Model>],
    incumbent: &AtomicUsize,
    mut score: impl FnMut(&Model) -> f64,
) -> Option<IpAddr> {
    if models.is_empty() {
        return None;
    }
    let previous = incumbent.load(Ordering::Relaxed).min(models.len() - 1);
    let mut incumbent_score = 0.0;
    let mut best = 0;
    let mut best_score = f64::INFINITY;
    for (index, model) in models.iter().enumerate() {
        let value = score(model);
        if index == previous {
            incumbent_score = value;
        }
        if value < best_score {
            best = index;
            best_score = value;
        }
    }
    let (chosen, chosen_score) = if best == previous || super::beats(best_score, incumbent_score) {
        (best, best_score)
    } else {
        (previous, incumbent_score)
    };
    incumbent.store(chosen, Ordering::Relaxed);
    tracing::debug!(candidate = %models[chosen].addr, score_s = chosen_score, "selected pool candidate");
    Some(models[chosen].addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scoring::default_nig_prior;

    fn models() -> Vec<Arc<Model>> {
        (1..=32)
            .map(|i| {
                Arc::new(Model {
                    addr: std::net::Ipv4Addr::new(192, 0, 2, i).into(),
                    rtt: Duration::from_millis(20),
                    throughput: default_nig_prior(),
                })
            })
            .collect()
    }

    #[test]
    fn each_candidate_is_scored_once_and_position_does_not_change_winner() {
        let mut models = models();
        let wanted = models[31].addr;
        for _ in 0..32 {
            let mut seen = std::collections::HashSet::new();
            let chosen = choose_with(&models, &AtomicUsize::new(0), |m| {
                assert!(seen.insert(m.addr), "candidate sampled twice");
                if m.addr == wanted {
                    0.01
                } else {
                    1.0
                }
            });
            assert_eq!(chosen, Some(wanted));
            assert_eq!(seen.len(), models.len());
            models.rotate_left(1);
        }
    }

    #[test]
    fn repeated_connections_explore_without_republishing() {
        let models = models();
        let incumbent = AtomicUsize::new(0);
        let choices: std::collections::HashSet<_> = (0..2000)
            .map(|_| choose(&models, &incumbent, 1_000_000).unwrap())
            .collect();
        assert!(
            choices.len() > 16,
            "only explored {} endpoints",
            choices.len()
        );
        for _ in 0..100 {
            assert_eq!(choose(&models, &incumbent, 0), Some(models[0].addr));
        }
    }
}
