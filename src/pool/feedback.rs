//! Observation updates and retention. Only the pool worker mutates this state.

use super::*;

impl PoolState {
    pub(super) fn observe(&mut self, obs: PassiveObs, discount: f64, now: Instant) -> bool {
        if obs.bytes == 0 || obs.elapsed.is_zero() {
            return false;
        }
        let active = self.health.contains_key(&obs.addr);
        let health = self.health.get_mut(&obs.addr).or_else(|| {
            self.parked
                .get_mut(&obs.addr)
                .filter(|(_, expires)| *expires > now)
                .map(|(h, _)| h)
        });
        let Some(health) = health else {
            return false;
        };
        health.observe_throughput(obs.bytes, obs.elapsed, discount);
        let bps = obs.bytes as f64 / obs.elapsed.as_secs_f64();
        let prior = self
            .subnet_priors
            .entry(SubnetKey::of(obs.addr))
            .or_insert_with(|| SubnetPrior {
                model: default_nig_prior(),
                last_used: now,
            });
        prior.model.observe(bps, discount);
        prior.last_used = now;
        debug!(addr = %obs.addr, bytes = obs.bytes, throughput_mbps = bps * 8.0 / 1_000_000.0,
            "observed passive throughput");
        active
    }

    pub(super) fn prune_history(&mut self, now: Instant) {
        self.parked.retain(|_, (_, expires)| *expires > now);
        if self.parked.len() > MAX_PARKED_CANDIDATES {
            let mut oldest: Vec<_> = self
                .parked
                .iter()
                .map(|(addr, (_, expires))| (*addr, *expires))
                .collect();
            oldest.sort_unstable_by_key(|(_, expires)| *expires);
            for (addr, _) in oldest
                .into_iter()
                .take(self.parked.len() - MAX_PARKED_CANDIDATES)
            {
                self.parked.remove(&addr);
            }
        }
        let retained: HashSet<_> = self
            .health
            .keys()
            .chain(self.parked.keys())
            .copied()
            .map(SubnetKey::of)
            .collect();
        self.subnet_priors.retain(|key, prior| {
            retained.contains(key) || now.duration_since(prior.last_used) < PARK_DURATION
        });
        let mut idle: Vec<_> = self
            .subnet_priors
            .iter()
            .filter(|(key, _)| !retained.contains(key))
            .map(|(key, prior)| (*key, prior.last_used))
            .collect();
        if idle.len() > MAX_IDLE_SUBNET_PRIORS {
            idle.sort_unstable_by_key(|(_, last_used)| *last_used);
            let excess = idle.len() - MAX_IDLE_SUBNET_PRIORS;
            for (key, _) in idle.into_iter().take(excess) {
                self.subnet_priors.remove(&key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::fixture;
    use super::*;

    #[tokio::test]
    async fn bounded_feedback_and_disabled_scoring_do_not_grow_backlogs() {
        for payload in [0, 1_000_000] {
            let (pool, state, candidates) = fixture(payload);
            let handle = PoolBuilder::handle(pool.clone(), 0);
            for _ in 0..100_000 {
                handle.observe_transfer(candidates[0].addr, 1024, Duration::from_millis(1));
            }
            let accepted = if payload == 0 {
                0
            } else {
                OBSERVATION_CAPACITY
            };
            assert_eq!(state.obs_rx.len(), accepted);
            assert_eq!(
                pool.dropped_observations.load(Ordering::Relaxed),
                if payload == 0 {
                    0
                } else {
                    100_000 - accepted as u64
                }
            );
        }
    }

    #[tokio::test]
    async fn one_batch_has_a_fixed_work_budget() {
        let (pool, mut state, candidates) = fixture(1_000_000);
        let handle = PoolBuilder::handle(pool.clone(), 0);
        for _ in 0..OBSERVATION_CAPACITY {
            handle.observe_transfer(candidates[0].addr, 1024, Duration::from_millis(1));
        }
        let first = state.obs_rx.recv().await;
        process_observations(&pool, &mut state, &candidates, first);
        assert_eq!(state.obs_rx.len(), OBSERVATION_CAPACITY - OBSERVATION_BATCH);
    }

    #[tokio::test]
    async fn observations_publish_while_other_work_is_pending() {
        let (pool, mut state, candidates) = fixture(1_000_000);
        let handle = PoolBuilder::handle(pool.clone(), 0);
        let addr = candidates[0].addr;
        let before = state.health[&addr].nig.mu;
        let worker_pool = pool.clone();
        let worker = tokio::spawn(async move {
            with_observations(
                std::future::pending::<()>(),
                &worker_pool,
                &mut state,
                &candidates,
            )
            .await;
        });
        handle.observe_transfer(addr, 1_000_000, Duration::from_millis(1));
        timeout(Duration::from_secs(2), async {
            loop {
                let mu = pool.ranking.read().unwrap().per_view[0].ordered[0]
                    .throughput
                    .mu;
                if mu > before {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("feedback waited for unrelated work");
        worker.abort();
        assert!(worker.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn parked_transfers_update_the_state_restored_after_dns_rotation() {
        let (pool, mut state, candidates) = fixture(1_000_000);
        let addr = candidates[0].addr;
        let h = state.health.remove(&addr).unwrap();
        let before = h.nig.mu;
        let now = Instant::now();
        state.parked.insert(addr, (h, now + PARK_DURATION));
        state.observe(
            PassiveObs {
                addr,
                bytes: 1_000_000,
                elapsed: Duration::from_millis(1),
            },
            0.95,
            now,
        );
        let updated = state.parked[&addr].0.nig.mu;
        assert!(updated > before);
        build_candidates(&pool, &mut state);
        assert_eq!(state.health[&addr].nig.mu, updated);
        assert!(!state.parked.contains_key(&addr));
    }

    #[tokio::test]
    async fn history_is_bounded_and_expired_observations_cannot_resurrect_it() {
        let (_, mut state, candidates) = fixture(1_000_000);
        let now = Instant::now();
        let h = state.health[&candidates[0].addr].clone();
        for index in 0..(MAX_PARKED_CANDIDATES + 100) {
            let addr = IpAddr::V4(Ipv4Addr::new(10, (index / 256) as u8, index as u8, 1));
            state.parked.insert(addr, (h.clone(), now + PARK_DURATION));
            state.subnet_priors.insert(
                SubnetKey::of(addr),
                SubnetPrior {
                    model: default_nig_prior(),
                    last_used: now,
                },
            );
        }
        state.prune_history(now);
        assert_eq!(state.parked.len(), MAX_PARKED_CANDIDATES);
        assert!(state.subnet_priors.len() <= MAX_PARKED_CANDIDATES + MAX_IDLE_SUBNET_PRIORS);
        let later = now + PARK_DURATION + Duration::from_secs(1);
        state.prune_history(later);
        assert!(state.parked.is_empty());
        assert!(state.subnet_priors.is_empty());
        state.observe(
            PassiveObs {
                addr: "10.0.0.1".parse().unwrap(),
                bytes: 1024,
                elapsed: Duration::from_secs(1),
            },
            0.95,
            later,
        );
        assert!(state.subnet_priors.is_empty());
    }

    #[tokio::test]
    async fn new_candidates_cannot_revive_expired_subnet_priors() {
        for expired in [false, true] {
            let (pool, mut state, candidates) = fixture(1_000_000);
            let addr = candidates[0].addr;
            let key = SubnetKey::of(addr);
            let now = Instant::now();
            let mut learned = default_nig_prior();
            learned.observe(1_000_000_000.0, 0.95);
            let expected = if expired {
                default_nig_prior()
            } else {
                learned.clone()
            };
            state.health.clear();
            state.subnet_priors.insert(
                key,
                SubnetPrior {
                    model: learned,
                    last_used: if expired {
                        now - PARK_DURATION - Duration::from_secs(1)
                    } else {
                        now
                    },
                },
            );

            build_candidates(&pool, &mut state);

            let actual = &state.health[&addr].nig;
            assert_eq!(actual.mu, expected.mu);
            assert_eq!(actual.kappa, expected.kappa);
            assert_eq!(actual.alpha, expected.alpha);
            assert_eq!(actual.beta, expected.beta);
            assert_eq!(state.subnet_priors.contains_key(&key), !expired);
        }
    }

    #[tokio::test]
    async fn high_measurement_noise_does_not_exclude_healthy_endpoints() {
        let (pool, mut state, candidates) = fixture(1_000_000);
        let addr = candidates[0].addr;
        let h = state.health.get_mut(&addr).unwrap();
        h.kalman = KalmanRtt::new(10.0, 10.0);
        for _ in 0..1000 {
            h.kalman.update(Duration::from_millis(50));
        }
        assert!(h.kalman.variance > 5.0);
        recompute_order(&mut state, &pool.timing, &candidates);
        publish(&pool, &state, &candidates);
        assert_eq!(pool.pick(0, 443).unwrap().ip(), addr);
    }
}
