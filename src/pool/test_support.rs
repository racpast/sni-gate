use super::*;

pub(super) fn fixture(payload: u64) -> (Arc<Pool>, PoolState, Vec<Candidate>) {
    let (tx, rx) = mpsc::channel(OBSERVATION_CAPACITY);
    let addr: IpAddr = "127.0.0.1".parse().unwrap();
    let resolver = DnsResolver::new(
        "test".into(),
        crate::dns::ResolverSpec::System
            .build(AddressFamily::Dual)
            .unwrap(),
        None,
        None,
    );
    let pool = Arc::new(Pool {
        name: "test".into(),
        targets: vec![Target {
            index: 0,
            spec: TargetSpec::Ip(addr),
            custom_tags: Arc::from([]),
            sampled: Vec::new(),
        }],
        probe: ProbePlan {
            port: 9,
            timeout: Duration::from_millis(20),
            kind: ProbeKind::Tcp,
        },
        timing: ProbeTiming {
            interval: Duration::from_secs(300),
            degraded_interval: Duration::from_secs(30),
            fail_threshold: 2,
            max_concurrent_probes: 16,
            score_payload_bytes: payload,
            throughput_discount: 0.95,
            kalman_q: DEFAULT_KALMAN_Q,
            kalman_r: DEFAULT_KALMAN_R,
        },
        nat64: None,
        fallback: None,
        resolver,
        views: vec![View {
            selectors: Vec::new(),
        }],
        ranking: RwLock::new(Arc::new(Ranking::empty(1))),
        obs_tx: (payload != 0).then_some(tx),
        dropped_observations: AtomicU64::new(0),
    });
    let mut state = PoolState::new(rx);
    let mut h = Health::new(
        Instant::now(),
        Duration::from_secs(30),
        DEFAULT_KALMAN_Q,
        DEFAULT_KALMAN_R,
    );
    h.record_success(
        Duration::from_millis(25),
        pool.timing.interval,
        pool.timing.degraded_interval,
    );
    state.health.insert(addr, h);
    let candidates = vec![Candidate {
        addr,
        target: 0,
        tags: vec!["ipv4".into()],
    }];
    recompute_order(&mut state, &pool.timing, &candidates);
    publish(&pool, &state, &candidates);
    (pool, state, candidates)
}

pub(crate) fn observer() -> (PoolHandle, mpsc::Receiver<PassiveObs>) {
    let (pool, state, _) = fixture(1_000_000);
    (PoolBuilder::handle(pool, 0), state.obs_rx)
}
