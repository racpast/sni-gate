//! Statistical state for endpoint selection. Active probes estimate RTT;
//! completed transfers update a discounted NIG posterior over log rate.
//! Selection samples the posterior of the latent mean, not the predictive
//! distribution of another noisy observation. Discounting deliberately keeps
//! uncertainty under changing conditions; no stationary regret bound is assumed.

use rand::Rng;
use rand_distr::{Distribution, StudentT};
use std::net::IpAddr;
use std::time::Duration;

const WIDE_P: f64 = 1_000.0;
const CUSUM_DELTA_MS: f64 = 50.0;
const CUSUM_H: f64 = 200.0;

/// A successful probe establishes availability regardless of measurement noise.
/// Posterior uncertainty controls smoothing, never whether an endpoint is usable.
#[derive(Debug, Clone)]
pub struct KalmanRtt {
    pub mean_ms: f64,
    pub variance: f64,
    q: f64,
    r: f64,
    cusum: f64,
    initialized: bool,
}

impl KalmanRtt {
    pub fn new(q: f64, r: f64) -> Self {
        Self {
            mean_ms: 0.0,
            variance: WIDE_P,
            q,
            r,
            cusum: 0.0,
            initialized: false,
        }
    }

    pub fn update(&mut self, obs: Duration) -> bool {
        let obs_ms = obs.as_secs_f64() * 1000.0;
        if !self.initialized {
            self.mean_ms = obs_ms;
            self.variance = self.r;
            self.initialized = true;
            return false;
        }
        let innovation = obs_ms - self.mean_ms;
        self.cusum = (self.cusum + innovation - CUSUM_DELTA_MS / 2.0).max(0.0);
        let alarm = self.cusum > CUSUM_H;
        if alarm {
            self.cusum = 0.0;
            self.variance = self.variance.max(WIDE_P);
        }
        // Stable gain and covariance even for finite Q/R near f64::MAX.
        let predicted = (self.variance + self.q).min(f64::MAX);
        let gain = if predicted > self.r {
            1.0 / (1.0 + self.r / predicted)
        } else {
            let ratio = predicted / self.r;
            ratio / (1.0 + ratio)
        };
        self.mean_ms += gain * innovation;
        self.variance = self.r * gain;
        alarm
    }

    pub fn estimate(&self) -> Duration {
        // Observations are Durations. Clamp rounding at the largest representable
        // duration, rather than letting conversion at that endpoint panic.
        let seconds = self.mean_ms / 1000.0;
        Duration::try_from_secs_f64(seconds).unwrap_or(Duration::MAX)
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

// Encompass representable transfer byte/time ratios while keeping sampled
// scores finite even for u64::MAX payloads and extreme posterior tail draws.
pub const MIN_THROUGHPUT_BPS: f64 = 1e-20;
const MAX_THROUGHPUT_BPS: f64 = 1e30;

pub fn default_nig_prior() -> NigThroughput {
    NigThroughput::new((256.0 * 1024.0_f64).ln(), 0.5, 1.5, 1.0)
}

/// NIG posterior over log transfer rate. The marginal posterior of its mean
/// is Student-t(2 alpha, mu, sqrt(beta / (alpha kappa))). Sampling that mean
/// expresses uncertainty about the endpoint, excluding irreducible sample noise.
#[derive(Debug, Clone)]
pub struct NigThroughput {
    pub mu: f64,
    pub kappa: f64,
    pub alpha: f64,
    pub beta: f64,
    kappa0: f64,
    alpha0: f64,
    beta0: f64,
}

impl NigThroughput {
    fn new(mu: f64, kappa: f64, alpha: f64, beta: f64) -> Self {
        Self {
            mu,
            kappa,
            alpha,
            beta,
            kappa0: kappa,
            alpha0: alpha,
            beta0: beta,
        }
    }

    pub fn observe(&mut self, bps: f64, gamma: f64) {
        if !bps.is_finite() || bps <= 0.0 {
            return;
        }
        let x = bps.clamp(MIN_THROUGHPUT_BPS, MAX_THROUGHPUT_BPS).ln();
        self.kappa = (self.kappa * gamma).max(self.kappa0);
        self.alpha = (self.alpha * gamma).max(self.alpha0);
        self.beta = (self.beta * gamma).max(self.beta0);
        let kn = self.kappa + 1.0;
        let diff = x - self.mu;
        self.mu += diff / kn;
        self.alpha += 0.5;
        self.beta += (self.kappa / kn) * diff * diff / 2.0;
        self.kappa = kn;
    }

    /// Exact Student-t marginal sampling using the Rand distribution library.
    /// All alpha values are at least the prior's 1.5.
    pub fn sample(&self, rng: &mut impl Rng) -> f64 {
        let distribution = StudentT::new(2.0 * self.alpha).expect("NIG shape remains positive");
        let scale = ((self.beta / self.alpha) / self.kappa).sqrt();
        let log_bps = self.mu + scale * distribution.sample(rng);
        log_bps
            .clamp(MIN_THROUGHPUT_BPS.ln(), MAX_THROUGHPUT_BPS.ln())
            .exp()
    }

    /// Geometric centre, for deterministic diagnostics rather than selection.
    pub fn typical_bps(&self) -> f64 {
        self.mu.exp()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubnetKey {
    V4([u8; 3]),
    V6([u8; 6]),
}

impl SubnetKey {
    pub fn of(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(a) => {
                let o = a.octets();
                SubnetKey::V4([o[0], o[1], o[2]])
            }
            IpAddr::V6(a) => {
                let o = a.octets();
                SubnetKey::V6([o[0], o[1], o[2], o[3], o[4], o[5]])
            }
        }
    }
}

/// Score one candidate using exactly one posterior draw for this decision.
pub fn score(rtt: Duration, nig: &NigThroughput, payload_bytes: u64, rng: &mut impl Rng) -> f64 {
    let rtt_s = rtt.as_secs_f64();
    if payload_bytes == 0 {
        return rtt_s;
    }
    rtt_s + payload_bytes as f64 / nig.sample(rng)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthy_measurements_are_usable_across_valid_noise_scales() {
        for (q, r) in [
            (0.0, 0.1),
            (10.0, 10.0),
            (1e308, 1e308),
            (0.0, f64::MIN_POSITIVE),
        ] {
            let mut filter = KalmanRtt::new(q, r);
            assert!(!filter.is_initialized());
            for i in 0..100 {
                let measurement = Duration::from_millis(if i % 2 == 0 { 40 } else { 60 });
                filter.update(measurement);
                assert!(filter.is_initialized());
                assert!(filter.mean_ms.is_finite());
                assert!(filter.variance.is_finite() && filter.variance >= 0.0);
                assert!((Duration::from_millis(39)..=Duration::from_millis(61))
                    .contains(&filter.estimate()));
            }
        }
    }

    #[test]
    fn first_slow_measurement_is_not_a_false_regime_change() {
        let mut filter = KalmanRtt::new(0.01, 0.1);
        assert!(!filter.update(Duration::from_secs(1)));
        assert_eq!(filter.estimate(), Duration::from_secs(1));
    }

    #[test]
    fn posterior_mean_uncertainty_shrinks_despite_noisy_observations() {
        use rand::SeedableRng;
        let mut posterior = default_nig_prior();
        for i in 0..100_000 {
            posterior.observe((14.0_f64 + if i % 2 == 0 { -1.0 } else { 1.0 }).exp(), 1.0);
        }
        let mut rng = rand::rngs::StdRng::seed_from_u64(99);
        let mut squared_error = 0.0;
        for _ in 0..20_000 {
            squared_error += (posterior.sample(&mut rng).ln() - posterior.mu).powi(2);
        }
        let variance = squared_error / 20_000.0;
        assert!(
            (0.000002..0.0001).contains(&variance),
            "mean posterior variance={variance}"
        );
    }

    #[test]
    fn discount_keeps_model_and_scores_finite_for_extreme_transfer_rates() {
        use rand::SeedableRng;
        let mut posterior = default_nig_prior();
        let mut rng = rand::rngs::StdRng::seed_from_u64(100);
        for i in 0..1000 {
            posterior.observe(if i % 2 == 0 { 1e-20 } else { 1e30 }, 0.01);
            let value = score(Duration::from_secs(1), &posterior, u64::MAX, &mut rng);
            assert!(value.is_finite() && value >= 1.0);
        }
    }

    #[test]
    fn kalman_converges_and_tracks() {
        let mut k = KalmanRtt::new(0.01, 0.1);
        // Feed 20 observations at 50 ms.
        for _ in 0..20 {
            k.update(Duration::from_millis(50));
        }
        let est_ms = k.estimate().as_millis();
        assert!(
            (45..=55).contains(&est_ms),
            "estimate {est_ms} ms out of range"
        );
        assert!(k.is_initialized());
    }

    #[test]
    fn cusum_fires_on_step_increase() {
        let mut k = KalmanRtt::new(0.01, 0.1);
        // Converge at 50 ms.
        for _ in 0..30 {
            k.update(Duration::from_millis(50));
        }
        assert!(k.is_initialized());
        // Now step up to 200 ms; CUSUM should fire within a moderate number
        // of observations (well under 100).
        let mut fired = false;
        for _ in 0..100 {
            if k.update(Duration::from_millis(200)) {
                fired = true;
                break;
            }
        }
        assert!(fired, "CUSUM did not fire on a large step increase");
        // After firing, variance should have been reset.
        assert!((k.estimate().as_millis() as i64 - 200).abs() <= 1);
    }

    #[test]
    fn cusum_does_not_fire_on_noise() {
        let mut k = KalmanRtt::new(0.01, 0.1);
        // Converge at 50 ms.
        for _ in 0..30 {
            k.update(Duration::from_millis(50));
        }
        // Feed noisy observations around 50 ms — CUSUM must not fire.
        for i in 0..200 {
            let obs = if i % 2 == 0 { 45 } else { 55 };
            let fired = k.update(Duration::from_millis(obs));
            assert!(!fired, "CUSUM fired on noise at step {i}");
        }
    }

    #[test]
    fn nig_posterior_moves_toward_truth() {
        let mut n = default_nig_prior();
        // True throughput: 1 MB/s.
        let truth = 1_024.0 * 1_024.0;
        for _ in 0..50 {
            n.observe(truth, 1.0); // no discount
        }
        let mean = n.typical_bps();
        // After 50 observations the posterior mean should be within 20% of truth.
        assert!(
            mean > truth * 0.8 && mean < truth * 1.2,
            "posterior mean {mean:.0} bps far from truth {truth:.0}"
        );
    }

    #[test]
    fn nig_discount_weakens_old_evidence() {
        let mut n = default_nig_prior();
        // Establish a strong belief at 1 MB/s.
        let high = 1_024.0 * 1_024.0;
        for _ in 0..50 {
            n.observe(high, 1.0);
        }
        let kappa_before = n.kappa;
        // Now observe 64 KB/s with heavy discount — the prior weakens and
        // the new evidence takes over.
        let low = 64.0 * 1_024.0;
        for _ in 0..20 {
            n.observe(low, 0.5);
        }
        assert!(
            n.kappa < kappa_before,
            "discount did not weaken old evidence"
        );
    }

    #[test]
    fn score_degrades_to_rtt_when_payload_zero() {
        let k = KalmanRtt::new(0.01, 0.1);
        let n = default_nig_prior();
        // With payload_bytes = 0, score must equal rtt estimate regardless of nig.
        let s = score(k.estimate(), &n, 0, &mut rand::rng());
        let rtt_s = k.estimate().as_secs_f64();
        assert!(
            (s - rtt_s).abs() < 1e-9,
            "score with payload=0 must equal RTT"
        );
    }

    #[test]
    fn score_penalises_slow_throughput() {
        let mut k_fast = KalmanRtt::new(0.01, 0.1);
        let mut k_slow = KalmanRtt::new(0.01, 0.1);
        // fast: 20 ms RTT; slow: 30 ms RTT.
        for _ in 0..30 {
            k_fast.update(Duration::from_millis(20));
            k_slow.update(Duration::from_millis(30));
        }
        let mut nig_fast = default_nig_prior();
        let mut nig_slow = default_nig_prior();
        // fast: 1 MB/s; slow: 64 KB/s.
        for _ in 0..50 {
            nig_fast.observe(1_024.0 * 1_024.0, 1.0);
            nig_slow.observe(64.0 * 1_024.0, 1.0);
        }
        // Payload: 512 KB. fast should almost always score lower.
        let payload = 512 * 1_024;
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(71);
        let mut fast_wins = 0u32;
        for _ in 0..100 {
            if score(k_fast.estimate(), &nig_fast, payload, &mut rng)
                < score(k_slow.estimate(), &nig_slow, payload, &mut rng)
            {
                fast_wins += 1;
            }
        }
        // With such a large throughput difference, fast should win > 90% of the time.
        assert!(
            fast_wins > 90,
            "fast candidate won only {fast_wins}/100 trials"
        );
    }

    #[test]
    fn subnet_key_groups_correctly() {
        let a: IpAddr = "172.64.229.1".parse().unwrap();
        let b: IpAddr = "172.64.229.200".parse().unwrap();
        let c: IpAddr = "172.64.230.1".parse().unwrap();
        assert_eq!(
            SubnetKey::of(a),
            SubnetKey::of(b),
            "same /24 must share key"
        );
        assert_ne!(
            SubnetKey::of(a),
            SubnetKey::of(c),
            "different /24 must differ"
        );
    }
}
