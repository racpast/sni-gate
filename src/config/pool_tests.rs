use super::*;

#[test]
fn invalid_pool_model_parameters_are_rejected_at_load_time() {
    for (field, bad_values) in [
        (
            "max_concurrent_probes",
            &["0", "4097", "9223372036854775807"][..],
        ),
        (
            "throughput_discount",
            &["0.0", "-0.5", "1.1", "nan", "inf", "-inf"],
        ),
        ("rtt_process_noise", &["-0.01", "nan", "inf", "-inf"]),
        ("rtt_obs_noise", &["0.0", "-999.0", "nan", "inf", "-inf"]),
    ] {
        for value in bad_values {
            let probe: ProbeDef =
                toml::from_str(&format!("mode = \"tcp\"\n{field} = {value}")).unwrap();
            let error = probe.validate().unwrap_err();
            assert!(error.contains(field), "{field}={value}: {error}");
        }
    }
    for settings in [
        "max_concurrent_probes = 1\nthroughput_discount = 1.0\nrtt_process_noise = 0.0\nrtt_obs_noise = 0.1",
        "max_concurrent_probes = 4096\nrtt_process_noise = 10.0\nrtt_obs_noise = 10.0",
        "rtt_process_noise = 1e308\nrtt_obs_noise = 1e308",
    ] {
        let probe: ProbeDef = toml::from_str(&format!("mode = \"tcp\"\n{settings}")).unwrap();
        probe.validate().unwrap();
    }
}

#[test]
fn commented_adaptive_example_loads_when_enabled() {
    let template = include_str!("../../sni-gate.example.toml");
    let (_, section) = template
        .split_once("# [pools.cdn-adaptive]")
        .expect("adaptive pool example marker is present");
    let (example, _) = section
        .split_once("# The gateway learns")
        .expect("adaptive pool example terminator is present");
    let uncommented: String = example
        .lines()
        .map(|line| format!("{}\n", line.strip_prefix("# ").unwrap_or(line)))
        .collect();
    let full = format!("[ca]\ncert_path=\"ca.crt\"\nkey_path=\"ca.key\"\n[pools.cdn-adaptive]\n{uncommented}\n[[listener]]\naddr=\"127.0.0.1:8443\"\n[[listener.route]]\ntype=\"tls\"\nmatch_sni=[\"media.example.com\"]\nupstream=\"@cdn-adaptive:443\"\n");
    let config: Config = toml::from_str(&full).unwrap();
    config.validate().unwrap();
}
