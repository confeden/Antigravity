//! DNS proxy eligibility is per host AND address. A successful unauthenticated
//! probe proves transport only; only the client's model answer proves region.
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{mpsc, Mutex, OnceLock};
use std::time::{Duration, Instant};

pub const CHECK_EVERY: Duration = Duration::from_secs(10 * 60);
const FRESH_FOR: Duration = Duration::from_secs(25 * 60);

pub enum Probe {
    Reachable(Duration),
    Refused,
    Failed(String),
}

struct Endpoint {
    ip: Ipv4Addr,
    checked: Option<Instant>,
    latency: Duration,
    reachable: bool,
    refused: bool,
    proven: bool,
}

impl Endpoint {
    fn new(ip: Ipv4Addr) -> Self {
        Self {
            ip,
            checked: None,
            latency: Duration::MAX,
            reachable: false,
            refused: false,
            proven: false,
        }
    }

    fn apply(&mut self, probe: &Probe) {
        self.checked = Some(Instant::now());
        match probe {
            Probe::Reachable(latency) => {
                self.latency = *latency;
                self.reachable = true;
                // A 401/403 is NOT evidence against a measured region refusal.
            }
            Probe::Refused => {
                self.refused = true;
                self.proven = false;
            }
            Probe::Failed(_) => {
                self.reachable = false;
            }
        }
    }

    fn usable(&self) -> bool {
        self.reachable && !self.refused && self.checked.is_some_and(|at| at.elapsed() < FRESH_FOR)
    }
}

#[derive(Default)]
struct State {
    generation: u64,
    configuration: Option<Configuration>,
    hosts: HashMap<String, Vec<Endpoint>>,
}

type Configuration = (Vec<String>, Vec<String>, bool, String);

fn configuration() -> Configuration {
    (
        crate::settings::disabled_providers_cached(),
        crate::settings::provider_order_cached(),
        crate::settings::rotation_enabled(),
        crate::settings::custom_dns_cached(),
    )
}

fn state() -> &'static Mutex<State> {
    static STATE: OnceLock<Mutex<State>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(State::default()))
}

static WAKE: OnceLock<mpsc::SyncSender<()>> = OnceLock::new();

pub fn refresh_settings() {
    let configuration = configuration();
    if let Ok(mut s) = state().lock() {
        if s.configuration.as_ref() == Some(&configuration) {
            return;
        }
        s.configuration = Some(configuration);
        s.generation = s.generation.wrapping_add(1);
        for entries in s.hosts.values_mut() {
            for entry in entries {
                entry.reachable = false;
            }
        }
    }
    if let Some(tx) = WAKE.get() {
        let _ = tx.try_send(());
    }
}

/// Runs separately from the warm loop: a slow provider must not delay gate.json,
/// network detection or the other methods' health checks.
pub fn start() {
    WAKE.get_or_init(|| {
        let (tx, rx) = mpsc::sync_channel(1);
        std::thread::spawn(move || loop {
            check_all();
            match rx.recv_timeout(CHECK_EVERY) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        });
        tx
    });
}

pub fn network_changed() {
    if let Ok(mut s) = state().lock() {
        s.generation = s.generation.wrapping_add(1);
        s.hosts.clear();
    }
    if let Some(tx) = WAKE.get() {
        // Coalesce notifications while a check is already pending.
        let _ = tx.try_send(());
    }
}

pub fn addresses(host: &str) -> Vec<Ipv4Addr> {
    let configuration = configuration();
    let Ok(s) = state().lock() else {
        return Vec::new();
    };
    if s.configuration.as_ref() != Some(&configuration) {
        return Vec::new();
    }
    let Some(entries) = s.hosts.get(host) else {
        return Vec::new();
    };
    let mut usable: Vec<_> = entries.iter().filter(|e| e.usable()).collect();
    usable.sort_by_key(|e| (!e.proven, e.latency));
    usable.into_iter().map(|e| e.ip).collect()
}

/// Feedback is attributed to the actual address of the tunnel, not every DNS
/// provider. A bad egress on one proxy must not discard another provider's IP.
pub fn feedback(host: &str, ip: Ipv4Addr, answered: bool) {
    if let Ok(mut s) = state().lock() {
        if let Some(e) = s
            .hosts
            .get_mut(host)
            .and_then(|es| es.iter_mut().find(|e| e.ip == ip))
        {
            e.refused = !answered;
            e.proven = answered;
            if answered {
                e.reachable = true;
                e.checked = Some(Instant::now());
            }
        }
    }
}

fn check_all() {
    refresh_settings();
    let generation = match state().lock() {
        Ok(s) => s.generation,
        Err(_) => return,
    };
    let pin = crate::net::pin_interface();
    std::thread::scope(|scope| {
        for host in crate::dns::core_namespaces() {
            scope.spawn(move || check_host(host, pin, generation));
        }
    });
}

fn publish_probe(host: &str, ip: Ipv4Addr, result: &Probe, generation: u64) -> bool {
    let protected = crate::routes::streaming_dns_endpoints(host).contains(&ip);
    let Ok(mut s) = state().lock() else {
        return false;
    };
    if s.generation != generation {
        return false;
    }
    let entries = s.hosts.entry(host.to_string()).or_default();
    let idx = match entries.iter().position(|e| e.ip == ip) {
        Some(i) => i,
        None => {
            entries.push(Endpoint::new(ip));
            entries.len() - 1
        }
    };
    if !protected || matches!(result, Probe::Reachable(_)) {
        entries[idx].apply(result);
    }
    true
}

fn check_host(host: &str, pin: u32, generation: u64) {
    let before: Vec<_> = match state().lock() {
        Ok(s) => s
            .hosts
            .get(host)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| e.usable())
                    .map(|e| e.ip)
                    .collect()
            })
            .unwrap_or_default(),
        Err(_) => return,
    };
    let candidates = crate::resolvers::dns_proxy_candidates(host, pin);
    let mut results = Vec::new();
    for ip in candidates {
        if state().lock().map_or(true, |s| s.generation != generation) {
            return;
        }
        let result = crate::proxy::probe_dns_endpoint(host, ip, pin);
        #[cfg(test)]
        if let Probe::Failed(why) = &result {
            println!("{host}: candidate #{}: {why}", results.len() + 1);
        }
        // Publish the first good address without waiting for dead peers.
        if !publish_probe(host, ip, &result, generation) {
            return;
        }
        results.push((ip, result));
    }
    let Ok(mut s) = state().lock() else {
        return;
    };
    if s.generation != generation {
        return;
    }
    let entries = s.hosts.entry(host.to_string()).or_default();
    // Keep refusal evidence for an address even if DNS temporarily stops
    // returning it. It must not come back as a new, innocent candidate.
    for entry in entries.iter_mut() {
        if !results.iter().any(|(ip, _)| *ip == entry.ip) {
            entry.reachable = false;
        }
    }
    let after: Vec<_> = entries
        .iter()
        .filter(|e| e.usable())
        .map(|e| e.ip)
        .collect();
    let best = entries
        .iter()
        .filter(|e| e.usable())
        .map(|e| e.latency)
        .min();
    drop(s);
    if before != after || after.is_empty() {
        let failures = results
            .iter()
            .filter_map(|(_, r)| match r {
                Probe::Failed(e) => Some(e.as_str()),
                _ => None,
            })
            .next();
        crate::dns_forwarder::log_proxy(&format!(
            "DNS {host}: доступно {}/{} прокси{}{}; регион подтверждается ответом модели",
            after.len(),
            results.len(),
            if failures.is_some() { "; " } else { "" },
            failures.unwrap_or("")
        ));
    }
    if host == "daily-cloudcode-pa.googleapis.com" {
        match best {
            Some(d) => crate::routes::record(crate::routes::Kind::Direct, d),
            None => crate::routes::probe_failed(crate::routes::Kind::Direct),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_transport_probe_cannot_erase_a_region_refusal() {
        let mut e = Endpoint::new(Ipv4Addr::LOCALHOST);
        assert!(!e.usable());
        e.apply(&Probe::Reachable(Duration::from_millis(50)));
        assert!(e.usable());
        assert!(!e.proven, "401 is not a model answer");
        e.apply(&Probe::Refused);
        e.apply(&Probe::Reachable(Duration::from_millis(30)));
        assert!(!e.usable(), "a known region-blocked proxy stays excluded");
    }

    #[test]
    fn a_failed_background_check_excludes_only_the_failed_endpoint() {
        let mut e = Endpoint::new(Ipv4Addr::LOCALHOST);
        let mut other = Endpoint::new(Ipv4Addr::new(127, 0, 0, 2));
        e.apply(&Probe::Reachable(Duration::from_millis(50)));
        other.apply(&Probe::Reachable(Duration::from_millis(60)));
        e.apply(&Probe::Failed("timeout".into()));
        assert!(!e.usable());
        assert!(other.usable());
        e.apply(&Probe::Reachable(Duration::from_millis(50)));
        assert!(e.usable());
    }

    #[test]
    #[ignore = "checks live public DNS proxies; no credentials or model requests"]
    fn inspects_live_dns_proxy_eligibility() {
        check_all();
        let s = state().lock().unwrap();
        for host in crate::dns::core_namespaces() {
            let entries = s.hosts.get(*host).expect("host was checked");
            println!(
                "{host}: {}/{} transport-reachable, {} region-refused, {} model-proven",
                entries.iter().filter(|e| e.usable()).count(),
                entries.len(),
                entries.iter().filter(|e| e.refused).count(),
                entries.iter().filter(|e| e.proven).count()
            );
        }
    }
}
