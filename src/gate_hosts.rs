//! Shared gate-host policy, independent of transport and application state.
pub(crate) fn is_gate_host(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    h == "cloudcode-pa.googleapis.com" || h == "daily-cloudcode-pa.googleapis.com"
}
