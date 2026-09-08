//! What the user switched on, remembered between runs.
//!
//! The old build had no such file: state lived only in the system (an NRPT rule
//! either exists or does not) and the menu asked again every time. A switch UI
//! needs both — the *system* answers "is it on right now", this answers "is it
//! on because the user asked for it", which is what lets the app put a switch
//! back where the user left it and re-apply after a reboot wiped something.
//!
//! Deliberately best-effort: a missing or corrupt file is a fresh `Settings`,
//! never an error the user has to deal with.
//!
//! Lives in `dns_forwarder::log_dir()`, next to `upstream.txt`, and for the same
//! reason: the relay task runs **as this user** under an S4U principal, not as
//! SYSTEM, so per-user state is exactly what both processes can reach. It is
//! also why the provider deny-list needs no second copy anywhere — one file,
//! re-read rather than cached, is the pattern `upstream::configured` already
//! set (src/upstream.rs:286).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const FILE_NAME: &str = "settings.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Switch 1: the client patch that lifts the account-region block.
    pub client_patch: bool,

    /// Re-apply the patch by itself when Antigravity updates and wipes it.
    ///
    /// Read by the *watchdog process*, not just the window, which is why it goes
    /// through `auto_patch_enabled()` and its cache rather than being consulted
    /// from an in-memory `Settings` the watchdog never sees.
    pub auto_patch: bool,

    /// Switch 2 and its parts. The master switch is not stored separately: it is
    /// on when any of its parts is, which keeps one truth instead of two.
    pub dns: bool,
    pub local_proxy: bool,
    pub builtin_exits: bool,

    /// Providers the user turned off by name. A deny-list rather than an
    /// allow-list on purpose: a provider added in a later release is then on by
    /// default instead of silently missing from everyone's saved settings.
    pub disabled_providers: Vec<String>,

    /// Whether every enabled provider may answer, or only the first one.
    ///
    /// On (the default) is what the pool was built for: each query is raced and
    /// the answer verified against a reference resolver, so a provider that
    /// silently drops a name costs nothing. Off pins the layer to the first
    /// enabled provider in pool order - for a user who wants exactly one service
    /// seeing their lookups, at the price of having no fallback when it stops
    /// substituting.
    pub rotate_providers: bool,

    /// The user's own order for the DNS pool, by name.
    ///
    /// Empty means the compiled order, which is ordered by measured substitution.
    /// It matters most with rotation off, where the *first* enabled provider is
    /// the only one asked - so being able to say which one that is is the point.
    /// Names not listed here keep their compiled position after the listed ones,
    /// so a provider added in a later release is never silently dropped.
    pub provider_order: Vec<String>,

    /// Whether a VPN carrying Antigravity makes the DNS layer stand down.
    ///
    /// On (the default) is the measured behaviour: with the client itself inside
    /// a tunnel, an NRPT rule overrides the resolver the user deliberately turned
    /// on, and the substituted address is reached through that tunnel anyway - so
    /// the rules buy nothing and cost the user control (D13, G26). Off installs
    /// them regardless, for a user who wants the bypass on top of their VPN and
    /// has decided that trade for themselves.
    pub vpn_detect: bool,

    /// Whether a substituted address must prove itself with a real certificate
    /// before it is handed to the client.
    ///
    /// On (the default): the liveness probe completes a full TLS handshake for
    /// the gate hostname against the public CA roots, so an address that fronts
    /// anything other than a genuine Google endpoint is dropped from the answer.
    /// That is the one check standing between an unblock service and a listener
    /// that could read the traffic. Off: TCP on 443 only — faster on a slow link,
    /// and no protection against a substituted address that is not what it says.
    pub verify_tls: bool,

    /// The user's own HTTP proxy ("bring your own exit"). Kept even while off so
    /// flipping the switch back does not mean typing it again.
    pub own_proxy: String,
    pub own_proxy_enabled: bool,

    /// Installs the user pointed at by hand, on top of the ones found by the
    /// scan (the pencil next to each path).
    pub manual_paths: Vec<PathBuf>,
}

impl Default for Settings {
    fn default() -> Self {
        // Everything under the region bypass ships ON: spec item 3 — the
        // switches are there to turn things *off*, not to make the user
        // assemble a working setup out of parts.
        Self {
            client_patch: false,
            auto_patch: true,
            dns: true,
            local_proxy: true,
            builtin_exits: true,
            disabled_providers: Vec::new(),
            rotate_providers: true,
            provider_order: Vec::new(),
            vpn_detect: true,
            verify_tls: true,
            own_proxy: String::new(),
            own_proxy_enabled: false,
            manual_paths: Vec::new(),
        }
    }
}

impl Settings {
    pub fn load() -> Self {
        let Some(path) = path() else {
            return Self::default();
        };
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Best-effort write. A failure here must never block an action the user
    /// asked for, so it is reported as a bool and normally ignored.
    pub fn save(&self) -> bool {
        let Some(path) = path() else { return false };
        if let Some(dir) = path.parent() {
            if std::fs::create_dir_all(dir).is_err() {
                return false;
            }
        }
        let written = match serde_json::to_string_pretty(self) {
            Ok(json) => std::fs::write(path, json).is_ok(),
            Err(_) => false,
        };
        if written {
            // The writer must see its own write immediately. Without this the
            // window saves a new provider order and then reads the list back
            // through a cache that is up to a TTL old, so the change appears not
            // to have happened at all - for twenty seconds. Other processes
            // still pick it up on their own TTL, which is the point of the
            // cache; this only shortcuts the process that made the change.
            if let Ok(mut guard) = CACHE.lock() {
                *guard = Some((self.clone(), Instant::now()));
            }
        }
        written
    }

    pub fn provider_enabled(&self, name: &str) -> bool {
        !self
            .disabled_providers
            .iter()
            .any(|d| d.eq_ignore_ascii_case(name))
    }

    pub fn set_provider_enabled(&mut self, name: &str, on: bool) {
        self.disabled_providers
            .retain(|d| !d.eq_ignore_ascii_case(name));
        if !on {
            self.disabled_providers.push(name.to_string());
        }
    }
}

fn path() -> Option<PathBuf> {
    let dir = crate::dns_forwarder::log_dir();
    if dir.as_os_str().is_empty() {
        return None;
    }
    Some(dir.join(FILE_NAME))
}

/// The settings as a *serving* process must read them.
///
/// The relay resolves on a hot path — one call per DNS query, one per CONNECT —
/// so this is cached behind a short TTL rather than read from disk each time.
/// The TTL is the whole bargain: it lets the window write the file and an
/// already-running relay pick the change up without a restart, which is exactly
/// what `upstream.txt` does and why that file is re-read rather than cached
/// forever (src/upstream.rs:302-308).
///
/// Holds only its own lock and calls into nothing else, so it cannot take part
/// in the cross-module reentrancy I50 forbids.
static CACHE: Mutex<Option<(Settings, Instant)>> = Mutex::new(None);

fn cached() -> Settings {
    // Tests get the defaults, never the machine's file.
    //
    // `resolvers` and `proxy` ask this question deep inside the pool, so without
    // this the pool's own unit tests would depend on whatever the person running
    // them last switched in the window — and the failure looks like a bug in the
    // pool rather than in the harness. Behaviour with real settings is covered
    // where it belongs, by tests that build a `Settings` and pass it in.
    #[cfg(test)]
    return Settings::default();

    #[cfg(not(test))]
    {
        cached_from_disk()
    }
}

#[cfg(not(test))]
fn cached_from_disk() -> Settings {
    const TTL: Duration = Duration::from_secs(20);

    if let Ok(guard) = CACHE.lock() {
        if let Some((s, at)) = guard.as_ref() {
            if at.elapsed() < TTL {
                return s.clone();
            }
        }
    }
    let fresh = Settings::load();
    if let Ok(mut guard) = CACHE.lock() {
        *guard = Some((fresh.clone(), Instant::now()));
    }
    fresh
}

pub fn disabled_providers_cached() -> Vec<String> {
    cached().disabled_providers
}

/// The user's provider order, for the resolver pool to lay itself out by.
pub fn provider_order_cached() -> Vec<String> {
    cached().provider_order
}

/// Whether the pool may rotate, or only its first enabled member answers.
pub fn rotation_enabled() -> bool {
    cached().rotate_providers
}

/// Whether a VPN carrying Antigravity makes the DNS layer stand down.
///
/// Read from `dns.rs`, which runs in the window *and* in the relay, so it goes
/// through the cache like every other cross-process setting.
/// Whether a substituted address must present a valid certificate for the gate
/// host before it is used. Read on the resolver's hot path, so it goes through
/// the cache like every other cross-process setting.
pub fn verify_tls_enabled() -> bool {
    cached().verify_tls
}

pub fn vpn_detect_enabled() -> bool {
    cached().vpn_detect
}

/// Whether the user wants the client patched at all.
///
/// The watchdog is a separate process that survives reboots, so this is the only
/// way it can hear that the patch was switched off. Without it the watchdog puts
/// back what the window just removed, seconds later, and the switch flips itself
/// back on.
pub fn client_patch_enabled() -> bool {
    cached().client_patch
}

/// Whether the user wants the local proxy route at all.
///
/// Read by the relay, which restores the proxy variable at every start: without
/// this it put back a route the window had just switched off.
pub fn local_proxy_wanted() -> bool {
    cached().local_proxy
}

/// Whether the watchdog may re-apply the patch after an Antigravity update.
///
/// The watchdog is its own process and its own task, so this is the only way it
/// can hear about a switch the window flipped. Defaults to on when there is no
/// settings file yet, which is the shipped behaviour.
pub fn auto_patch_enabled() -> bool {
    cached().auto_patch
}

/// Whether the built-in permitted-region exits may be used as a route.
///
/// Defaults to on: a missing settings file means a machine that never opened the
/// window (the relay's first start races the first save), and the route being
/// there is the shipped behaviour.
pub fn builtin_exits_enabled() -> bool {
    cached().builtin_exits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_file_reads_as_the_defaults_not_an_error() {
        // Nothing has been written in a test process, so this exercises the
        // "first run" path that every new user takes.
        let s = Settings::default();
        assert!(s.dns && s.local_proxy && s.builtin_exits && s.auto_patch);
        assert!(s.rotate_providers, "the pool races by default");
        assert!(!s.client_patch, "the patch is an action the user opts into");
    }

    #[test]
    fn a_provider_is_on_until_it_is_explicitly_turned_off() {
        let mut s = Settings::default();
        assert!(s.provider_enabled("dns-ai"));
        s.set_provider_enabled("dns-ai", false);
        assert!(
            !s.provider_enabled("DNS-AI"),
            "the name match is case-blind"
        );
        assert_eq!(s.disabled_providers.len(), 1);
        // Turning it off twice must not leave two entries behind.
        s.set_provider_enabled("dns-ai", false);
        assert_eq!(s.disabled_providers.len(), 1);
        s.set_provider_enabled("dns-ai", true);
        assert!(s.disabled_providers.is_empty());
    }

    #[test]
    fn an_unknown_field_in_the_file_does_not_throw_the_whole_thing_away() {
        // A settings file written by a newer build must still load in an older
        // one - otherwise a downgrade silently resets every switch.
        let json = r#"{"dns": false, "something_from_the_future": 7}"#;
        let s: Settings = serde_json::from_str(json).expect("unknown fields are ignored");
        assert!(!s.dns);
        assert!(s.local_proxy, "fields left out keep their default");
    }
}
