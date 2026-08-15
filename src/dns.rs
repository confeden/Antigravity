use std::process::Command;
use std::sync::Mutex;

// NRPT-based selective DNS routing. Only the exact hostnames that Antigravity
// actually talks to AND that the upstream resolver actually proxies are routed
// to xbox-dns.ru; everything else stays on the system default resolver.
//
// The namespaces below were verified against the resolver: each one answers
// with a proxy address instead of the real Google address. Hosts that the
// resolver merely forwards (accounts.google.com, oauth2.googleapis.com,
// aiplatform.googleapis.com, *.googleusercontent.com, antigravity.google, ...)
// are deliberately NOT listed - a rule for them would send DNS traffic to a
// third party for zero benefit.
//
// Rules are tagged via Comment so they can be found and removed later without
// touching rules created by other tools.
const AG_NRPT_TAG: &str = "AG_UNLOCKER_NRPT_V2";
// Tags written by earlier releases; removed on cleanup so upgrades don't leave
// stale (and much broader) rules behind.
const AG_NRPT_LEGACY_TAGS: &[&str] = &["AG_UNLOCKER_NRPT"];

// Endpoints used by language_server.exe / agy.exe and the Electron shell.
const AG_NRPT_CORE: &[&str] = &[
    "cloudcode-pa.googleapis.com",
    "daily-cloudcode-pa.googleapis.com",
    "generativelanguage.googleapis.com",
    "antigravity-unleash.goog",
];
// Only needed for the Gemini CLI flow (the API-key page must open in a browser).
const AG_NRPT_GEMINI: &[&str] = &["aistudio.google.com"];

// xbox-dns.ru servers (v4 + v6); Windows will pick whichever family is reachable.
const AG_NRPT_NAMESERVERS: &str =
    "'111.88.96.50','111.88.96.51','2a00:ab00:1233:26::50','2a00:ab00:1233:26::51'";

const IPV4_PREFIX: &str = "::ffff:0:0/96";
// Windows default precedence for the IPv4-mapped prefix.
const IPV4_PREFIX_DEFAULT_PRECEDENCE: &str = "35";
// Precedence that puts IPv4 above native IPv6.
const IPV4_PREFIX_PREFERRED_PRECEDENCE: &str = "46";

// is_nrpt_applied() shells out to PowerShell, which costs a few hundred ms.
// The menu redraws on every keystroke, so the answer is cached and invalidated
// explicitly whenever we change the rules ourselves.
static NRPT_CACHE: Mutex<Option<bool>> = Mutex::new(None);

fn powershell(script: &str) -> Option<std::process::Output> {
    Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .ok()
}

fn invalidate_cache() {
    if let Ok(mut c) = NRPT_CACHE.lock() {
        *c = None;
    }
}

fn ps_string_list(items: &[&str]) -> String {
    items
        .iter()
        .map(|s| format!("'{}'", s))
        .collect::<Vec<_>>()
        .join(",")
}

fn all_tags() -> Vec<&'static str> {
    let mut tags = vec![AG_NRPT_TAG];
    tags.extend_from_slice(AG_NRPT_LEGACY_TAGS);
    tags
}

/// True when the machine has no routable IPv6 address. In that case the AAAA
/// records handed out by the resolver point at an unreachable proxy, so IPv4 is
/// forced ahead of IPv6 to avoid connect timeouts.
fn lacks_global_ipv6() -> bool {
    let out = powershell(
        "(Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue | \
         Where-Object { $_.IPAddress -notlike 'fe80*' -and $_.IPAddress -ne '::1' -and \
         $_.PrefixOrigin -ne 'WellKnown' } | Measure-Object).Count",
    );
    match out {
        Some(o) => String::from_utf8_lossy(&o.stdout)
            .trim()
            .parse::<usize>()
            .map_or(false, |n| n == 0),
        // If the probe fails, leave the system policy alone.
        None => false,
    }
}

fn set_ipv4_precedence(precedence: &str) {
    Command::new("netsh")
        .args([
            "interface",
            "ipv6",
            "set",
            "prefixpolicy",
            IPV4_PREFIX,
            precedence,
            "4",
        ])
        .output()
        .ok();
}

/// Restores the default IPv4/IPv6 precedence, but only if the current value is
/// the one this tool sets. A precedence the user (or another tool) chose is
/// left untouched.
fn restore_ipv4_precedence() {
    let out = powershell(
        "(Get-NetPrefixPolicy -ErrorAction SilentlyContinue | \
         Where-Object { $_.Prefix -eq '::ffff:0:0/96' }).Precedence",
    );
    let is_ours = out.map_or(false, |o| {
        String::from_utf8_lossy(&o.stdout).trim() == IPV4_PREFIX_PREFERRED_PRECEDENCE
    });
    if is_ours {
        set_ipv4_precedence(IPV4_PREFIX_DEFAULT_PRECEDENCE);
    }
}

pub fn remove_dns_nrpt() {
    restore_ipv4_precedence();

    let cmd = format!(
        "$tags=@({}); Get-DnsClientNrptRule -ErrorAction SilentlyContinue | \
         Where-Object {{ $tags -contains $_.Comment }} | \
         Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue; \
         Clear-DnsClientCache -ErrorAction SilentlyContinue",
        ps_string_list(&all_tags())
    );
    powershell(&cmd);
    invalidate_cache();
}

/// Namespaces currently installed under our tag, lowercased.
fn installed_namespaces() -> Vec<String> {
    let cmd = format!(
        "Get-DnsClientNrptRule -ErrorAction SilentlyContinue | \
         Where-Object {{$_.Comment -eq '{}'}} | ForEach-Object {{ $_.Namespace }}",
        AG_NRPT_TAG
    );
    match powershell(&cmd) {
        Some(o) => String::from_utf8_lossy(&o.stdout)
            .lines()
            .map(|l| l.trim().trim_end_matches('.').to_lowercase())
            .filter(|l| !l.is_empty())
            .collect(),
        None => Vec::new(),
    }
}

/// True when every core namespace already has a rule. Extra rules (e.g. the
/// Gemini-only namespace) do not make this false - they are still ours and are
/// cleaned up together.
pub fn is_nrpt_applied() -> bool {
    if let Ok(cache) = NRPT_CACHE.lock() {
        if let Some(v) = *cache {
            return v;
        }
    }

    let installed = installed_namespaces();
    let applied = AG_NRPT_CORE
        .iter()
        .all(|ns| installed.iter().any(|i| i == &ns.to_lowercase()));

    if let Ok(mut cache) = NRPT_CACHE.lock() {
        *cache = Some(applied);
    }
    applied
}

pub fn setup_dns_nrpt() -> Result<(), String> {
    setup_dns_nrpt_with(false)
}

/// `include_gemini` additionally routes the AI Studio API-key page, which is
/// only relevant to the Gemini CLI flow.
pub fn setup_dns_nrpt_with(include_gemini: bool) -> Result<(), String> {
    // Remove any of our previous rules to keep a clean idempotent state.
    remove_dns_nrpt();

    let mut namespaces: Vec<&str> = AG_NRPT_CORE.to_vec();
    if include_gemini {
        namespaces.extend_from_slice(AG_NRPT_GEMINI);
    }

    // One PowerShell invocation for all rules; a failure on any namespace stops
    // the batch and reports the namespace that failed.
    let cmd = format!(
        "$ErrorActionPreference='Stop'; \
         foreach ($n in @({})) {{ \
           try {{ Add-DnsClientNrptRule -Namespace $n -NameServers @({}) -Comment '{}' \
                  -DisplayName 'AG Unlocker {} {}' -ErrorAction Stop }} \
           catch {{ Write-Error \"$n :: $($_.Exception.Message)\"; exit 1 }} \
         }} \
         Clear-DnsClientCache -ErrorAction SilentlyContinue",
        ps_string_list(&namespaces),
        AG_NRPT_NAMESERVERS,
        AG_NRPT_TAG,
        // DisplayName is cosmetic - rule matching goes through Comment - so it is
        // free real estate for the canaries. Recoverable from any patched machine
        // with `Get-DnsClientNrptRule`, without touching the tool that wrote it.
        crate::canary::STATIC_CANARY,
        crate::canary::RELEASE_TOKEN
    );

    let out = powershell(&cmd).ok_or_else(|| "не удалось запустить PowerShell".to_string())?;
    invalidate_cache();

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let lower = stderr.to_lowercase();
        let hint = if lower.contains("denied") || lower.contains("elevation") {
            "требуются права администратора".to_string()
        } else if stderr.is_empty() {
            "PowerShell завершился с ошибкой".to_string()
        } else {
            stderr
        };
        return Err(format!("NRPT: {}", hint));
    }

    if lacks_global_ipv6() {
        set_ipv4_precedence(IPV4_PREFIX_PREFERRED_PRECEDENCE);
    }

    Ok(())
}
