use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::background;
use crate::dns_forwarder;
use crate::egress::{self, Egress};
use crate::hosts_pin;
use crate::resolvers;
use crate::utils::{bounded_output, no_window, powershell};

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

// The only names that actually need unblock DNS, measured end-to-end.
//
// `cloudcode-pa` is back (2026-08-30), and it is the one entry here whose
// history matters. It was dropped under N2 because a 22-resolver sweep found
// **nobody** substituting it (S9) - a rule for a name every provider answers
// genuinely is pure DNS leakage. That premise died the moment a provider that
// does substitute it was measured: dns-ai.ru answers 186.246.45.126, and that
// address accepts the SNI and replies as Google's own frontend. N2 still holds
// as written - do not add a name *nobody* substitutes - but it was never a rule
// about this hostname, it was a rule about the measurement, and the measurement
// changed. `antigravity-unleash` stays out: still genuine everywhere.
//
// `daily-cloudcode-pa` stays because it is the same service by another name and
// two providers reach it. `generativelanguage` and `aistudio.google.com` are
// **deliberately absent** (owner, `_4`): both were only ever routed for the
// Gemini CLI flow, the IDE was measured running a full agentic task with the
// `generativelanguage` rule removed, and another of the owner's tools owns those
// two names now. We neither install them nor take them away - `remove_dns_nrpt`
// works off `all_tags()`, so it only ever removes rules carrying our own tag and
// a foreign rule on either name is left alone (so is a subtree rule, I44).
// Everything else Antigravity talks to - oauth2/www/play/accounts and
// jetski-webchannel - works on real Google and is deliberately not listed.
const AG_NRPT_CORE: &[&str] = &[
    "cloudcode-pa.googleapis.com",
    "daily-cloudcode-pa.googleapis.com",
];

/// The names an NRPT rule always points at the relay - and therefore the ones
/// the relay keeps a fresh answer for. Warming anything else would put queries
/// on a third party for names Windows never sends here.
pub fn core_namespaces() -> &'static [&'static str] {
    AG_NRPT_CORE
}

// The unblock resolvers live in `resolvers` - the rules and the relay have to
// name the same services, and which of them actually substitutes a given name
// is decided per query rather than assumed here.

const IPV4_PREFIX: &str = "::ffff:0:0/96";
// Windows default precedence for the IPv4-mapped prefix.
const IPV4_PREFIX_DEFAULT_PRECEDENCE: &str = "35";
// Precedence that puts IPv4 above native IPv6.
const IPV4_PREFIX_PREFERRED_PRECEDENCE: &str = "46";

// is_nrpt_applied() shells out to PowerShell, which costs a few hundred ms.
// The menu redraws on every keystroke, so the answer is cached and invalidated
// explicitly whenever we change the rules ourselves.
static NRPT_CACHE: Mutex<Option<bool>> = Mutex::new(None);

#[allow(dead_code)]
pub fn invalidate_cache() {
    if let Ok(mut c) = NRPT_CACHE.lock() {
        *c = None;
    }
}

/// Queries whether NRPT rules are currently active after explicitly dropping the cache.
///
/// Expensive: shells out to PowerShell on Windows, so this is intended for on-demand
/// checks (e.g. user toggles, periodic health checks), not for every UI render frame.
#[allow(dead_code)]
pub fn is_nrpt_applied_fresh() -> bool {
    invalidate_cache();
    is_nrpt_applied()
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
    let mut cmd = Command::new("netsh");
    cmd.args([
        "interface",
        "ipv6",
        "set",
        "prefixpolicy",
        IPV4_PREFIX,
        precedence,
        "4",
    ]);
    // Bounded like everything else on this path: `netsh` is a child process and
    // a child process can stop answering.
    bounded_output(no_window(&mut cmd), HELPER_LIMIT);
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

/// Linux has no NRPT and no relay installed yet, so there is nothing to remove;
/// the undo menus must not spawn doomed helpers or error here.
#[cfg(not(target_os = "windows"))]
pub fn remove_dns_nrpt() {}

#[cfg(target_os = "windows")]
pub fn remove_dns_nrpt() {
    restore_ipv4_precedence();
    // The pinned addresses only exist to serve these rules, so they go together.
    hosts_pin::remove_entries().ok();
    egress::remove_legacy_routes();

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

/// No NRPT layer on Linux yet, so no rules are ever applied. Returning false
/// keeps the "running without admin" advisory honest and stops `main()` probing
/// PowerShell that is not there.
#[cfg(not(target_os = "windows"))]
pub fn is_nrpt_applied() -> bool {
    false
}

/// True when every core namespace already has a rule. Extra rules (e.g. the
/// Gemini-only namespace) do not make this false - they are still ours and are
/// cleaned up together.
#[cfg(target_os = "windows")]
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

/// Resolvers to write into the rule.
///
/// With the local relay running it goes first and the real resolvers stay on as
/// fallbacks, so a relay that is down degrades to the direct path instead of
/// leaving the names unresolvable. IPv6 is dropped in that case: Windows is free
/// to pick a v6 resolver, and that query would leave through the tunnel and skip
/// the relay entirely.
/// The NRPT nameserver list for one specific name.
///
/// The relay goes first; it does the smart per-query provider selection and is
/// almost always what answers. The fallbacks matter only when the relay is slow
/// or down - and they must contain **only providers that actually substitute
/// this name**. A provider that returns the genuine Google address here is not
/// a harmless fallback: Windows will occasionally prefer its fast genuine answer
/// over the relay's and cache it for minutes, and the region error comes back
/// (measured: xbox-dns leaked genuine for `daily-cloudcode-pa` ~1 query in 8).
///
/// When nobody substitutes the name (`antigravity-unleash` is genuine
/// everywhere; `cloudcode-pa` is no longer proxied by anyone), genuine is the
/// only answer there is, so every provider is listed as a plain resolver -
/// there is nothing to leak.
fn nameservers_for(name: &str, via_relay: bool, if_index: u32) -> Vec<String> {
    assemble_nameservers(via_relay, &resolvers::substituting_addrs(name, if_index))
}

/// The pure half of `nameservers_for`, split out so the ordering rules can be
/// tested without a live network probe. `substituters` is what actually proxies
/// the name; empty means nobody does.
fn assemble_nameservers(via_relay: bool, substituters: &[&str]) -> Vec<String> {
    let mut servers: Vec<String> = Vec::new();
    if via_relay {
        servers.push(dns_forwarder::LISTEN_IP.to_string());
    }

    if substituters.is_empty() {
        for s in resolvers::fallback_v4() {
            servers.push(s.to_string());
        }
    } else {
        for s in substituters {
            servers.push(s.to_string());
        }
    }

    // IPv6 only without the relay: with the relay up a v6 nameserver would let
    // Windows send the query out of the tunnel, skipping the relay entirely.
    if !via_relay {
        for s in resolvers::all_v6() {
            servers.push(s.to_string());
        }
    }
    servers
}

fn ps_string_list_owned(items: &[String]) -> String {
    let refs: Vec<&str> = items.iter().map(|s| s.as_str()).collect();
    ps_string_list(&refs)
}

/// What the DNS step ended up doing. `pinned` is non-empty only when a tunnel
/// forced the fallback path.
pub struct DnsOutcome {
    pub vpn_active: bool,
    /// True when a tunnel was up **and the client was measured inside it**, so
    /// this run installed no rules and left the machine resolving exactly as the
    /// VPN configured it.
    pub stood_down_for_vpn: bool,
    /// Which way the client's own traffic was going. Only measured when a tunnel
    /// is up - with none there is nothing for it to decide - so `Unknown` here
    /// means either "no tunnel" or "tunnel, client not running"; `vpn_active`
    /// separates the two.
    pub client: egress::ClientEgress,
    pub via_relay: bool,
    pub pinned: Vec<String>,
    pub pin_error: Option<String>,
    /// Names another tool was routing that this run claimed.
    pub taken_over: Vec<String>,
    /// True when the probe budget ran out and the remaining names were given the
    /// full provider list instead of a measured one.
    pub probe_gave_up: bool,
}

/// Takes our namespaces away from any other tool's NRPT rule, and reports what
/// it took.
///
/// Windows applies exactly one rule per name, and a foreign rule can win, which
/// makes ours a no-op without any error anywhere. Measured on a machine that
/// also ran "Nova DNS Unblock": `cloudcode-pa` went straight to the direct
/// resolvers and never reached the relay, while `antigravity-unleash.goog` -
/// which had no duplicate - did; dropping the two foreign rules made both
/// resolve through the relay.
///
/// A foreign rule may cover several names at once, so only ours are stripped
/// out of it; the rule is deleted outright only when nothing else is left. This
/// is the one place the tool touches another product's configuration, and it is
/// deliberately narrowed to the exact names it routes.
fn take_over_conflicting_rules(namespaces: &[&str]) -> Vec<String> {
    let cmd = format!(
        "$ours=@({ours}); \
         foreach ($r in @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue | \
             Where-Object {{ $_.Comment -ne '{tag}' }})) {{ \
           $hit=@(); $rest=@(); \
           foreach ($n in $r.Namespace) {{ \
             $k=$n.Trim().TrimEnd('.').ToLower(); \
             if ($ours -contains $k) {{ $hit += $n }} else {{ $rest += $n }} }}; \
           if ($hit.Count -eq 0) {{ continue }}; \
           foreach ($n in $hit) {{ '{{0}}|{{1}}' -f $n, $r.Comment }}; \
           if ($rest.Count -eq 0) {{ \
             Remove-DnsClientNrptRule -Name $r.Name -Force -ErrorAction SilentlyContinue }} \
           else {{ Set-DnsClientNrptRule -Name $r.Name -Namespace $rest -ErrorAction SilentlyContinue }} }}",
        ours = ps_string_list(
            &namespaces
                .iter()
                .map(|n| n.to_lowercase())
                .collect::<Vec<_>>()
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
        ),
        tag = AG_NRPT_TAG
    );
    match powershell(&cmd) {
        Some(out) => parse_conflicts(&String::from_utf8_lossy(&out.stdout), namespaces),
        None => Vec::new(),
    }
}

/// Picks the `namespace|owner` lines that collide with one of ours.
fn parse_conflicts(output: &str, namespaces: &[&str]) -> Vec<String> {
    let ours: Vec<String> = namespaces.iter().map(|n| n.to_lowercase()).collect();
    let mut found: Vec<String> = Vec::new();
    for line in output.lines() {
        let mut parts = line.trim().splitn(2, '|');
        let (Some(ns), Some(owner)) = (parts.next(), parts.next()) else {
            continue;
        };
        // Exact names only. A leading dot means "this domain and everything
        // below it" - a broader rule that our exact-name rule already outranks
        // by specificity, so claiming it would strip another tool's subdomain
        // coverage for nothing. Windows reports names with a trailing dot.
        let ns = ns.trim().trim_end_matches('.').to_lowercase();
        if ns.is_empty() || !ours.contains(&ns) {
            continue;
        }
        let owner = owner.trim();
        let entry = if owner.is_empty() {
            format!("{} (без метки)", ns)
        } else {
            format!("{} ({})", ns, owner)
        };
        if !found.contains(&entry) {
            found.push(entry);
        }
    }
    found
}

/// Resolves each routed namespace through the ISP link and pins whatever a
/// provider substitutes into `hosts`. Only genuinely substituted addresses are
/// written: a real Google address in `hosts` buys nothing and goes stale the
/// moment Google rotates its edge.
///
/// The "substituted?" question used to be answered by resolving twice - once
/// bound to the ISP link, once left to the routing table - and writing the
/// address only when the two differed, which says nothing without a tunnel up.
/// `resolvers` answers it directly by comparing every provider against a
/// reference resolver, so the same test now holds with or without a VPN.
fn pin_substituted_hosts(namespaces: &[&str], if_index: u32) -> Result<Vec<String>, String> {
    let mut entries = Vec::new();
    for ns in namespaces {
        let Some((addrs, _, verdict)) = resolvers::resolve_a_best(ns, if_index) else {
            continue;
        };
        if verdict != resolvers::Verdict::Substituted {
            continue;
        }
        entries.push((ns.to_string(), addrs[0]));
    }

    let pinned = entries.iter().map(|(h, _)| h.clone()).collect();
    hosts_pin::write_entries(&entries)?;
    Ok(pinned)
}

/// One character of progress on the caller's line.
fn tick() {
    use std::io::Write;
    // Was a progress dot on the console line. The window has no console, and the
    // step is reported as a whole when it finishes.
    std::io::stdout().flush().ok();
}

/// Longest the whole rule-building probe may take.
///
/// There has to be a bound. `substituting_addrs` asks every provider about every
/// name over UDP/53, and `ask_provider` walks a provider's addresses one at a
/// time at `QUERY_TIMEOUT` each; where those queries are simply dropped - a
/// corporate firewall, some VPN configurations - the arithmetic reaches minutes,
/// all of it behind one printed line with nothing moving. That is what users
/// reported as an eternal hang at "Патч для Google серверов...".
///
/// Past this, the remaining names get the full provider list - the same list a
/// name nobody substitutes gets anyway. The cost is that the fallback may then
/// hold a provider that returns genuine Google for that name (I22), which is a
/// rule that leaks when the relay is slow. A leak that degrades beats a hang
/// that does not end, and the relay is still listed first.
const PROBE_BUDGET: Duration = Duration::from_secs(25);

/// Limit for the small helpers here (`netsh`). Short, because they answer in
/// milliseconds when they answer at all.
const HELPER_LIMIT: Duration = Duration::from_secs(15);

/// The DNS/NRPT layer is the last part of the Linux port (kb/patch.md). Until it
/// lands, the binary/JS patch is what lifts the gate on a permitted exit, and
/// this reports "not done" so the caller can say so rather than half-running the
/// Windows path.
#[cfg(not(target_os = "windows"))]
pub fn setup_dns_nrpt() -> Result<DnsOutcome, String> {
    Err("DNS-слой на Linux пока не портирован".to_string())
}

#[cfg(target_os = "windows")]
pub fn setup_dns_nrpt() -> Result<DnsOutcome, String> {
    // Remove any of our previous rules to keep a clean idempotent state.
    remove_dns_nrpt();

    let egress = egress::detect();
    let via_relay = background::is_enabled();

    // A tunnel is up: install nothing and leave the machine resolving exactly as
    // the VPN configured it (owner's call).
    //
    // The rules cannot help here and can only hurt. An NRPT rule *overrides* the
    // VPN's own DNS for those names, so it takes a decision away from the thing
    // the user deliberately turned on; and the answer it substitutes points at a
    // provider's proxy, which the traffic then reaches **through** the tunnel -
    // client -> tunnel -> proxy -> Google, a detour to reach what the tunnel
    // already reaches directly. Worse, if the exit is in a permitted region the
    // gate is already lifted by the tunnel alone (S25), so the whole layer is
    // paying latency for nothing. Measured on a live machine: exit `loc=FI`,
    // TLS to CloudCode 0.126 s direct, against a substituted address that adds a
    // hop. G26.
    //
    // This is the counterpart to N3, not a contradiction of it: N3 says a tunnel
    // *breaks* substitution (the provider geolocates the exit, not the user), and
    // the answer used to be to dodge the tunnel for DNS. Dodging is still right
    // when the exit is blocked, but the tool cannot tell a Finnish exit from a
    // Russian one without asking, and the owner's instruction is unambiguous:
    // with a VPN up, the VPN decides. `remove_dns_nrpt()` above has already taken
    // ours off, which is the whole of the work.
    //
    // What that reasoning silently assumed is that a tunnel carrying a default
    // route carries *the client*. Windows VPN clients route per application, so
    // it need not: with `language_server.exe` on an exclusion list the machine
    // shows a full tunnel while the client talks to Google straight off the ISP
    // link. Standing down there leaves it in the blocked region with nothing at
    // all - the one state that cannot work (G29). So the condition is now the
    // measured one, and the absence of a measurement installs the rules rather
    // than skipping them; `egress::stand_down_for_vpn` carries the whole rule and
    // the reason for it.
    // The switch only ever *suppresses* the stand-down; it can never cause one.
    // Measuring stays unconditional so `DnsOutcome` still reports the tunnel it
    // saw, which is what the window's indicator is drawn from.
    let (measured_stand_down, client) = egress::vpn_verdict(egress.as_ref());
    let stand_down = measured_stand_down && crate::settings::vpn_detect_enabled();
    if stand_down {
        return Ok(DnsOutcome {
            vpn_active: true,
            stood_down_for_vpn: true,
            client,
            via_relay,
            pinned: Vec::new(),
            pin_error: None,
            taken_over: Vec::new(),
            probe_gave_up: false,
        });
    }

    let namespaces: Vec<&str> = AG_NRPT_CORE.to_vec();

    // Before ours go in: a leftover rule from another tool on the same name wins
    // silently and would make everything below pointless for that name.
    let taken_over = take_over_conflicting_rules(&namespaces);

    // Each name gets its own rule with its own nameserver list, because which
    // providers substitute a name differs per name (only geohide proxies
    // `daily-cloudcode-pa`; xbox-dns and comss return genuine Google for it).
    // The probe leaves through the ISP interface so a tunnel does not hide the
    // substitution.
    let probe_if = egress.as_ref().map(|e| e.if_index).unwrap_or(0);
    let probe_until = Instant::now() + PROBE_BUDGET;
    let mut probe_gave_up = false;
    let mut adds = String::new();
    for (i, name) in namespaces.iter().enumerate() {
        let servers = if Instant::now() < probe_until {
            // A dot per name, because the probing below is network-bound and the
            // caller has already printed its label: without this the step is a
            // motionless line for as long as the queries take, which is what an
            // eternal hang looks like from the outside.
            tick();
            nameservers_for(name, via_relay, probe_if)
        } else {
            probe_gave_up = true;
            assemble_nameservers(via_relay, &[])
        };
        adds.push_str(&format!(
            "try {{ Add-DnsClientNrptRule -Namespace '{name}' -NameServers @({ns}) \
               -Comment '{tag}' -DisplayName 'AG Unlocker {canary} {token} {i}' -ErrorAction Stop }} \
             catch {{ Write-Error \"{name} :: $($_.Exception.Message)\"; exit 1 }}; ",
            name = name,
            ns = ps_string_list_owned(&servers),
            tag = AG_NRPT_TAG,
            // DisplayName is cosmetic - rule matching goes through Comment - so it
            // is free real estate for the canaries. Recoverable from any patched
            // machine with `Get-DnsClientNrptRule`.
            canary = crate::canary::STATIC_CANARY,
            token = crate::canary::RELEASE_TOKEN,
            i = i
        ));
    }
    let cmd = format!(
        "$ErrorActionPreference='Stop'; {} Clear-DnsClientCache -ErrorAction SilentlyContinue",
        adds
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

    // Fallback for a machine without the relay. With a tunnel up the rules alone
    // cannot work: Windows sends the query through the VPN whatever the routing
    // table says, so the resolver sees a foreign client and forwards the genuine
    // Google address. Pinning the substituted address takes DNS out of the loop,
    // at the cost of freezing a TTL-60 answer in a static file - which is
    // exactly what the relay exists to avoid, so it wins whenever it is on.
    let (pinned, pin_error) = match &egress {
        _ if via_relay => (Vec::new(), None),
        Some(eg) if eg.vpn_active => match pin_substituted_hosts(&namespaces, eg.if_index) {
            Ok(pinned) => (pinned, None),
            Err(e) => (Vec::new(), Some(e)),
        },
        _ => (Vec::new(), None),
    };
    if !pinned.is_empty() {
        // hosts is consulted through the same cache the rules just flushed.
        powershell("Clear-DnsClientCache -ErrorAction SilentlyContinue");
    }

    Ok(DnsOutcome {
        vpn_active: egress.as_ref().map_or(false, |e: &Egress| e.vpn_active),
        stood_down_for_vpn: false,
        client,
        via_relay,
        pinned,
        pin_error,
        taken_over,
        probe_gave_up,
    })
}

/// What to print after the DNS step, or `None` when there is nothing worth
/// saying. A conflicting rule is reported on top of everything else: it makes
/// the rest a no-op for that name, silently.
pub fn outcome_note(o: &DnsOutcome) -> Option<String> {
    let mut lines: Vec<String> = Vec::new();

    // Said first and on its own: nothing else in this function describes rules
    // that were not written, and a user who sees no other note would reasonably
    // assume the step silently failed.
    if o.stood_down_for_vpn {
        return Some(
            "  Обнаружен активный VPN, трафик Antigravity идёт через него —\n  \
             правила DNS не создавались. Запросы идут так, как их настраивает\n  \
             VPN. Если выход VPN в разрешённом регионе, обход уже работает и\n  \
             без наших правил; если нет — отключите VPN и запустите пункт 1 снова."
                .to_string(),
        );
    }

    // The two cases a tunnel used to swallow. Said early and in full, because a
    // user who sees "VPN обнаружен" and rules created at the same time will
    // otherwise read it as the tool contradicting itself.
    if o.vpn_active {
        lines.push(
            match o.client {
                egress::ClientEgress::Physical => {
                    "  VPN активен, но трафик Antigravity идёт мимо него\n  \
                     (исключён из VPN) — правила DNS созданы: без них\n  \
                     запросы уходят из заблокированного региона и возвращают\n  \
                     ошибку 400."
                }
                _ => {
                    "  VPN активен, Antigravity не запущен — проверить, идёт ли\n  \
                     его трафик через VPN, не удалось. Правила DNS созданы:\n  \
                     лишние они лишь замедляют на один переход, а недостающие\n  \
                     дают ошибку 400."
                }
            }
            .to_string(),
        );
    }

    if o.probe_gave_up {
        lines.push(
            "  \x1b[33mПроверка DNS-провайдеров не уложилась в отведённое время —\n  \
             правила записаны по общему списку. Обычно это значит, что запросы\n  \
             к DNS блокирует сеть или VPN.\x1b[0m\x1b[92m"
                .to_string(),
        );
    }

    if !o.taken_over.is_empty() {
        lines.push(format!(
            "  Забраны правила DNS у другой программы (мешали патчу):\n  {}",
            o.taken_over.join("\n  ")
        ));
    }

    if o.via_relay {
        lines.push(
            if background::is_running() {
                "  Резолвинг идёт через фоновый релей — адреса берутся с канала\n  \
                 провайдера и обновляются по TTL."
            } else {
                "  \x1b[33mФоновый релей включён, но не запущен — временно работает\n  \
                 прямой путь.\x1b[0m\x1b[92m"
            }
            .to_string(),
        );
        return Some(lines.join("\n"));
    }

    if let Some(note) = fallback_note(o) {
        lines.push(note);
    }
    if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    }
}

/// The `hosts`-pinning half of the message, used when the relay is off.
fn fallback_note(o: &DnsOutcome) -> Option<String> {
    if let Some(e) = &o.pin_error {
        return Some(format!(
            "  \x1b[33mНе удалось закрепить адреса: {}\x1b[0m\x1b[92m",
            e
        ));
    }
    if !o.pinned.is_empty() {
        return Some(format!(
            "  VPN активен — {} адресов получено напрямую через провайдера и закреплено.",
            o.pinned.len()
        ));
    }
    // Says nothing about the VPN itself: `outcome_note` has already printed a
    // line about it by the time this is reached, and saying "VPN активен" twice
    // in one step reads as two different findings.
    if o.vpn_active {
        return Some(
            "  \x1b[33mРезолвер не подменяет адреса даже с канала провайдера —\n  \
             проверьте, что DNS-провайдеры доступны.\x1b[0m\x1b[92m"
                .to_string(),
        );
    }
    None
}

/// Keeps the DNS layer honest about the network it woke up on. Runs on every
/// elevated start of the unlocker.
///
/// Two jobs, and the first one is new: **a VPN that came up after the machine
/// was patched takes the rules back off.** `setup_dns_nrpt` refuses to
/// install them while a tunnel is up, but that only covers the machine's state
/// at patch time; a user who connects a VPN afterwards would otherwise keep
/// overriding their own resolver for three names indefinitely. Returns the
/// machine to "whatever the VPN configured", which is the whole rule (G26).
///
/// The second is the older one: the pinned `hosts` block is a static copy of a
/// TTL-60 answer, so it is rewritten while it is still the fallback in use, and
/// dropped the moment it is not.
/// Nothing is pinned on Linux yet (no NRPT, no relay), so there is nothing to
/// refresh. A no-op keeps `main()`'s startup path clean.
#[cfg(not(target_os = "windows"))]
pub fn refresh_pinned_hosts() {}

#[cfg(target_os = "windows")]
pub fn refresh_pinned_hosts() {
    if !is_nrpt_applied() {
        return;
    }
    // Same evidence rule as `setup_dns_nrpt`, and it matters more here: this
    // runs unattended on every elevated start, so reading "a tunnel is up" as
    // "the client is in it" would quietly strip a working configuration off a
    // machine whose client is excluded from that tunnel (G29). Rules are removed
    // only when the client is measured inside it - and here the measurement is
    // usually available, because a user opens this tool while Antigravity is
    // running.
    if egress::vpn_verdict(egress::detect().as_ref()).0 && crate::settings::vpn_detect_enabled() {
        // Takes the pinned block with it - `remove_dns_nrpt` owns both, because
        // the addresses only ever existed to serve the rules.
        remove_dns_nrpt();
        return;
    }
    // The relay resolves live, so a pinned block would only be a stale copy.
    if background::is_enabled() {
        hosts_pin::remove_entries().ok();
        return;
    }
    hosts_pin::remove_entries().ok();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// The stand-down is announced on its own and nothing else is printed with
    /// it: a user who saw no note at all would reasonably read a step that wrote
    /// no rules as a step that failed.
    #[test]
    fn a_vpn_stand_down_says_so_and_says_nothing_else() {
        let o = DnsOutcome {
            vpn_active: true,
            stood_down_for_vpn: true,
            client: egress::ClientEgress::Tunnel,
            via_relay: true,
            pinned: Vec::new(),
            pin_error: None,
            taken_over: vec!["cloudcode-pa.googleapis.com (OTHER)".to_string()],
            probe_gave_up: true,
        };
        let note = outcome_note(&o).expect("должно быть сообщение");
        assert!(note.contains("VPN"), "{}", note);
        assert!(note.contains("правила DNS не создавались"), "{}", note);
        // The relay/probe/takeover lines belong to a run that wrote rules.
        assert!(!note.contains("релей"), "{}", note);
        assert!(!note.contains("Забраны правила"), "{}", note);
    }

    /// The G29 case, from the other side: a tunnel is up, the client was
    /// measured going around it, so the rules **were** written. Seeing "VPN"
    /// and created rules in the same run reads as a contradiction unless the
    /// note explains it, so it must be there and it must not be the stand-down
    /// text.
    #[test]
    fn a_client_outside_the_tunnel_is_told_why_rules_were_written() {
        let with = |client| DnsOutcome {
            vpn_active: true,
            stood_down_for_vpn: false,
            client,
            via_relay: false,
            pinned: Vec::new(),
            pin_error: None,
            taken_over: Vec::new(),
            probe_gave_up: false,
        };

        let excluded = outcome_note(&with(egress::ClientEgress::Physical)).expect("сообщение");
        assert!(excluded.contains("мимо него"), "{}", excluded);
        assert!(excluded.contains("400"), "{}", excluded);
        assert!(!excluded.contains("не создавались"), "{}", excluded);

        // Antigravity was not running: the rules still go in, and the note says
        // the measurement is what is missing rather than claiming either way.
        let unknown = outcome_note(&with(egress::ClientEgress::Unknown)).expect("сообщение");
        assert!(unknown.contains("не запущен"), "{}", unknown);
        assert!(!unknown.contains("не создавались"), "{}", unknown);

        // No tunnel at all: nothing to explain, so nothing is said about one.
        let plain = DnsOutcome {
            vpn_active: false,
            ..with(egress::ClientEgress::Unknown)
        };
        assert!(
            outcome_note(&plain).map_or(true, |n| !n.contains("VPN")),
            "{:?}",
            outcome_note(&plain)
        );
    }

    #[test]
    fn a_foreign_rule_on_one_of_our_names_is_a_conflict() {
        let out = "daily-cloudcode-pa.googleapis.com|NOVA_DNS_UNBLOCK\n\
                   chatgpt.com|NOVA_DNS_UNBLOCK\n";
        assert_eq!(
            parse_conflicts(out, AG_NRPT_CORE),
            vec!["daily-cloudcode-pa.googleapis.com (NOVA_DNS_UNBLOCK)"]
        );
    }

    /// Windows writes names with a trailing dot; that is the same name.
    #[test]
    fn a_trailing_dot_still_matches() {
        let found = parse_conflicts("cloudcode-pa.googleapis.com.|OTHER\n", AG_NRPT_CORE);
        assert_eq!(found, vec!["cloudcode-pa.googleapis.com (OTHER)"]);
    }

    /// A leading dot is a subtree rule, which our exact-name rule already
    /// outranks - claiming it would cost another tool its subdomains for free.
    #[test]
    fn a_subtree_rule_is_left_alone() {
        let out = ".daily-cloudcode-pa.googleapis.com|OTHER\n.googleapis.com|OTHER\n";
        assert!(parse_conflicts(out, AG_NRPT_CORE).is_empty());
    }

    #[test]
    fn the_same_collision_is_reported_once() {
        let out = "daily-cloudcode-pa.googleapis.com|X\nDAILY-CLOUDCODE-PA.GOOGLEAPIS.COM|X\n";
        assert_eq!(parse_conflicts(out, AG_NRPT_CORE).len(), 1);
    }

    #[test]
    fn noise_and_empty_lines_are_ignored() {
        let out = "\n  \nnot-a-rule\n|\nfoo.example|X\n";
        assert!(parse_conflicts(out, AG_NRPT_CORE).is_empty());
    }

    #[test]
    fn the_relay_goes_first_in_the_rule() {
        // A name only geohide substitutes: the fallback is geohide alone -
        // never a provider that returns genuine Google for it.
        let geohide = "45.155.204.190";
        let servers = assemble_nameservers(true, &[geohide]);
        assert_eq!(
            servers.first().map(|s| s.as_str()),
            Some(dns_forwarder::LISTEN_IP)
        );
        assert!(servers.iter().any(|s| s == geohide));
        // The genuine-returning providers must NOT be in this name's fallback.
        for other in ["111.88.96.50", "83.220.169.155"] {
            assert!(
                !servers.iter().any(|s| s == other),
                "a non-substituting provider leaked into the fallback: {:?}",
                servers
            );
        }
        // No IPv6 while the relay is up.
        assert!(!servers.iter().any(|s| s.contains(':')));
    }

    #[test]
    fn a_name_nobody_substitutes_lists_every_reachable_provider() {
        // antigravity-unleash is genuine everywhere - there is nothing to leak,
        // so all providers serve as plain resolvers behind the relay.
        //
        // "Every provider" means every provider Windows can be pointed at. A DoH
        // provider has no UDP address by construction (see `resolvers::Transport`)
        // and must stay out of the list even here, where the rule is at its most
        // permissive: a nameserver that answers nothing is worse than one fewer
        // fallback.
        let servers = assemble_nameservers(true, &[]);
        for p in resolvers::PROVIDERS {
            match p.v4.first() {
                Some(first) => assert!(
                    servers.iter().any(|s| s == first),
                    "{} missing from {:?}",
                    p.name,
                    servers
                ),
                None => {
                    if let resolvers::Transport::Doh(endpoint) = p.transport {
                        for a in endpoint.addrs {
                            assert!(
                                !servers.iter().any(|s| s == a),
                                "DoH address {} leaked into a nameserver list",
                                a
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn without_the_relay_ipv6_is_listed_and_loopback_is_not() {
        let servers = assemble_nameservers(false, &["45.155.204.190"]);
        assert!(!servers.iter().any(|s| s == dns_forwarder::LISTEN_IP));
        assert!(
            servers.iter().any(|s| s.contains(':')),
            "v6 resolvers belong in the no-relay list: {:?}",
            servers
        );
    }

    /// The end-to-end path this machine can actually exercise: resolve through
    /// the ISP link past a live tunnel and rewrite the real hosts block, exactly
    /// as startup does. Needs admin, a live network and the rules already in
    /// place. Deliberately leaves the block behind - that is the working state.
    #[test]
    #[ignore = "writes the real hosts file; run with --ignored"]
    fn pins_the_real_hosts_file() {
        let path = hosts_pin::hosts_path();
        let before = std::fs::read_to_string(&path).unwrap_or_default();
        println!("--- before ---\n{}\n--------------", before);

        // Each precondition, so a silent no-op says which one failed.
        println!("nrpt applied: {}", is_nrpt_applied());
        let eg = egress::detect();
        println!(
            "egress: if{:?} vpn={:?}",
            eg.as_ref().map(|e| e.if_index),
            eg.as_ref().map(|e| e.vpn_active)
        );
        if let Some(eg) = &eg {
            let server: Ipv4Addr = resolvers::PROVIDERS[0].v4[0].parse().unwrap();
            for ns in AG_NRPT_CORE {
                println!(
                    "  {}\n    isp={:?}\n    tun={:?}\n    best={:?}",
                    ns,
                    crate::dns_client::resolve_a_via(ns, server, eg.if_index),
                    crate::dns_client::resolve_a_via(ns, server, 0),
                    resolvers::resolve_a_best(ns, eg.if_index)
                        .map(|(a, p, v)| format!("{:?} via {} {:?}", a, p, v))
                );
            }
        }

        refresh_pinned_hosts();

        let after = std::fs::read_to_string(&path).unwrap_or_default();
        println!("--- after ---\n{}\n-------------", after);

        // Whatever else lived in the file has to survive untouched.
        for line in before.lines().filter(|l| !l.trim().is_empty()) {
            assert!(
                after.contains(line),
                "hosts lost a pre-existing line: {}",
                line
            );
        }

        // The outcome differs by design, so assert the right one instead of
        // passing silently either way.
        let pinned = after.contains("AG_UNLOCKER_HOSTS_BEGIN");
        if eg.map_or(false, |e| e.vpn_active) {
            assert!(pinned, "a tunnel is up but nothing was pinned");
        } else {
            assert!(!pinned, "no tunnel, so the block should not be there");
            println!("(без VPN пиннинг не нужен — правила NRPT справляются сами)");
        }
    }
}
