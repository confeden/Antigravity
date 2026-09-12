use std::time::Duration;

use crate::utils::{powershell, powershell_within};

// Finding the ISP-facing interface, and why that is the whole job here.
//
// With a full-tunnel VPN up, the NRPT rules resolve to nothing useful: xbox-dns
// substitutes addresses only for clients it geolocates to a blocked region, and
// through the tunnel it sees a foreign address and forwards the genuine Google
// one. The region gate then answers 400 as if the unlocker were not installed.
//
// Routing the resolver addresses back onto the ISP link does not work either,
// and this is worth remembering rather than rediscovering: AmneziaVPN already
// holds its own /32 for exactly those addresses. Equal prefix length hands the
// decision to RouteMetric + InterfaceMetric, where the tunnel's 5 beats
// Ethernet's 26; no legal RouteMetric closes that gap, the only other lever -
// the interface metric - would drag every other route off the VPN with it, and
// the WireGuard tunnel service restores its route as fast as it is deleted.
//
// What does work is not touching the routing table at all: `dns_client` names
// the outgoing interface on the socket via IP_UNICAST_IF, which skips the route
// lookup entirely. Verified against a live tunnel - the same resolver answers
// 172.217.119.4 (genuine Google) through the tunnel and 87.228.47.204 (proxy)
// through the ISP link, and a query to an address nothing holds a route for
// still leaves through the named interface. So this module only has to say
// which interface that is; `hosts_pin` does the rest.

// The resolver addresses used to live here as a single xbox-dns.ru pair. They
// now live in `resolvers`, which holds several providers and picks between them
// per query - a hardcoded pair cannot notice that a provider stopped
// substituting a name, which is exactly how the tool broke. This module is back
// to its one job: naming the interface those queries must leave through.

/// Prefixes an earlier build pinned to the physical adapter. They are harmless
/// but pointless, and the persistent ones outlive the tool, so cleanup drops
/// them. Remove this once no installed build can still have written them.
const LEGACY_PINNED_PREFIXES: &[&str] = &[
    "111.88.96.50/32",
    "111.88.96.51/32",
    "2a00:ab00:1233:26::50/128",
    "2a00:ab00:1233:26::51/128",
];

#[derive(Debug, Clone)]
pub struct Egress {
    pub if_index: u32,
    /// True when some non-physical adapter also holds a default route - i.e. a
    /// tunnel is up and the NRPT path alone cannot work.
    pub vpn_active: bool,
}

/// `ifIndex|gateway|vpn`. The gateway itself is not kept - nothing routes any
/// more - but an interface without one is not an internet-facing link, so its
/// presence still decides whether the line describes a usable egress.
fn parse_egress(line: &str) -> Option<Egress> {
    let mut parts = line.trim().split('|');
    let if_index = parts.next()?.trim().parse::<u32>().ok()?;
    let gateway = parts.next()?.trim();
    let vpn = parts.next()?.trim();

    if gateway.is_empty() || gateway == "-" {
        return None;
    }
    Some(Egress {
        if_index,
        vpn_active: vpn.eq_ignore_ascii_case("true"),
    })
}

/// The default route that belongs to real hardware. `Get-NetAdapter -Physical`
/// drops WireGuard/TAP tunnels and the Hyper-V/VMware virtual switches in one
/// go, and requiring a real next hop drops host-only adapters, which carry a
/// gateway address but no default route.
pub fn detect() -> Option<Egress> {
    const SCRIPT: &str = "\
$phys=@(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | \
  Where-Object {$_.Status -eq 'Up'} | ForEach-Object {$_.ifIndex}); \
$def=@(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -PolicyStore ActiveStore -ErrorAction SilentlyContinue); \
$mine=@($def | Where-Object {$phys -contains $_.ifIndex -and $_.NextHop -ne '0.0.0.0'}); \
if ($mine.Count -eq 0) { 'none' } else { \
  $best=$mine | Sort-Object {[int]$_.RouteMetric + \
    [int](Get-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily IPv4 \
      -ErrorAction SilentlyContinue).InterfaceMetric} | Select-Object -First 1; \
  $vpn=@($def | Where-Object {$phys -notcontains $_.ifIndex}).Count -gt 0; \
  '{0}|{1}|{2}' -f $best.ifIndex,$best.NextHop,$vpn }";

    let out = powershell(SCRIPT)?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .and_then(parse_egress)
}

// Which way the *client* leaves, which is not the question `vpn_active` answers.
//
// `vpn_active` reads the routing table, and the routing table only knows that
// some tunnel holds `0.0.0.0/0`. Windows VPN clients route per application - an
// exclusion list, or an "only these apps" list - and that decision is invisible
// there: the tunnel holds the same default route either way, because the
// filtering happens in WFP, keyed on the executable image. So a machine can show
// a full tunnel while `language_server.exe` talks to Google straight off the ISP
// link.
//
// That combination is the worst state this tool can produce, and it produced it:
// the client sat in the blocked region *and* the DNS layer had stood down for a
// tunnel the client was not using, so nothing lifted the gate and every request
// came back `User location is not supported for the API use` (G29). The routing
// table cannot tell them apart. The client's own sockets can, and that is all
// this does: read where its established connections are sourced from.

/// Where the client's own traffic leaves the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientEgress {
    /// Measured: at least one of its connections is sourced from a physical
    /// adapter. A tunnel may well be up - this client is not inside it.
    Physical,
    /// Measured: its connections are sourced from a tunnel adapter.
    Tunnel,
    /// Measured: some of each, which is a state of its own and not a rounding
    /// error.
    ///
    /// Seen live the moment the owner took our service out of his VPN's
    /// exclusions: six sockets still on the physical link, two new ones already
    /// sourced from `10.8.1.2`. For the DNS layer this counts as "outside" — the
    /// rules are needed by the half that is out, exactly as for `Physical`. For
    /// anything that asks "will a provider serving only Russian addresses accept
    /// us", it counts as "inside": the connections that leave through the tunnel
    /// will be refused whatever the others do.
    Mixed,
    /// Measured, and it settles nothing by itself: the client's traffic leaves
    /// through **our own** local proxy, so where it goes after that is a
    /// question about the relay's socket, not the client's.
    ///
    /// This is the ordinary state for a patched client with the proxy route on
    /// (S40/S42), and it used to read as `Unknown` - "Antigravity has not asked
    /// for anything yet" - about a client that was asking constantly. Measured
    /// on the owner's machine: the IDE's language server held ten connections to
    /// `127.0.0.1:53129` and not one to anything on 443.
    ViaLocalProxy,
    /// Nothing to read. The client is not running, or has not opened an outbound
    /// connection yet.
    Unknown,
}

/// Where the two processes that can carry a gate connection leave the machine.
///
/// Both halves in one reading because they come from one query, and because the
/// interesting answer is the *pair*: a client that talks only to our proxy
/// (`ViaLocalProxy`) plus a relay in the tunnel is the state where a provider
/// that serves only Russian clients refuses us, and the user sees a 400 with
/// every switch in the window green.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
    pub client: ClientEgress,
    /// Our own service. `Unknown` when it is not running or holds nothing open.
    pub relay: ClientEgress,
}

/// The language server under both names it ships as: `language_server.exe` in the
/// Desktop app and `language_server_windows_x64.exe` in the IDE. The Electron
/// shell is deliberately not matched - it never carries a gated call, so its
/// sockets would only add noise to the count.
const CLIENT_PROCESS_GLOB: &str = "language_server*";

/// Bound for the probe below. Shorter than `PS_LIMIT`: this is three read-only
/// cmdlets on a path the user is watching, and if the machine cannot answer that
/// in fifteen seconds the honest result is `Unknown`, not a frozen menu (I24).
const CLIENT_PROBE_LIMIT: Duration = Duration::from_secs(15);

/// Reads where the client's live connections are sourced from.
///
/// Port 443 is what says something about egress - the client also holds loopback
/// sockets to the Electron host bridge, and those do not. With one exception,
/// and it is the one that matters most now: a connection to **our own proxy
/// port** is the client telling us it is not making gate connections at all, and
/// that its egress is the relay's to answer. Counted separately, never as a
/// tunnel: loopback is not an adapter the routing table has an opinion about.
pub fn read() -> Reading {
    let script = format!(
        "$ids=@(Get-Process -Name '{glob}' -ErrorAction SilentlyContinue | \
           ForEach-Object {{$_.Id}}); \
         $rid=@(Get-Process -Name '{relay}' -ErrorAction SilentlyContinue | \
           ForEach-Object {{$_.Id}}); \
         if ($ids.Count -eq 0 -and $rid.Count -eq 0) {{ 'none' }} else {{ \
           $phys=@(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | \
             Where-Object {{$_.Status -eq 'Up'}} | ForEach-Object {{$_.ifIndex}}); \
           $ix=@{{}}; \
           foreach ($a in @(Get-NetIPAddress -ErrorAction SilentlyContinue)) {{ \
             $ix[($a.IPAddress -split '%')[0]]=$a.InterfaceIndex }}; \
           $p=0; $t=0; $l=0; $rp=0; $rt=0; \
           foreach ($c in @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue)) {{ \
             $mine = $ids -contains $c.OwningProcess; \
             $ours = $rid -contains $c.OwningProcess; \
             if (-not $mine -and -not $ours) {{ continue }}; \
             if ($mine -and $c.RemotePort -eq {port} -and $c.RemoteAddress -eq '{listen}') {{ \
               $l++; continue }}; \
             if ($c.RemotePort -ne 443) {{ continue }}; \
             $i=$ix[($c.LocalAddress -split '%')[0]]; \
             if ($null -eq $i) {{ continue }}; \
             $hw = $phys -contains $i; \
             if ($mine) {{ if ($hw) {{ $p++ }} else {{ $t++ }} }} \
             else {{ if ($hw) {{ $rp++ }} else {{ $rt++ }} }} }}; \
           '{{0}}|{{1}}|{{2}}|{{3}}|{{4}}' -f $p,$t,$l,$rp,$rt }}",
        glob = CLIENT_PROCESS_GLOB,
        relay = relay_process_name(),
        port = crate::proxy::LISTEN_PORT,
        listen = crate::proxy::LISTEN_IP,
    );

    let Some(out) = powershell_within(&script, CLIENT_PROBE_LIMIT) else {
        return Reading {
            client: ClientEgress::Unknown,
            relay: ClientEgress::Unknown,
        };
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .map_or(
            Reading {
                client: ClientEgress::Unknown,
                relay: ClientEgress::Unknown,
            },
            parse_reading,
        )
}

/// `Get-Process` wants the image name without its extension. Taken from the
/// installed path rather than spelled out again, so the two cannot drift.
fn relay_process_name() -> String {
    crate::background::installed_exe()
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "ag_dns".to_string())
}

fn parse_reading(line: &str) -> Reading {
    let mut fields = line.trim().split('|').map(|f| f.trim().parse::<u32>().ok());
    let counts = (
        fields.next().flatten(),
        fields.next().flatten(),
        fields.next().flatten(),
        fields.next().flatten(),
        fields.next().flatten(),
    );
    let (Some(p), Some(t), Some(l), Some(rp), Some(rt)) = counts else {
        return Reading {
            client: ClientEgress::Unknown,
            relay: ClientEgress::Unknown,
        };
    };
    Reading {
        client: classify_client(p, t, l),
        // No `ViaLocalProxy` for our own service: it *is* the local proxy, and
        // the only question about it is which adapter its sockets sit on.
        relay: classify_client(rp, rt, 0),
    }
}

fn classify_client(phys: u32, tunnel: u32, ours: u32) -> ClientEgress {
    match (phys, tunnel, ours) {
        // Both sides at once — two language servers on different sides of a
        // split tunnel, or a process whose old sockets outlive a rule change.
        // Named rather than rounded to one of them: `vpn_verdict` treats it as
        // "not in the tunnel" (the rules are needed by the half that is out,
        // which is the same reason `Physical` does), while the window must not
        // tell anyone "трафик идёт мимо VPN" about traffic that is half in it.
        (p, t, _) if p > 0 && t > 0 => ClientEgress::Mixed,
        // One socket off the tunnel is enough. That traffic faces the gate
        // whatever the rest of it does, so the rules are needed either way, and
        // reading a split as "in the tunnel" would restore exactly the failure
        // this probe exists to catch.
        (p, _, _) if p > 0 => ClientEgress::Physical,
        (_, t, _) if t > 0 => ClientEgress::Tunnel,
        // Nothing of its own, everything through us: the honest answer is that
        // this process no longer decides, not that it is idle.
        (_, _, l) if l > 0 => ClientEgress::ViaLocalProxy,
        // Running, but nothing outbound yet. Not evidence of anything.
        _ => ClientEgress::Unknown,
    }
}

/// Kept for the one caller that only asks about the client: the stand-down
/// decision, which is about the client and must not start answering a different
/// question because a second one became measurable (D13, P34).
pub fn client_egress() -> ClientEgress {
    read().client
}

/// Whether the DNS layer must stand down for a tunnel (D13).
///
/// The single place that decision is made, because it is made in three: menu 1
/// when it writes the rules, `refresh_pinned_hosts` when a later tunnel makes
/// them wrong, and the relay's warm loop when it chooses between substituting and
/// passing through. Three copies of a two-term condition is three chances for one
/// of them to keep the old meaning.
///
/// It takes evidence to stand down, not the absence of evidence. `Unknown` -
/// which is the ordinary case, since menu 1 normally runs before Antigravity is
/// started - installs the rules: an unnecessary rule costs one hop (G26), a
/// missing one costs every request (G29). Owner's call, revising D13.
///
/// Returns the measurement alongside the verdict so a caller that reports it does
/// not have to repeat the condition or spawn the probe twice. With no tunnel up
/// the probe does not run at all - the answer cannot change the verdict, and the
/// warm loop would be paying for it every four minutes.
pub fn vpn_verdict(egress: Option<&Egress>) -> (bool, ClientEgress) {
    if !egress.is_some_and(|e| e.vpn_active) {
        return (false, ClientEgress::Unknown);
    }
    let client = client_egress();
    (client == ClientEgress::Tunnel, client)
}

/// Drops the host routes an earlier build pinned. Deleted per interface rather
/// than by prefix alone, so a route stranded on an adapter the machine no longer
/// uses goes too; netsh cleans up whatever the cmdlet could not.
pub fn remove_legacy_routes() {
    let list = LEGACY_PINNED_PREFIXES
        .iter()
        .map(|p| format!("'{}'", p))
        .collect::<Vec<_>>()
        .join(",");
    let cmd = format!(
        "foreach ($d in @({})) {{ \
           $fam=$(if ($d -like '*:*') {{'ipv6'}} else {{'ipv4'}}); \
           foreach ($s in @('ActiveStore','PersistentStore')) {{ \
             $st=$(if ($s -eq 'ActiveStore') {{'active'}} else {{'persistent'}}); \
             foreach ($r in @(Get-NetRoute -DestinationPrefix $d -PolicyStore $s \
                 -ErrorAction SilentlyContinue)) {{ \
               Remove-NetRoute -DestinationPrefix $d -InterfaceIndex $r.ifIndex \
                 -PolicyStore $s -Confirm:$false -ErrorAction SilentlyContinue; \
               if (@(Get-NetRoute -DestinationPrefix $d -PolicyStore $s -ErrorAction SilentlyContinue | \
                   Where-Object {{$_.ifIndex -eq $r.ifIndex}}).Count -gt 0) {{ \
                 netsh interface $fam delete route prefix=$d interface=$($r.ifIndex) store=$st | Out-Null }} }} }} }}",
        list
    );
    powershell(&cmd);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_client;
    use std::net::Ipv4Addr;

    #[test]
    fn egress_line_is_parsed() {
        let eg = parse_egress("17|192.168.0.1|True").expect("parses");
        assert_eq!(eg.if_index, 17);
        assert!(eg.vpn_active);

        let plain = parse_egress(" 12|10.0.0.1|False ").expect("parses");
        assert!(!plain.vpn_active);
    }

    /// The counts a split-tunnelled machine produces, and what each has to mean.
    /// `(0,0)` is the one that decides the default for most users: the client is
    /// running but has not dialled out yet, and reading that as "in the tunnel"
    /// would stand the layer down on no evidence at all.
    #[test]
    fn client_socket_counts_are_read_as_evidence() {
        let client = |line| parse_reading(line).client;
        assert_eq!(client("2|0|0|0|0"), ClientEgress::Physical);
        assert_eq!(client("0|3|0|0|0"), ClientEgress::Tunnel);
        assert_eq!(client("0|0|0|0|0"), ClientEgress::Unknown);
        // Half in, half out: its own answer, and still not a stand-down (below).
        assert_eq!(client("1|4|0|0|0"), ClientEgress::Mixed);
        // The state a patched client with the proxy route on is normally in:
        // every connection it holds is to our own listener. Measured on the
        // owner's machine, where this used to read as `Unknown` and the window
        // said «Antigravity ещё ничего не запрашивал» about a client that was
        // being refused by the gate at that very moment.
        assert_eq!(client("0|0|10|0|0"), ClientEgress::ViaLocalProxy);
        // Its own traffic still outranks that: those sockets do face the gate.
        assert_eq!(client("1|0|10|0|0"), ClientEgress::Physical);
        assert_eq!(client("0|1|10|0|0"), ClientEgress::Tunnel);
        assert_eq!(client("1|1|10|0|0"), ClientEgress::Mixed);
        // Nothing running at all.
        assert_eq!(client("none"), ClientEgress::Unknown);
        assert_eq!(client(""), ClientEgress::Unknown);
        assert_eq!(client("2|x|0|0|0"), ClientEgress::Unknown);
        assert_eq!(client("2|0|0"), ClientEgress::Unknown);
    }

    /// The half the client can no longer answer (G46): with everything of its
    /// own going to `127.0.0.1`, the socket that faces the gate is ours, and
    /// which adapter *it* sits on is what a provider serving only Russian
    /// clients will judge us by.
    #[test]
    fn the_relays_own_egress_is_read_beside_the_clients() {
        let relay = |line| parse_reading(line).relay;
        assert_eq!(relay("0|0|10|3|0"), ClientEgress::Physical);
        assert_eq!(relay("0|0|10|0|3"), ClientEgress::Tunnel);
        assert_eq!(relay("0|0|10|0|0"), ClientEgress::Unknown);
        // A relay holding both: the connections that do leave through the
        // tunnel will be refused by a provider that serves Russian addresses
        // only, so this is not "outside" — measured live when the owner took
        // `ag_dns.exe` out of his VPN's exclusions.
        assert_eq!(relay("0|0|10|1|4"), ClientEgress::Mixed);
        // The pair the owner's machine was in when the gate refused him: the
        // client talks only to us, and we were the ones inside the tunnel.
        let bad = parse_reading("0|0|10|0|4");
        assert_eq!(bad.client, ClientEgress::ViaLocalProxy);
        assert_eq!(bad.relay, ClientEgress::Tunnel);
    }

    /// The regression G29 is: a tunnel holding a default route was enough to
    /// stand the whole DNS layer down, so a client excluded from that tunnel sat
    /// in the blocked region with no assistance. Standing down now needs the
    /// client to be measured *inside* the tunnel — and deliberately still only
    /// the **client**, never the relay's own reading (P34).
    /// `Mixed` must not stand the layer down: the half that is outside the
    /// tunnel is the half the rules exist for (S37, G29).
    #[test]
    fn a_split_client_still_gets_the_rules() {
        assert_eq!(
            parse_reading("1|4|0|0|0").client,
            ClientEgress::Mixed,
            "the shape this test is about"
        );
        // `vpn_verdict`'s bool is `client == Tunnel`, and nothing else.
        for (line, stands_down) in [
            ("0|4|0|0|0", true),
            ("1|4|0|0|0", false),
            ("4|0|0|0|0", false),
            ("0|0|4|0|0", false),
            ("0|0|0|0|0", false),
        ] {
            assert_eq!(
                parse_reading(line).client == ClientEgress::Tunnel,
                stands_down,
                "{line}"
            );
        }
    }

    #[test]
    fn standing_down_needs_the_client_to_be_in_the_tunnel() {
        let no_vpn = Egress {
            if_index: 29,
            vpn_active: false,
        };
        // No tunnel: nothing to stand down for, and the probe never runs.
        assert_eq!(vpn_verdict(Some(&no_vpn)), (false, ClientEgress::Unknown));
        assert_eq!(vpn_verdict(None), (false, ClientEgress::Unknown));
    }

    #[test]
    fn egress_line_rejects_garbage() {
        assert!(parse_egress("none").is_none());
        assert!(parse_egress("").is_none());
        assert!(parse_egress("17|-|False").is_none());
        assert!(parse_egress("17|192.168.0.1").is_none());
    }

    /// The one thing unit tests cannot cover: that the socket really leaves
    /// through the interface we named. Needs a live network, and only says
    /// something with a VPN up - that is when the two answers must differ.
    #[test]
    #[ignore = "needs a live network; run with --ignored"]
    fn resolves_past_the_tunnel() {
        let eg = detect().expect("physical egress");
        let server: Ipv4Addr = crate::resolvers::PROVIDERS[0].v4[0].parse().unwrap();
        let host = "cloudcode-pa.googleapis.com";
        let isp = dns_client::resolve_a_via(host, server, eg.if_index);
        let tunnelled = dns_client::resolve_a_via(host, server, 0);
        println!("egress if{} (vpn: {})", eg.if_index, eg.vpn_active);
        println!("  via ISP:     {:?}", isp);
        println!("  via default: {:?}", tunnelled);
        assert!(
            isp.as_ref().map_or(false, |a| !a.is_empty()),
            "no answer over the ISP link"
        );
        if eg.vpn_active {
            assert_ne!(
                isp.unwrap(),
                tunnelled.unwrap(),
                "the tunnel was not bypassed"
            );
        }
    }

    /// What the machine says right now. The only test that can tell a working
    /// probe from one that always answers `Unknown`, because the whole question
    /// is about live sockets.
    ///
    /// Reads, never asserts a particular answer: all three are legitimate
    /// depending on what is running. Run it with Antigravity open, and with the
    /// client in and out of the VPN's exclusion list - the printed verdict must
    /// follow.
    ///
    ///     cargo test reads_where_the_client_actually_leaves -- --ignored --nocapture
    #[test]
    #[ignore = "reads live processes and sockets; run with --ignored"]
    fn reads_where_the_client_actually_leaves() {
        let eg = detect();
        let reading = read();
        let (stand_down, _) = vpn_verdict(eg.as_ref());
        println!(
            "vpn_active: {}\nclient:     {:?}\nслужба:     {:?}\nstand down: {}  (правила DNS {})",
            eg.as_ref().is_some_and(|e| e.vpn_active),
            reading.client,
            reading.relay,
            stand_down,
            if stand_down {
                "НЕ ставятся"
            } else {
                "ставятся"
            }
        );
    }

    /// Forcing the interface must work for a destination nothing holds a route
    /// for - that is what makes the host-route pinning unnecessary.
    #[test]
    #[ignore = "needs a live network; run with --ignored"]
    fn unicast_if_needs_no_host_route() {
        let eg = detect().expect("physical egress");
        let unrouted: Ipv4Addr = "1.1.1.1".parse().unwrap();
        let answer = dns_client::resolve_a_via("github.com", unrouted, eg.if_index);
        println!("via if{} to 1.1.1.1: {:?}", eg.if_index, answer);
        assert!(
            answer.as_ref().map_or(false, |a| !a.is_empty()),
            "IP_UNICAST_IF needs a host route after all"
        );
    }
}
