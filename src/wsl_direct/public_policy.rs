//! Immutable PublicV1 candidate. Equality of digests does not install trust.

use ipnet::IpNet;
use ring::digest;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const RULE_ID: &[u8] = b"mapped-v4;deny-multicast;v4-default-unicast;v6-default-2000::/3;longest-prefix;flags-dfgT-rF;unknown-deny;terminated-deny;nat64-/96-public-v4";
const ORDINARY_V6: IpNet =
    IpNet::new_assert(IpAddr::V6(Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0)), 3);
const WELL_KNOWN_NAT64: IpNet = IpNet::new_assert(
    IpAddr::V6(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0)),
    96,
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PolicyUnavailable;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reason {
    InvalidInput,
    Multicast,
    SpecialFlags,
    Terminated,
    UnknownAllocation,
    Translation,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CandidateDecision {
    Allow,
    Deny(Reason),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Flag {
    Unknown = 0,
    False = 1,
    True = 2,
}
#[derive(Clone, Copy)]
struct Record<'a> {
    network: IpNet,
    flags: [Flag; 4],
    termination: &'a str,
}
#[derive(Clone, Copy)]
struct Source<'a> {
    family: u8,
    url: &'a str,
    updated: &'a str,
    expected_hash: [u8; 32],
    raw: &'a [u8],
}

include!("policy_data/records.rs");

/// A candidate is evidence for receiving, not a production authorization capability.
/// No accepted binding is installed here and no constructor accepts an approval hash.
pub(crate) struct Candidate<'a> {
    sources: &'a [Source<'a>],
    records: &'a [Record<'a>],
    package_checksum: [u8; 32],
    adapter_hash: [u8; 32],
    digest: [u8; 32],
}
impl Candidate<'static> {
    pub fn bundled() -> Result<Self, PolicyUnavailable> {
        Self::from_parts(SOURCES, RECORDS, IPNET_CHECKSUM, ROW_BYTES_SHA256)
    }
}
impl<'a> Candidate<'a> {
    fn from_parts(
        sources: &'a [Source<'a>],
        records: &'a [Record<'a>],
        package_checksum: [u8; 32],
        row_hash: [u8; 32],
    ) -> Result<Self, PolicyUnavailable> {
        if package_checksum == [0; 32]
            || package_checksum != IPNET_CHECKSUM
            || sources.len() != 2
            || records.is_empty()
        {
            return Err(PolicyUnavailable);
        }
        let mut family_mask = 0u8;
        let mut previous_url = None;
        for source in sources {
            let bit = match source.family {
                4 => 1,
                6 => 2,
                _ => return Err(PolicyUnavailable),
            };
            if family_mask & bit != 0
                || source.url.is_empty()
                || previous_url.is_some_and(|url| url >= source.url)
                || !valid_date(source.updated, false)
                || source.expected_hash == [0; 32]
                || hash(source.raw) != source.expected_hash
            {
                return Err(PolicyUnavailable);
            }
            family_mask |= bit;
            previous_url = Some(source.url);
        }
        if family_mask != 3 {
            return Err(PolicyUnavailable);
        }
        let mut previous_key = None;
        let mut record_families = 0u8;
        for record in records {
            let key = record_key(record);
            if record.network.addr() != record.network.network()
                || previous_key.is_some_and(|previous| previous >= key)
                || (!record.termination.is_empty() && !valid_date(record.termination, true))
            {
                return Err(PolicyUnavailable);
            }
            record_families |= if key.0 == 4 { 1 } else { 2 };
            previous_key = Some(key);
        }
        if record_families != 3 || row_hash == [0; 32] || hash(&encode_rows(records)?) != row_hash {
            return Err(PolicyUnavailable);
        }
        let mut result = Self {
            sources,
            records,
            package_checksum,
            adapter_hash: hash(include_bytes!("public_policy.rs")),
            digest: [0; 32],
        };
        result.digest = hash(&result.canonical_bytes()?);
        if result.digest == [0; 32] {
            return Err(PolicyUnavailable);
        }
        Ok(result)
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    /// Observing/supplying a matching peer digest cannot install local trust.
    /// Root must receive this exact candidate independently and install the trusted
    /// binding through the separate receiving owner before a production adapter exists.
    pub fn authorize(
        &self,
        _address: IpAddr,
        _port: u16,
        _scope: u32,
        _peer_claim: Option<[u8; 32]>,
    ) -> Result<CandidateDecision, PolicyUnavailable> {
        Err(PolicyUnavailable)
    }
    /// Non-authorizing candidate evaluation. Only the separate receiving binding
    /// can qualify these semantics for a production consumer.
    pub(crate) fn candidate_only(
        &self,
        address: IpAddr,
        port: u16,
        scope: u32,
    ) -> CandidateDecision {
        evaluate(self.records, address, port, scope)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PolicyUnavailable> {
        let mut bytes = b"AGWPUB01\0\x01\0\x01".to_vec();
        lp(&mut bytes, b"ipnet")?;
        lp(&mut bytes, b"2.12.2")?;
        bytes.extend(self.package_checksum);
        bytes.extend(self.adapter_hash);
        bytes.extend(
            u32::try_from(self.sources.len())
                .map_err(|_| PolicyUnavailable)?
                .to_be_bytes(),
        );
        for source in self.sources {
            lp(&mut bytes, source.url.as_bytes())?;
            lp(&mut bytes, source.updated.as_bytes())?;
            bytes.extend(source.expected_hash);
        }
        bytes.extend(
            u32::try_from(self.records.len())
                .map_err(|_| PolicyUnavailable)?
                .to_be_bytes(),
        );
        bytes.extend(encode_rows(self.records)?);
        lp(&mut bytes, RULE_ID)?;
        Ok(bytes)
    }
}

fn valid_date(value: &str, month_only: bool) -> bool {
    let bytes = value.as_bytes();
    let expected = if month_only { 7 } else { 10 };
    if bytes.len() != expected || bytes[4] != b'-' || (!month_only && bytes[7] != b'-') {
        return false;
    }
    if bytes
        .iter()
        .enumerate()
        .any(|(i, b)| i != 4 && (month_only || i != 7) && !b.is_ascii_digit())
    {
        return false;
    }
    let month = (bytes[5] - b'0') * 10 + bytes[6] - b'0';
    if !(1..=12).contains(&month) {
        return false;
    }
    month_only || {
        let day = (bytes[8] - b'0') * 10 + bytes[9] - b'0';
        (1..=31).contains(&day)
    }
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    digest::digest(&digest::SHA256, bytes)
        .as_ref()
        .try_into()
        .unwrap()
}
fn lp(output: &mut Vec<u8>, value: &[u8]) -> Result<(), PolicyUnavailable> {
    output.extend(
        u32::try_from(value.len())
            .map_err(|_| PolicyUnavailable)?
            .to_be_bytes(),
    );
    output.extend(value);
    Ok(())
}
fn record_key(record: &Record<'_>) -> (u8, [u8; 16], u8) {
    let mut bytes = [0; 16];
    let family = match record.network.network() {
        IpAddr::V4(v) => {
            bytes[12..].copy_from_slice(&v.octets());
            4
        }
        IpAddr::V6(v) => {
            bytes = v.octets();
            6
        }
    };
    (family, bytes, record.network.prefix_len())
}
fn encode_rows(records: &[Record<'_>]) -> Result<Vec<u8>, PolicyUnavailable> {
    let mut bytes = Vec::new();
    for record in records {
        let (family, network, prefix) = record_key(record);
        bytes.extend([family, prefix]);
        bytes.extend(network);
        bytes.extend(record.flags.map(|flag| flag as u8));
        lp(&mut bytes, record.termination.as_bytes())?;
    }
    Ok(bytes)
}

/// Candidate semantics only. Longest-prefix matching uses maintained ipnet; no
/// address enumeration, range chain, runtime XML, per-address allocation or I/O.
fn evaluate(records: &[Record<'_>], address: IpAddr, port: u16, scope: u32) -> CandidateDecision {
    if port == 0 || scope != 0 {
        return CandidateDecision::Deny(Reason::InvalidInput);
    }
    let address = match address {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v)),
        v => v,
    };
    if address.is_multicast() {
        return CandidateDecision::Deny(Reason::Multicast);
    }
    let selected = records
        .iter()
        .filter(|record| record.network.contains(&address))
        .max_by_key(|record| record.network.prefix_len());
    if let Some(record) = selected {
        if !record.termination.is_empty() {
            return CandidateDecision::Deny(Reason::Terminated);
        }
        if record.flags != [Flag::True, Flag::True, Flag::True, Flag::False] {
            return CandidateDecision::Deny(Reason::SpecialFlags);
        }
        if WELL_KNOWN_NAT64.contains(&address) {
            let IpAddr::V6(ip) = address else {
                return CandidateDecision::Deny(Reason::Translation);
            };
            let bytes = ip.octets();
            let embedded = IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]));
            if evaluate(records, embedded, port, 0) != CandidateDecision::Allow {
                return CandidateDecision::Deny(Reason::Translation);
            }
        }
        return CandidateDecision::Allow;
    }
    match address {
        IpAddr::V4(_) => CandidateDecision::Allow,
        IpAddr::V6(_) if ORDINARY_V6.contains(&address) => CandidateDecision::Allow,
        _ => CandidateDecision::Deny(Reason::UnknownAllocation),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed(candidate: &Candidate<'_>, text: &str) -> bool {
        candidate.candidate_only(text.parse().unwrap(), 8443, 0) == CandidateDecision::Allow
    }

    #[test]
    fn registry_exceptions_defaults_and_representative_boundaries() {
        let c = Candidate::bundled().unwrap();
        for text in [
            "1.1.1.1",
            "8.8.8.8",
            "100.63.255.255",
            "100.128.0.0",
            "192.0.0.9",
            "192.0.0.10",
            "192.31.196.0",
            "192.175.48.255",
            "223.255.255.255",
            "2000::",
            "2001:1::3",
            "2606:4700:4700::1111",
            "3fff:1000::",
            "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ] {
            assert!(allowed(&c, text), "{text}");
        }
        for text in [
            "0.0.0.0",
            "0.255.255.255",
            "10.0.0.1",
            "100.64.0.0",
            "100.127.255.255",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.0.0.0",
            "192.0.0.8",
            "192.0.0.11",
            "192.0.0.170",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.0.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.0",
            "239.255.255.255",
            "240.0.0.0",
            "255.255.255.255",
            "::",
            "::1",
            "::8.8.8.8",
            "100:0:0:1::",
            "1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "2001::1",
            "2001:10::1",
            "2001:db8::1",
            "2002::1",
            "3fff::",
            "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff",
            "4000::",
            "5f00::1",
            "fc00::1",
            "fe80::1",
            "ff00::1",
        ] {
            assert!(!allowed(&c, text), "{text}");
        }
        assert_eq!(
            c.candidate_only("8.8.8.8".parse().unwrap(), 0, 0),
            CandidateDecision::Deny(Reason::InvalidInput)
        );
        assert_eq!(
            c.candidate_only("2606:4700::1".parse().unwrap(), 443, 1),
            CandidateDecision::Deny(Reason::InvalidInput)
        );
    }

    #[test]
    fn mapped_normalization_and_nat64_do_not_expose_private_ipv4() {
        let c = Candidate::bundled().unwrap();
        for text in ["::ffff:8.8.8.8", "64:ff9b::808:808"] {
            assert!(allowed(&c, text), "{text}");
        }
        for text in [
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:100.64.0.1",
            "64:ff9b::a00:1",
            "64:ff9b::7f00:1",
            "64:ff9b::6440:1",
            "64:ff9b::e000:1",
            "64:ff9b:1::808:808",
        ] {
            assert!(!allowed(&c, text), "{text}");
        }
    }

    #[test]
    fn unknown_narrower_and_terminated_rows_never_fall_back() {
        let parent = Record {
            network: "192.0.0.0/24".parse().unwrap(),
            flags: [Flag::True, Flag::True, Flag::True, Flag::False],
            termination: "",
        };
        let child = Record {
            network: "192.0.0.9/32".parse().unwrap(),
            flags: [Flag::True, Flag::True, Flag::Unknown, Flag::False],
            termination: "",
        };
        assert_eq!(
            evaluate(&[parent, child], "192.0.0.9".parse().unwrap(), 443, 0),
            CandidateDecision::Deny(Reason::SpecialFlags)
        );
        assert_eq!(
            evaluate(&[parent, child], "192.0.0.10".parse().unwrap(), 443, 0),
            CandidateDecision::Allow
        );
        let child = Record {
            flags: parent.flags,
            termination: "2015-03",
            ..child
        };
        assert_eq!(
            evaluate(&[parent, child], "192.0.0.9".parse().unwrap(), 443, 0),
            CandidateDecision::Deny(Reason::Terminated)
        );
    }

    #[test]
    fn missing_corrupt_duplicate_or_changed_materials_are_unavailable() {
        assert!(
            Candidate::from_parts(&SOURCES[..1], RECORDS, IPNET_CHECKSUM, ROW_BYTES_SHA256)
                .is_err()
        );
        let mut sources = SOURCES.to_vec();
        sources[0].raw = b"truncated XML";
        assert!(
            Candidate::from_parts(&sources, RECORDS, IPNET_CHECKSUM, ROW_BYTES_SHA256).is_err()
        );
        let mut sources = SOURCES.to_vec();
        sources[1].expected_hash = [0; 32];
        assert!(
            Candidate::from_parts(&sources, RECORDS, IPNET_CHECKSUM, ROW_BYTES_SHA256).is_err()
        );
        let mut records = RECORDS.to_vec();
        records.push(records[0]);
        assert!(
            Candidate::from_parts(SOURCES, &records, IPNET_CHECKSUM, ROW_BYTES_SHA256).is_err()
        );
        let mut records = RECORDS.to_vec();
        records[0].flags = [Flag::True; 4];
        assert!(
            Candidate::from_parts(SOURCES, &records, IPNET_CHECKSUM, ROW_BYTES_SHA256).is_err()
        );
        let mut records = RECORDS.to_vec();
        records[0].network = "0.0.0.1/8".parse().unwrap();
        assert!(
            Candidate::from_parts(SOURCES, &records, IPNET_CHECKSUM, ROW_BYTES_SHA256).is_err()
        );
        assert!(Candidate::from_parts(SOURCES, RECORDS, [0; 32], ROW_BYTES_SHA256).is_err());
        assert!(Candidate::from_parts(SOURCES, RECORDS, IPNET_CHECKSUM, [0; 32]).is_err());
    }

    #[test]
    fn canonical_identity_is_nonzero_and_never_self_authorizes() {
        let c = Candidate::bundled().unwrap();
        let bytes = c.canonical_bytes().unwrap();
        assert_eq!(&bytes[..12], b"AGWPUB01\0\x01\0\x01");
        assert_eq!(&bytes[12..21], b"\0\0\0\x05ipnet");
        assert_eq!(&bytes[21..31], b"\0\0\0\x062.12.2");
        assert_ne!(c.digest(), [0; 32]);
        assert_eq!(c.digest(), hash(&bytes));
        for claimed in [None, Some([0; 32]), Some([0xff; 32]), Some(c.digest())] {
            assert_eq!(
                c.authorize("8.8.8.8".parse().unwrap(), 443, 0, claimed),
                Err(PolicyUnavailable)
            );
        }
    }
}
