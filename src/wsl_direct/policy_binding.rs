//! Local receiving binding, separate from the candidate bytes it qualifies.

use crate::wsl_direct_public_policy::{Candidate, CandidateDecision, PolicyUnavailable};
use std::net::SocketAddr;

// Root selects Some only after receiving this exact candidate and integration.
// This file is deliberately outside the candidate's canonical source bytes.
const RECEIVED_PUBLIC_V1: Option<[u8; 32]> = Some([
    0xfc, 0x13, 0x35, 0x5b, 0x92, 0x78, 0xc6, 0xb9, 0x26, 0x2d, 0x22, 0x11, 0x8c, 0xaa, 0x5b, 0x72,
    0xe2, 0x7f, 0x44, 0x79, 0x2e, 0xac, 0x49, 0xb1, 0x00, 0xee, 0x14, 0x60, 0x7c, 0xf4, 0x6a, 0x42,
]);

pub(crate) struct BoundPublicV1 {
    candidate: Candidate<'static>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Denied,
}

impl BoundPublicV1 {
    pub(crate) fn bundled() -> Result<Self, PolicyUnavailable> {
        let expected = RECEIVED_PUBLIC_V1
            .filter(|digest| *digest != [0; 32])
            .ok_or(PolicyUnavailable)?;
        let candidate = Candidate::bundled()?;
        if candidate.digest() != expected {
            return Err(PolicyUnavailable);
        }
        Ok(Self { candidate })
    }
    pub(crate) fn check(&self, address: SocketAddr) -> Result<(), Error> {
        let scope = match address {
            SocketAddr::V6(v) => v.scope_id(),
            SocketAddr::V4(_) => 0,
        };
        match self
            .candidate
            .candidate_only(address.ip(), address.port(), scope)
        {
            CandidateDecision::Allow => Ok(()),
            CandidateDecision::Deny(_) => Err(Error::Denied),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reviewed_selection_constructs_the_actual_bundled_policy() {
        let bound = BoundPublicV1::bundled().expect("reviewed fixed policy must reconstruct");
        assert_eq!(
            bound.candidate.digest(),
            [
                0xfc, 0x13, 0x35, 0x5b, 0x92, 0x78, 0xc6, 0xb9, 0x26, 0x2d, 0x22, 0x11, 0x8c, 0xaa,
                0x5b, 0x72, 0xe2, 0x7f, 0x44, 0x79, 0x2e, 0xac, 0x49, 0xb1, 0x00, 0xee, 0x14, 0x60,
                0x7c, 0xf4, 0x6a, 0x42,
            ]
        );
    }

    #[test]
    fn production_constructor_reaches_the_local_classifier() {
        let bound = BoundPublicV1::bundled().unwrap();
        for address in [
            "8.8.8.8:8443",
            "192.0.0.9:65535",
            "[2606:4700::1111]:8443",
            "[::ffff:8.8.8.8]:443",
            "[64:ff9b::808:808]:443",
        ] {
            assert_eq!(bound.check(address.parse().unwrap()), Ok(()), "{address}");
        }
        for address in [
            "127.0.0.1:443",
            "10.0.0.1:8443",
            "100.64.0.1:443",
            "224.0.0.1:443",
            "8.8.8.8:0",
            "[::ffff:127.0.0.1]:443",
            "[64:ff9b::a00:1]:443",
            "[2606:4700::1%1]:443",
        ] {
            assert_eq!(
                bound.check(address.parse().unwrap()),
                Err(Error::Denied),
                "{address}"
            );
        }
    }
}
