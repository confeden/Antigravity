//! Provenance markers ("canaries") for release builds.
//!
//! Two independent layers, both documented in the open on purpose:
//!
//! 1. **Copyright notice** (`NOTICE`) - copyright management information carried
//!    inside every binary and inside the Win32 version resource. It states the
//!    author, the origin repository and the licence. Removing or altering CMI
//!    from a copy is an act that is assessed separately from the copying itself
//!    (17 U.S.C. §1202 / ст. 1300 ГК РФ), so an infringer who strips it does not
//!    improve their position.
//!
//! 2. **Canaries** (`STATIC_CANARY`, `RELEASE_TOKEN`) - short tokens that carry
//!    no function whatsoever. Their only job is to travel with the code:
//!    * `STATIC_CANARY` never changes, so *any* copy of *any* release matches it;
//!    * `RELEASE_TOKEN` is derived from the crate version, so a match also names
//!      the exact release the copy was taken from.
//!    Both are emitted into the binary, into the version resource, into the
//!    marker written to patched files and into the NRPT rule display name - i.e.
//!    they can be recovered from a suspect binary, from a suspect source tree,
//!    *and* from a machine that was patched by a suspect tool, without needing
//!    access to that tool's sources at all.
//!
//! Nothing here is secret. The derivation is committed so that a clone from
//! GitHub reproduces the official binary byte for byte - the same "transparent
//! build" property the licence keys already have (see `auth.rs`). Evidentiary
//! weight comes from provenance (this repository published the token first, and
//! git history dates it), not from obscurity.
//!
//! ## Canaries that already existed before this module
//!
//! These are load-bearing, so they survive a port to another language and cannot
//! be dropped without breaking the copy. Check for them too:
//!
//! * `inexigible` - the `patch_binary.rs` rename target. Equal length to
//!   `ineligible` so the PE layout survives; the specific misspelling is a free
//!   choice out of a large space and has no reason to be reinvented.
//! * `AG_UNLOCKER_NRPT_V2` - the NRPT rule `Comment` tag in `dns.rs`.
//! * `// [AG_PROXY_HOOK]` / `/*[AG_PATCHED]*/` - legacy Electron hook fences.
//! * The exact four-host NRPT list and its order, plus precedence `46` for
//!   `::ffff:0:0/96`.
//!
//! Use `tools/canary_check.py` to scan anything for all of the above at once.

use sha2::{Digest, Sha256};

// Emitted by build.rs from CANARY_SEED + the crate version:
//     pub const RELEASE_TOKEN: &str = "AGU-...";
include!(concat!(env!("OUT_DIR"), "/canary_gen.rs"));

/// Committed on purpose - see the module docs. build.rs parses this exact line,
/// and tools/canary_check.py parses it too, so the three never drift apart.
/// Read from the source text (not linked) by the build script, hence dead at
/// runtime but load-bearing as committed source.
#[allow(dead_code)]
pub const CANARY_SEED: &str = "7m0DQ4UJVxKM_LU+TU@2^w4<^8rxwn!^";

/// Separator between seed and version salt. Must match build.rs and
/// tools/canary_check.py.
#[allow(dead_code)]
pub const CANARY_SEP: &str = "::";

/// Version-independent canary. Present in every release ever built from this
/// tree, so a copy still matches even when its origin release is unknown.
pub const STATIC_CANARY: &str = "AGU-IBS3Q-ZDXY1-0RMEU";

pub const AUTHOR: &str = "Brent (t.me/nova_txt)";
pub const ORIGIN: &str = "https://github.com/confeden/Antigravity";

/// Copyright management information. Kept on one line so a `strings` dump of the
/// binary shows it intact.
pub const NOTICE: &str = concat!(
    "Antigravity Unlocker. Copyright (c) 2026 Brent (t.me/nova_txt). ",
    "Origin: https://github.com/confeden/Antigravity . ",
    "Licensed under the Antigravity Non-Commercial & Restricted Use License: ",
    "modification, derivative works and public hosting of modified copies are ",
    "not permitted. This notice is copyright management information; removing ",
    "or altering it is assessed separately from the copying itself."
);

/// Keeps the notice and both canaries in the binary even if no code path happens
/// to read them - the menu no longer prints the release token, so this anchor is
/// what guarantees it survives. `#[used]` survives `--release`, LTO and
/// `strip = true`; the reference in `about_banner()` is a second guarantee.
#[used]
static CANARY_ANCHOR: [&str; 4] = [NOTICE, STATIC_CANARY, RELEASE_TOKEN, ORIGIN];

/// Recomputes `RELEASE_TOKEN` for an arbitrary version. build.rs bakes in the
/// value for the version being compiled; this exists so tests can prove the
/// formula, and so a copy that only carries the seed is still attributable.
/// Exercised by the unit tests; not on the runtime path (the token is a baked
/// literal), so it reads as dead code in a plain build.
#[allow(dead_code)]
pub fn token_for(version: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CANARY_SEED.as_bytes());
    hasher.update(CANARY_SEP.as_bytes());
    hasher.update(version.as_bytes());
    let hex = hex::encode(hasher.finalize()).to_uppercase();
    format!("AGU-{}-{}-{}", &hex[0..5], &hex[5..10], &hex[10..15])
}

/// Marker appended to every file this tool rewrites. Recoverable from a patched
/// machine without access to anyone's sources - the strongest evidence of the
/// three, because it needs no cooperation from the suspect.
pub fn file_marker() -> String {
    format!("// UNLOCKED {} {}", STATIC_CANARY, RELEASE_TOKEN)
}

/// Printed by `--about` / `--license`. Also the live reference that pins
/// `NOTICE` and the canaries into the linked binary.
pub fn about_banner() -> String {
    format!(
        "{}\n\nversion: {}\nbuild:   {}\nmark:    {}\nauthor:  {}\norigin:  {}",
        NOTICE,
        env!("CARGO_PKG_VERSION"),
        RELEASE_TOKEN,
        STATIC_CANARY,
        AUTHOR,
        ORIGIN
    )
}

/// Handles `--about` / `--license` / `--version` and exits. Called first thing
/// in `main`, before the licence prompt, so a binary can always be fingerprinted
/// without a key.
pub fn handle_cli_flags() {
    let wants = std::env::args().skip(1).any(|a| {
        matches!(
            a.trim_start_matches('-').to_ascii_lowercase().as_str(),
            "about" | "license" | "licence" | "version" | "v"
        )
    });
    if wants {
        println!("{}", about_banner());
        std::process::exit(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_script_and_runtime_agree() {
        assert_eq!(RELEASE_TOKEN, token_for(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn token_is_version_specific() {
        assert_ne!(token_for("2.5.0"), token_for("2.5.1"));
    }

    #[test]
    fn token_shape_is_stable() {
        let t = token_for("2.5.0");
        assert_eq!(t.len(), 21);
        assert!(t.starts_with("AGU-"));
        assert!(t
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-'));
    }

    #[test]
    fn file_marker_carries_both_canaries() {
        let m = file_marker();
        assert!(m.starts_with("// UNLOCKED"));
        assert!(m.contains(STATIC_CANARY));
        assert!(m.contains(RELEASE_TOKEN));
    }

    #[test]
    fn notice_names_author_licence_and_origin() {
        assert!(NOTICE.contains("Copyright (c) 2026"));
        assert!(NOTICE.contains("t.me/nova_txt"));
        assert!(NOTICE.contains("github.com/confeden/Antigravity"));
        assert!(NOTICE.contains("Restricted Use License"));
    }
}
