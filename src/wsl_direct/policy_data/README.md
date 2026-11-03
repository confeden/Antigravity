# PublicV1 candidate data and regeneration

This entity contains immutable input data and the narrow offline importer for the WSL direct-route PublicV1 candidate. It installs no accepted policy, runtime updater or network service. The implementation boundary and exact rule/digest specification are in `work-items/active/2026-10-31-wsl-integration/public-address-policy-design.md`; actual producer evidence is in `public-policy-implementation.md` beside that design.

## Retained source identity

The XML files were acquired as data from the exact iprfc v1.0.0 tag on 2026-10-31, transferred by Root, then copied into this previously absent directory after exact inventory, ordinary-file and independent SHA-256 verification. The transferred scratch files were preserved. Each registry identifies its update date as 2025-10-09. All footnotes, unknown fields and terminated rows remain in the complete retained XML.

| Retained file | Bytes | SHA-256 |
| --- | ---: | --- |
| iana-ipv4-special-registry.xml | 13459 | cf24e11f41b7d42c68debe2d18b97cac815084ec413ebb3b244f704028a16f20 |
| iana-ipv6-special-registry.xml | 13431 | c17f4380ba84fb2160dae82ebfd8bd155a5853cfab624ed3a9fd251638a8be02 |

Actual acquisition URLs, which the canonical digest records:

- https://raw.githubusercontent.com/al8n/iprfc/v1.0.0/data/iana/iana-ipv4-special-registry.xml
- https://raw.githubusercontent.com/al8n/iprfc/v1.0.0/data/iana/iana-ipv6-special-registry.xml

Original registry URLs identified by the upstream provenance:

- https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xml
- https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xml

`upstream-README.md` retains the complete tagged source provenance, including its hashes and upstream workflow description, as evidence. Its commands describe the upstream project and are not this repository's regeneration entry points. `policy-data-acquisition.md` records the separate official HTML row/flag comparison and its limits. Exact byte identity with IANA-hosted XML remains unverified. These retained bytes are a candidate input, not evidence of current official-source acceptance or practical routability.

## License and component provenance

IANA's complete licensing statement, retrieved from https://www.iana.org/help/licensing-terms on 2026-10-31, is retained as `IANA-LICENSING.html`. It identifies protocol-registry factual data and applies the CC0 1.0 dedication with its limitations. The complete dedication was retrieved from https://creativecommons.org/publicdomain/zero/1.0/legalcode.txt and retained as `CC0-1.0.txt`. Those files are inert provenance text; no HTML or downloaded command is executed. No upstream iprfc implementation or updater script was copied or executed.

The exact ipnet 2.12.2 Cargo index entry is retained as `ipnet-2.12.2.index.json`, acquired from https://index.crates.io/ip/ne/ipnet. Its published package archive at https://static.crates.io/crates/ipnet/ipnet-2.12.2.crate has SHA-256 `791930b43c0d5973160d90a8f3894509f2b273430f5c5c73b668636d0287c5c0`, matching that entry. The non-yanked package declares no build script and no required normal dependencies when optional/default features are disabled. Full `IPNET-LICENSE-MIT` and `IPNET-LICENSE-APACHE` notices were copied from that verified archive. ipnet source remains a Cargo dependency rather than vendored classifier logic. Dependency provenance and license text do not supply independent security acceptance.

## Offline workflow and integrity

Run from the repository root with Python standard library only:

```text
python src/wsl_direct/policy_data/test_generate.py
python src/wsl_direct/policy_data/generate.py --check
```

The default generator invocation is also read-only. `--apply` explicitly regenerates only `records.rs` from the pinned inputs; use it only within an admitted reviewed policy update. There is no network or wall-clock dependency. The importer rejects source hash/identity/date/inventory mismatch, declarations that could introduce XML entities, malformed or incomplete XML, missing/duplicated policy fields, invalid/noncanonical prefixes, wrong address family, invalid termination dates and conflicting duplicate prefixes. Identical duplicates deduplicate. Known booleans retain their exact typed values; blank, N/A or future tokens remain Unknown rather than falling back to another row. Comma-split source rows and all overlaps are retained.

Generated records sort by family, network octets and prefix length. Their canonical byte hash is embedded alongside the actual source hashes and actual component checksum. The runtime owner `src/wsl_direct/public_policy.rs` embeds the complete source bytes and immutable records, validates their hashes/structure, and uses ipnet's longest-prefix membership without runtime XML parsing or per-classification allocation. Its candidate digest also binds the exact adapter source bytes, so even a source/comment/test change changes that digest. Neither the source files, generated output, matching peer digest nor importer can install a trusted receiving binding. Missing/corrupt/unaccepted policy remains unavailable; authentication/transport integration is separate.

## Terms and Abbreviations

IANA: Internet Assigned Numbers Authority. WSL: Windows Subsystem for Linux. XML: Extensible Markup Language. SHA-256: 256-bit cryptographic hash. CC0: Creative Commons public-domain dedication. CIDR: network-prefix notation. N/A: no asserted boolean value. LP: unsigned 32-bit big-endian byte-length prefix.
