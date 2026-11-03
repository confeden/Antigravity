"""Offline, pinned IANA snapshot importer. No network, runtime XML, or acceptance."""
import argparse
import datetime
import hashlib
import ipaddress
import json
import pathlib
import re
import struct
import xml.etree.ElementTree as ET

NS = "{http://www.iana.org/assignments}"
SPECS = (
    (4, "iana-ipv4-special-registry", "cf24e11f41b7d42c68debe2d18b97cac815084ec413ebb3b244f704028a16f20"),
    (6, "iana-ipv6-special-registry", "c17f4380ba84fb2160dae82ebfd8bd155a5853cfab624ed3a9fd251638a8be02"),
)
PACKAGE_CHECKSUM = "791930b43c0d5973160d90a8f3894509f2b273430f5c5c73b668636d0287c5c0"


def field(record, name, optional=False):
    nodes = record.findall(NS + name)
    if optional and not nodes:
        return ""
    if len(nodes) != 1:
        raise ValueError(f"missing or duplicated {name}")
    node = nodes[0]
    if any(child.tag != NS + "xref" or list(child) or (child.text or "").strip() for child in node):
        raise ValueError(f"unexpected structure in {name}")
    return "".join(node.itertext()).strip()


def valid_date(value, month=False):
    pattern = r"[0-9]{4}-[0-9]{2}" if month else r"[0-9]{4}-[0-9]{2}-[0-9]{2}"
    if not re.fullmatch(pattern, value):
        raise ValueError("invalid date")
    datetime.date.fromisoformat(value + "-01" if month else value)


def key(record):
    net = record[0]
    return net.version, net.network_address.packed.rjust(16, b"\0"), net.prefixlen


def unique(records):
    by_prefix = {}
    for record in records:
        identity = key(record)
        if identity in by_prefix and by_prefix[identity] != record:
            raise ValueError("conflicting duplicate prefix")
        by_prefix[identity] = record
    return [by_prefix[k] for k in sorted(by_prefix)]


def parse_registry(raw, family, registry_id):
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ValueError("DTD/entity declarations forbidden")
    try:
        root = ET.fromstring(raw.decode("utf-8"))
    except (UnicodeError, ET.ParseError) as error:
        raise ValueError("invalid complete UTF-8 XML") from error
    if root.tag != NS + "registry" or root.get("id") != registry_id or family not in (4, 6):
        raise ValueError("registry identity mismatch")
    updated = field(root, "updated")
    valid_date(updated)
    records = []
    source_rows = root.findall(".//" + NS + "record")
    if not source_rows:
        raise ValueError("empty registry")
    for row in source_rows:
        flags = tuple({"True": 2, "False": 1}.get(field(row, name), 0)
                      for name in ("destination", "forwardable", "global", "reserved"))
        termination = field(row, "termination", optional=True)
        if termination:
            valid_date(termination, month=True)
        for prefix in field(row, "address").split(","):
            try:
                network = ipaddress.ip_network(prefix.strip(), strict=True)
            except ValueError as error:
                raise ValueError("invalid/noncanonical CIDR") from error
            if network.version != family:
                raise ValueError("prefix family mismatch")
            records.append((network, flags, termination))
    return updated, unique(records)


def load_bundled(directory):
    if sorted(p.name for p in directory.glob("*.xml")) != sorted(f"{identity}.xml" for _, identity, _ in SPECS):
        raise ValueError("XML inventory mismatch")
    sources, records = [], []
    for family, identity, expected in SPECS:
        path = directory / f"{identity}.xml"
        if path.is_symlink() or not path.is_file():
            raise ValueError("source is not an ordinary file")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("source checksum mismatch")
        updated, rows = parse_registry(raw, family, identity)
        if updated != "2025-10-09":
            raise ValueError("snapshot updated date mismatch")
        sources.append(dict(family=family, id=identity, updated=updated, raw=raw, sha256=expected,
                            url=f"https://raw.githubusercontent.com/al8n/iprfc/v1.0.0/data/iana/{identity}.xml"))
        records.extend(rows)
    index = json.loads((directory / "ipnet-2.12.2.index.json").read_bytes())
    if index["name"] != "ipnet" or index["vers"] != "2.12.2" or index["yanked"] is not False or index["cksum"] != PACKAGE_CHECKSUM:
        raise ValueError("dependency identity/checksum mismatch")
    if any(not dep["optional"] for dep in index["deps"] if dep["kind"] == "normal"):
        raise ValueError("unexpected mandatory dependency")
    return sorted(sources, key=lambda source: source["url"]), unique(records), bytes.fromhex(PACKAGE_CHECKSUM)


def lp(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return struct.pack(">I", len(value)) + value


def row_bytes(records):
    output = bytearray()
    for network, flags, termination in records:
        output.extend(bytes([network.version, network.prefixlen]))
        output.extend(network.network_address.packed.rjust(16, b"\0"))
        output.extend(bytes(flags))
        output.extend(lp(termination))
    return bytes(output)


def byte_array(value):
    return "[" + ", ".join(f"0x{byte:02x}" for byte in value) + "]"


def render(sources, records, checksum):
    lines = ["// Generated offline by policy_data/generate.py from exact retained snapshots.",
             "// Candidate data only: this file does not supply trusted policy acceptance.",
             "#[rustfmt::skip]", f"const IPNET_CHECKSUM: [u8; 32] = {byte_array(checksum)};",
             "#[rustfmt::skip]", f"const ROW_BYTES_SHA256: [u8; 32] = {byte_array(hashlib.sha256(row_bytes(records)).digest())};",
             "#[rustfmt::skip]", "const SOURCES: &[Source<'static>] = &["]
    for source in sources:
        lines.append(f'    Source {{ family: {source["family"]}, url: "{source["url"]}", updated: "{source["updated"]}", expected_hash: {byte_array(bytes.fromhex(source["sha256"]))}, raw: include_bytes!("{source["id"]}.xml") }},')
    lines.extend(["];", "#[rustfmt::skip]", "const RECORDS: &[Record<'static>] = &["])
    flag_names = ("Unknown", "False", "True")
    for network, flags, termination in records:
        if network.version == 4:
            address = "IpAddr::V4(Ipv4Addr::new(" + ", ".join(map(str, network.network_address.packed)) + "))"
        else:
            groups = struct.unpack(">8H", network.network_address.packed)
            address = "IpAddr::V6(Ipv6Addr::new(" + ", ".join(f"0x{n:x}" for n in groups) + "))"
        flag_values = ", ".join("Flag::" + flag_names[flag] for flag in flags)
        lines.append(f'    Record {{ network: IpNet::new_assert({address}, {network.prefixlen}), flags: [{flag_values}], termination: "{termination}" }},')
    lines.extend(["];", ""])
    return "\n".join(lines).encode("utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--apply", action="store_true", help="write the exact generated records")
    modes.add_argument("--check", action="store_true", help="read-only deterministic regeneration check (default)")
    args = parser.parse_args()
    directory = pathlib.Path(__file__).resolve().parent
    sources, records, checksum = load_bundled(directory)
    generated = render(sources, records, checksum)
    target = directory / "records.rs"
    if args.apply:
        target.write_bytes(generated)
    elif not target.is_file() or target.read_bytes() != generated:
        raise SystemExit("generated records missing or different")
    print(f"Validated {len(sources)} sources / {len(records)} unique prefixes; generated bytes match")


if __name__ == "__main__":
    main()
