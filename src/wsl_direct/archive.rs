//! Strict, in-memory ASAR replacement for the desktop launch-hook owner.
//! The legacy reader uses the same JSON tree and header-size-relative offsets;
//! this boundary additionally validates every extent and SHA256 integrity record.
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;

pub(super) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn invalid(message: impl Into<String>) -> String {
    format!("archive-conflict: {}", message.into())
}

// serde_json::Value alone silently accepts duplicate object keys. Do not let
// two parsers disagree about the member/offset/integrity being reviewed.
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON without duplicate keys")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
                let mut map = Map::new();
                while let Some((key, value)) = a.next_entry::<String, Unique>()? {
                    if map.insert(key, value.0).is_some() {
                        return Err(de::Error::custom("duplicate key"));
                    }
                }
                Ok(Unique(Value::Object(map)))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
                let mut values = Vec::new();
                while let Some(v) = a.next_element::<Unique>()? {
                    values.push(v.0);
                }
                Ok(Unique(Value::Array(values)))
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Unique, E> {
                Ok(Unique(Value::Bool(v)))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Unique, E> {
                Ok(Unique(Value::from(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Unique, E> {
                Ok(Unique(Value::from(v)))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Unique, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| Unique(Value::Number(n)))
                    .ok_or_else(|| de::Error::custom("invalid number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Unique, E> {
                Ok(Unique(Value::String(v.into())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Unique, E> {
                Ok(Unique(Value::String(v)))
            }
            fn visit_none<E: de::Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
        }
        d.deserialize_any(V)
    }
}

pub(super) fn json_unique(bytes: &[u8]) -> Result<Value, String> {
    serde_json::from_slice::<Unique>(bytes)
        .map(|v| v.0)
        .map_err(|e| invalid(format!("JSON: {e}")))
}

#[derive(Debug, Clone)]
pub(super) struct Member {
    pub path: String,
    pub offset: usize,
    pub size: usize,
}

pub(super) struct Archive<'a> {
    pub tree: Value,
    pub data: &'a [u8],
    pub members: Vec<Member>,
}

fn word(input: &[u8], at: usize) -> Result<usize, String> {
    let bytes: [u8; 4] = input
        .get(at..at + 4)
        .ok_or_else(|| invalid("truncated header"))?
        .try_into()
        .unwrap();
    usize::try_from(u32::from_le_bytes(bytes)).map_err(|_| invalid("header integer overflow"))
}

fn component(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name
            .chars()
            .any(|c| c == '/' || c == '\\' || c == ':' || c.is_control())
}

fn path_valid(path: &str) -> bool {
    path.split('/').all(component)
}

fn size(value: &Value, field: &str) -> Result<usize, String> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .and_then(|n| usize::try_from(n).ok())
        .ok_or_else(|| invalid(format!("invalid {field}")))
}

fn hash_valid(hash: &Value) -> bool {
    hash.as_str().is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })
}

fn integrity(node: &Value, payload: Option<&[u8]>) -> Result<(), String> {
    let i = node
        .get("integrity")
        .ok_or_else(|| invalid("missing integrity"))?;
    let obj = i.as_object().ok_or_else(|| invalid("invalid integrity"))?;
    if obj.len() != 4
        || i.get("algorithm").and_then(Value::as_str) != Some("SHA256")
        || !hash_valid(&i["hash"])
    {
        return Err(invalid("unsupported integrity representation"));
    }
    let block_size = size(i, "blockSize")?;
    if block_size == 0 {
        return Err(invalid("zero integrity block size"));
    }
    let blocks = i
        .get("blocks")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("invalid integrity blocks"))?;
    if !blocks.iter().all(hash_valid) {
        return Err(invalid("invalid integrity block hash"));
    }
    let n = size(node, "size")?;
    if blocks.len() != n.div_ceil(block_size) {
        return Err(invalid("integrity block count"));
    }
    if let Some(bytes) = payload {
        if i["hash"].as_str() != Some(digest(bytes).as_str())
            || bytes
                .chunks(block_size)
                .zip(blocks)
                .any(|(b, h)| h.as_str() != Some(digest(b).as_str()))
        {
            return Err(invalid("integrity mismatch"));
        }
    }
    Ok(())
}

fn collect(
    node: &Value,
    path: &str,
    data: &[u8],
    members: &mut Vec<Member>,
    names: &mut BTreeSet<String>,
    links: &mut Vec<String>,
) -> Result<(), String> {
    let obj = node
        .as_object()
        .ok_or_else(|| invalid("non-object entry"))?;
    names.insert(path.into());
    if let Some(files) = node.get("files") {
        if obj.len() != 1 {
            return Err(invalid("ambiguous directory metadata"));
        }
        for (name, child) in files
            .as_object()
            .ok_or_else(|| invalid("invalid files tree"))?
        {
            if !component(name) {
                return Err(invalid("unsafe member name"));
            }
            let child_path = if path.is_empty() {
                name.clone()
            } else {
                format!("{path}/{name}")
            };
            collect(child, &child_path, data, members, names, links)?;
        }
    } else if let Some(link) = node.get("link") {
        let link = link
            .as_str()
            .filter(|p| path_valid(p))
            .ok_or_else(|| invalid("invalid link target"))?;
        if obj.len() != 1 {
            return Err(invalid("ambiguous link metadata"));
        }
        links.push(link.into());
    } else {
        if obj.keys().any(|k| {
            !matches!(
                k.as_str(),
                "size" | "offset" | "integrity" | "unpacked" | "executable"
            )
        }) {
            return Err(invalid("unsupported member metadata"));
        }
        if node
            .get("executable")
            .is_some_and(|v| v.as_bool().is_none())
        {
            return Err(invalid("invalid executable flag"));
        }
        let unpacked = match node.get("unpacked") {
            None => false,
            Some(v) => v
                .as_bool()
                .ok_or_else(|| invalid("invalid unpacked flag"))?,
        };
        let n = size(node, "size")?;
        if unpacked {
            if node.get("offset").is_some() {
                return Err(invalid("unpacked offset ambiguity"));
            }
            integrity(node, None)?;
        } else {
            let text = node
                .get("offset")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("missing packed offset"))?;
            if text.is_empty()
                || !text.bytes().all(|b| b.is_ascii_digit())
                || (text.len() > 1 && text.starts_with('0'))
            {
                return Err(invalid("invalid decimal offset"));
            }
            let offset = text
                .parse::<usize>()
                .map_err(|_| invalid("offset overflow"))?;
            let end = offset
                .checked_add(n)
                .ok_or_else(|| invalid("payload overflow"))?;
            integrity(
                node,
                Some(
                    data.get(offset..end)
                        .ok_or_else(|| invalid("payload out of bounds"))?,
                ),
            )?;
            members.push(Member {
                path: path.into(),
                offset,
                size: n,
            });
        }
    }
    Ok(())
}

pub(super) fn node_mut<'a>(tree: &'a mut Value, path: &str) -> Result<&'a mut Value, String> {
    let mut node = tree;
    for part in path.split('/') {
        node = node
            .get_mut("files")
            .and_then(|f| f.get_mut(part))
            .ok_or_else(|| invalid("missing member"))?;
    }
    Ok(node)
}

impl<'a> Archive<'a> {
    pub fn parse(input: &'a [u8]) -> Result<Self, String> {
        let header_size = word(input, 4)?;
        let json_size = word(input, 12)?;
        let base = header_size
            .checked_add(8)
            .ok_or_else(|| invalid("header overflow"))?;
        let json_end = json_size
            .checked_add(16)
            .ok_or_else(|| invalid("JSON size overflow"))?;
        if word(input, 0)? != 4
            || header_size.checked_sub(4) != Some(word(input, 8)?)
            || header_size % 4 != 0
            || json_end > base
            || base - json_end > 3
        {
            return Err(invalid("unsupported pickle framing"));
        }
        let json = input
            .get(16..json_end)
            .ok_or_else(|| invalid("truncated JSON"))?;
        if input
            .get(json_end..base)
            .ok_or_else(|| invalid("truncated padding"))?
            .iter()
            .any(|b| *b != 0)
        {
            return Err(invalid("nonzero pickle padding"));
        }
        let tree = json_unique(json)?;
        if tree.get("files").is_none() {
            return Err(invalid("missing root files"));
        }
        let data = input.get(base..).ok_or_else(|| invalid("truncated data"))?;
        let mut members = Vec::new();
        let mut names = BTreeSet::new();
        let mut links = Vec::new();
        collect(&tree, "", data, &mut members, &mut names, &mut links)?;
        if links.iter().any(|p| !names.contains(p)) {
            return Err(invalid("dangling link"));
        }
        members.sort_by_key(|m| (m.offset, m.size));
        let mut end = 0;
        for m in &members {
            if m.size != 0 {
                if m.offset < end {
                    return Err(invalid("overlapping payloads"));
                }
                end = m.offset + m.size;
            }
        }
        Ok(Self {
            tree,
            data,
            members,
        })
    }

    pub fn member(&self, path: &str) -> Result<&'a [u8], String> {
        let m = self
            .members
            .iter()
            .find(|m| m.path == path)
            .ok_or_else(|| invalid(format!("missing packed member {path}")))?;
        Ok(&self.data[m.offset..m.offset + m.size])
    }

    pub fn replace(mut self, path: &str, replacement: &[u8]) -> Result<Vec<u8>, String> {
        let target = self
            .members
            .iter()
            .find(|m| m.path == path)
            .ok_or_else(|| invalid("missing replacement member"))?
            .clone();
        if target.size == 0 {
            return Err(invalid("empty producer"));
        }
        let end = target.offset + target.size;
        for m in &self.members {
            let node = node_mut(&mut self.tree, &m.path)?;
            if m.path == path {
                node["size"] = Value::from(
                    u64::try_from(replacement.len()).map_err(|_| invalid("size overflow"))?,
                );
                let block_size = size(&node["integrity"], "blockSize")?;
                node["integrity"]["hash"] = Value::from(digest(replacement));
                node["integrity"]["blocks"] = Value::Array(
                    replacement
                        .chunks(block_size)
                        .map(|b| Value::from(digest(b)))
                        .collect(),
                );
            } else if m.offset >= end {
                let offset = m
                    .offset
                    .checked_sub(target.size)
                    .and_then(|o| o.checked_add(replacement.len()))
                    .ok_or_else(|| invalid("new offset overflow"))?;
                node["offset"] = Value::from(offset.to_string());
            } else if m.size == 0 && m.offset > target.offset {
                return Err(invalid("empty member inside replacement"));
            }
        }
        let mut data = Vec::new();
        data.extend_from_slice(&self.data[..target.offset]);
        data.extend_from_slice(replacement);
        data.extend_from_slice(&self.data[end..]);
        encode(&self.tree, &data)
    }
}

pub(super) fn encode(tree: &Value, data: &[u8]) -> Result<Vec<u8>, String> {
    let json = serde_json::to_vec(tree).map_err(|e| invalid(e.to_string()))?;
    let padding = (4 - json.len() % 4) % 4;
    let header_size = json
        .len()
        .checked_add(padding)
        .and_then(|n| n.checked_add(8))
        .ok_or_else(|| invalid("new header overflow"))?;
    let mut bytes = Vec::new();
    for n in [4, header_size, header_size - 4, json.len()] {
        bytes.extend_from_slice(
            &u32::try_from(n)
                .map_err(|_| invalid("pickle size overflow"))?
                .to_le_bytes(),
        );
    }
    bytes.extend_from_slice(&json);
    bytes.resize(bytes.len() + padding, 0);
    bytes.extend_from_slice(data);
    Ok(bytes)
}
