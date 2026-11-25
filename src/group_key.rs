use std::fmt;

#[derive(Clone, PartialEq, Eq)]
pub struct GroupKey {
    pub host: String,
    pub port: u16,
    pub tg: u64,
    pub code: String,
    pub issued: u64,
    pub user_key: [u8; 32],
}

impl fmt::Debug for GroupKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // never user_key, host or port — invariant I46
        write!(
            f,
            "GroupKey {{ tg: {}, code: {}, issued: {} }}",
            self.tg, self.code, self.issued
        )
    }
}

#[derive(Debug)]
pub enum KeyError {
    NotAKey,
    Damaged,
    OtherPc,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::NotAKey => write!(f, "Это не ключ доступа — скопируйте ответ бота целиком"),
            KeyError::Damaged => write!(f, "Ключ повреждён"),
            KeyError::OtherPc => write!(
                f,
                "Этот ключ выдан для другого ПК (код {})",
                crate::hwid::pc_code()
            ),
        }
    }
}

// The protocol literals (key prefix, HMAC labels, header scheme) live inside
// obfstr! blocks so the scheme does not read off this binary's strings.

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for (i, &b) in key.iter().enumerate().take(64) {
        ipad[i] ^= b;
        opad[i] ^= b;
    }
    let inner = Sha256::new()
        .chain_update(&ipad)
        .chain_update(data)
        .finalize();
    let outer = Sha256::new()
        .chain_update(&opad)
        .chain_update(inner)
        .finalize();
    let mut res = [0u8; 32];
    res.copy_from_slice(&outer);
    res
}

fn keystream(t: &[u8], nonce: &[u8], n: usize) -> Vec<u8> {
    obfstr::obfstr! { let label = "enc"; }
    let k = hmac_sha256(t, label.as_bytes());
    let mut out = Vec::with_capacity(n + 32);
    let mut i: u32 = 0;
    while out.len() < n {
        let mut msg = nonce.to_vec();
        msg.extend_from_slice(&i.to_be_bytes());
        out.extend_from_slice(&hmac_sha256(&k, &msg));
        i += 1;
    }
    out.truncate(n);
    out
}

fn base64_url_decode(s: &str) -> Result<Vec<u8>, KeyError> {
    let mut out = Vec::with_capacity(s.len());
    let mut val = 0u32;
    let mut bits = 0;
    for c in s.chars() {
        if c == '=' {
            break;
        }
        let b = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '-' => 62,
            '_' => 63,
            _ => return Err(KeyError::NotAKey),
        };
        val = (val << 6) | b;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((val >> bits) as u8);
        }
    }
    Ok(out)
}

pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut v = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        v |= x ^ y;
    }
    v == 0
}

fn unwrap(t: &[u8], token: &str) -> Result<Vec<u8>, KeyError> {
    let token = token.trim();
    obfstr::obfstr! { let prefix = "agk1."; }
    if !token.starts_with(prefix) {
        return Err(KeyError::NotAKey);
    }
    let body = &token[prefix.len()..];

    let raw = base64_url_decode(body)?;

    if raw.len() < 33 {
        return Err(KeyError::Damaged);
    }

    let nonce = &raw[..16];
    let ct = &raw[16..raw.len() - 16];
    let tag = &raw[raw.len() - 16..];

    obfstr::obfstr! { let label = "mac"; }
    let mac_key = hmac_sha256(t, label.as_bytes());
    let mut msg = nonce.to_vec();
    msg.extend_from_slice(ct);
    let expected_tag = &hmac_sha256(&mac_key, &msg)[..16];

    if !ct_eq(expected_tag, tag) {
        return Err(KeyError::Damaged);
    }

    let stream = keystream(t, nonce, ct.len());
    let plain: Vec<u8> = ct.iter().zip(stream.iter()).map(|(&a, &b)| a ^ b).collect();

    Ok(plain)
}

include!(concat!(env!("OUT_DIR"), "/group_gen.rs"));

pub fn parse_key(text: &str) -> Result<GroupKey, KeyError> {
    // Reject non-key strings before checking the baked .group secret so public
    // builds without .group still distinguish invalid input from a damaged key.
    obfstr::obfstr! { let prefix = "agk1."; }
    if !text.trim().starts_with(prefix) {
        return Err(KeyError::NotAKey);
    }
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce as AesNonce};
    let plain_group = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&GROUP_KEY))
        .decrypt(AesNonce::from_slice(&GROUP_NONCE), GROUP_CT)
        .map_err(|_| KeyError::Damaged)?;
    let t_hex = String::from_utf8_lossy(&plain_group).trim().to_string();

    let mut t = [0u8; 32];
    if t_hex.len() != 64 || hex::decode_to_slice(&t_hex, &mut t).is_err() {
        return Err(KeyError::Damaged); // internal error: baked T is invalid
    }
    parse_with(&t, text, crate::hwid::pc_code())
}

/// The parse itself, with the wrap key and this PC's code passed in, so the
/// reference vectors (server/agu2.py) can be checked without the baked secret.
fn parse_with(t: &[u8; 32], text: &str, own_code: &str) -> Result<GroupKey, KeyError> {
    let plain = unwrap(t, text)?;
    let s = String::from_utf8(plain).map_err(|_| KeyError::Damaged)?;
    let f: Vec<&str> = s.split('\n').collect();

    obfstr::obfstr! { let scheme = "AGU2"; }
    if f.len() != 7 || f[0] != scheme {
        return Err(KeyError::Damaged);
    }

    let host = f[1].to_string();
    let port = f[2].parse().map_err(|_| KeyError::Damaged)?;
    let tg = f[3].parse().map_err(|_| KeyError::Damaged)?;
    let code = f[4].to_string();
    let issued = f[5].parse().map_err(|_| KeyError::Damaged)?;

    let mut user_key = [0u8; 32];
    if f[6].len() != 64 || hex::decode_to_slice(f[6], &mut user_key).is_err() {
        return Err(KeyError::Damaged);
    }

    if code != own_code {
        return Err(KeyError::OtherPc);
    }

    Ok(GroupKey {
        host,
        port,
        tg,
        code,
        issued,
        user_key,
    })
}

/// The `Proxy-Authorization` value for one CONNECT (agu2.py `auth_header`).
///
/// Signed with **this PC's** code, never `key.code`: a key text moved to another
/// PC must sign with that PC's code, which the user key was not derived from,
/// so the server refuses it. That is the whole PC binding.
pub fn auth_header(key: &GroupKey, own_code: &str, ts: u64, nonce_hex: &str, host: &str) -> String {
    obfstr::obfstr! { let scheme = "AGU2"; }
    let msg = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}:443",
        scheme, key.tg, own_code, key.issued, ts, nonce_hex, host
    );
    let mac = hex::encode(hmac_sha256(&key.user_key, msg.as_bytes()));
    format!(
        "{} {}.{}.{}.{}.{}.{}",
        scheme, key.tg, own_code, key.issued, ts, nonce_hex, mac
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Inputs and outputs of `python server/agu2.py` (vectors()): M = 0..32, T = 32..64.
    const VEC_TOKEN: &str = "agk1.AAAAAAAAAAAAAAAAAAAAAEy6F3L5D8Dc9LvH6rGHrLK_G4rFhrMhG8w7VNcjIRD4C2Qnp-d8zEXAzX0HXJrBn86fGLYZdrwVLwxqo4mWvomgQVW33guBoeYXqx2R9i4dW6dBkyTlkhlClYB2cyASMeoT7-VvWR9lW3fNTy4CCrvS6j_bQ4HgCMve_WB8uI8AcvxRfiQ";
    const VEC_USER_KEY: &str = "b8d9209f252500b9c0461db1cabd864d65045863efeab29f0d64c17aa97aa4f0";
    const VEC_AUTH: &str = "AGU2 123456789.t146sdha.1760000000.1760000100.00000000000000000000000000000000.a4e1cfeab0eb14afa1839aa2b9243e0595d5a50a5b3276b427433c41516892f5";

    fn vec_t() -> [u8; 32] {
        let mut t = [0u8; 32];
        for (i, b) in t.iter_mut().enumerate() {
            *b = 32 + i as u8;
        }
        t
    }

    #[test]
    fn the_reference_token_parses_to_the_reference_fields() {
        let k = parse_with(&vec_t(), VEC_TOKEN, "t146sdha").expect("parses");
        assert_eq!(k.host, "proxy.example");
        assert_eq!(k.port, 443);
        assert_eq!(k.tg, 123456789);
        assert_eq!(k.code, "t146sdha");
        assert_eq!(k.issued, 1760000000);
        assert_eq!(hex::encode(k.user_key), VEC_USER_KEY);
    }

    #[test]
    fn the_reference_auth_header_matches_byte_for_byte() {
        let k = parse_with(&vec_t(), VEC_TOKEN, "t146sdha").expect("parses");
        let h = auth_header(
            &k,
            "t146sdha",
            1760000100,
            &"00".repeat(16),
            "daily-cloudcode-pa.googleapis.com",
        );
        assert_eq!(h, VEC_AUTH);
    }

    #[test]
    fn a_key_for_another_pc_or_tampered_is_refused() {
        assert!(matches!(
            parse_with(&vec_t(), VEC_TOKEN, "aaaaaaaa"),
            Err(KeyError::OtherPc)
        ));
        let mut bad = VEC_TOKEN.to_string();
        let flip = if &bad[40..41] == "A" { "B" } else { "A" };
        bad.replace_range(40..41, flip);
        assert!(matches!(
            parse_with(&vec_t(), &bad, "t146sdha"),
            Err(KeyError::Damaged)
        ));
        let mut wrong_t = vec_t();
        wrong_t[0] ^= 1;
        assert!(matches!(
            parse_with(&wrong_t, VEC_TOKEN, "t146sdha"),
            Err(KeyError::Damaged)
        ));
    }

    #[test]
    fn debug_never_shows_the_secret_or_the_address() {
        let k = parse_with(&vec_t(), VEC_TOKEN, "t146sdha").expect("parses");
        let d = format!("{:?}", k);
        assert!(
            !d.contains("proxy.example") && !d.contains(VEC_USER_KEY) && !d.contains("443"),
            "{d}"
        );
    }

    #[test]
    fn parse_key_errors() {
        assert!(matches!(parse_key("not_a_key"), Err(KeyError::NotAKey)));
        assert!(matches!(
            parse_key("agk1.invalid"),
            Err(KeyError::Damaged) | Err(KeyError::NotAKey)
        ));
    }
}
