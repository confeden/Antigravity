//! Pure CONNECT wire representation shared by independent binary roots.

pub(crate) fn format_request(host: &str, port: u16, encoded_basic: Option<&str>) -> String {
    let mut request = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
    if let Some(value) = encoded_basic {
        request.push_str(&format!("Proxy-Authorization: Basic {value}\r\n"));
    }
    request.push_str("\r\n");
    request
}

pub(crate) struct Request<'a> {
    pub host: String,
    pub port: u16,
    pub version: Option<&'a str>,
    pub extra_token: bool,
    pub strict_shape: bool,
}

pub(crate) fn decode_request(head: &str) -> Option<Request<'_>> {
    let line = head.lines().next()?;
    let mut parts = line.split_whitespace();
    if !parts.next()?.eq_ignore_ascii_case("CONNECT") {
        return None;
    }
    let target = parts.next()?;
    let (host, port) = target.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return None;
    }
    let port = port.parse().ok()?;
    let version = parts.next();
    let extra_token = parts.next().is_some();
    let strict_shape = version.is_some_and(|v| {
        (v == "HTTP/1.0" || v == "HTTP/1.1")
            && !extra_token
            && line == format!("CONNECT {target} {v}")
    });
    Some(Request {
        host: host.to_string(),
        port,
        version,
        extra_token,
        strict_shape,
    })
}

pub(crate) struct ResponseView {
    pub first_line: String,
    pub version: Option<&'static str>,
    pub status: Option<u16>,
}

pub(crate) fn response_view(head: &[u8]) -> ResponseView {
    let first_line = String::from_utf8_lossy(head)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    let raw_line = head.split(|&b| b == b'\n').next().unwrap_or_default();
    let bytes = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
    let status = if raw_line.ends_with(b"\r")
        && head.get(raw_line.len()) == Some(&b'\n')
        && bytes.len() >= 13
        && (&bytes[..9] == b"HTTP/1.0 " || &bytes[..9] == b"HTTP/1.1 ")
        && bytes[9..12].iter().all(u8::is_ascii_digit)
        && bytes[12] == b' '
        && bytes[13..]
            .iter()
            .all(|&b| b == b'\t' || (0x20..=0x7e).contains(&b) || b >= 0x80)
    {
        Some(
            u16::from(bytes[9] - b'0') * 100
                + u16::from(bytes[10] - b'0') * 10
                + u16::from(bytes[11] - b'0'),
        )
    } else {
        None
    };
    let version = if status.is_some() {
        Some(if &bytes[..9] == b"HTTP/1.0 " {
            "HTTP/1.0"
        } else {
            "HTTP/1.1"
        })
    } else {
        None
    };
    ResponseView {
        first_line,
        version,
        status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_wire_format_preserves_native_bytes() {
        assert_eq!(
            format_request("example.com", 443, None),
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
        );
        assert_eq!(format_request("::1", 8443, Some("dXNlcjpwYXNz")), "CONNECT ::1:8443 HTTP/1.1\r\nHost: ::1:8443\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n");
    }

    #[test]
    fn connect_wire_decoder_preserves_legacy_and_exposes_shape() {
        let r = decode_request("connect [[::1]]:443 HTTP/1.1 extra\r\n\r\n").unwrap();
        assert_eq!(
            (r.host.as_str(), r.port, r.version, r.extra_token),
            ("::1", 443, Some("HTTP/1.1"), true)
        );
        assert!(!r.strict_shape);
        let r = decode_request("CONNECT cloudcode-pa.googleapis.com:443 HTTP/1.0\r\n\r\n").unwrap();
        assert!(r.strict_shape);
        assert_eq!(
            decode_request("CONNECT host:443\r\n\r\n").unwrap().version,
            None
        );
        for bad in [
            "",
            "GET host:443 HTTP/1.1",
            "CONNECT :443",
            "CONNECT host:no",
            "CONNECT host:65536",
        ] {
            assert!(decode_request(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn connect_wire_response_keeps_legacy_line_and_strict_status() {
        for version in ["HTTP/1.0", "HTTP/1.1"] {
            let head = format!("{version} 200 OK\r\nHeader: x\r\n\r\n");
            let view = response_view(head.as_bytes());
            assert_eq!(view.first_line, format!("{version} 200 OK"));
            assert_eq!(view.version, Some(version));
            assert_eq!(view.status, Some(200));
        }
        for line in [
            "HTTP/1.1 502 bad 200",
            "garbage 200",
            "HTTP/1.1 2000 OK",
            "HTTP/2 200 OK",
            "HTTP/1.1 20 OK",
        ] {
            let view = response_view(line.as_bytes());
            assert!(view.first_line.contains(" 200") || !line.contains(" 200"));
            assert_ne!(view.status, Some(200), "{line}");
        }
        assert_eq!(
            response_view(b"HTTP/1.1 502 \xff\r\n\r\n").first_line,
            "HTTP/1.1 502 \u{fffd}"
        );
    }

    #[test]
    fn connect_wire_rejects_control_bytes_without_changing_legacy_line() {
        for byte in [0, 1, 31, 127] {
            let head = [b"HTTP/1.1 200 ".as_slice(), &[byte], b"\r\n\r\n"].concat();
            let view = response_view(&head);
            assert_eq!(
                view.first_line,
                String::from_utf8_lossy(&head).lines().next().unwrap()
            );
            assert_eq!(view.status, None, "control byte {byte}");
            assert_eq!(view.version, None);
        }
        for version in ["HTTP/1.0", "HTTP/1.1"] {
            assert_eq!(
                response_view(format!("{version} 200 \r\n\r\n").as_bytes()).status,
                Some(200)
            );
            assert_eq!(
                response_view(format!("{version} 200\r\n\r\n").as_bytes()).status,
                None
            );
        }
        assert_eq!(
            response_view(b"HTTP/1.1 200 \t\xff\r\n\r\n").status,
            Some(200)
        );
        assert_eq!(
            response_view(b"HTTP/1.1 200 OK\nHeader: x\r\n\r\n").status,
            None
        );
    }
}
