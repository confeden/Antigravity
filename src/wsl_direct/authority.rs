//! Pure CONNECT authority syntax and classification; no destination authorization.

use url::Host;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Class {
    Gate,
    NonGate,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Authority {
    pub host: Host<String>,
    pub port: u16,
    pub class: Class,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AuthorityError {
    InvalidRequest,
    InvalidAuthority,
    HeaderBudgetExceeded,
    TrailingInput,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HeaderPrefix {
    Partial,
    Complete {
        authority: Authority,
        consumed_header_bytes: usize,
    },
}

/// The budget counts header bytes only; bytes after the first delimiter remain caller-owned.
pub(crate) fn inspect_prefix(input: &[u8], budget: usize) -> Result<HeaderPrefix, AuthorityError> {
    if budget == 0 {
        return Err(AuthorityError::HeaderBudgetExceeded);
    }
    let consumed = match input.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(i) => i + 4,
        None if input.len() >= budget => return Err(AuthorityError::HeaderBudgetExceeded),
        None => return Ok(HeaderPrefix::Partial),
    };
    if consumed > budget {
        return Err(AuthorityError::HeaderBudgetExceeded);
    }
    let header = &input[..consumed];
    for (i, &b) in header.iter().enumerate() {
        if (b == b'\r' && header.get(i + 1) != Some(&b'\n'))
            || (b == b'\n' && (i == 0 || header[i - 1] != b'\r'))
        {
            return Err(AuthorityError::InvalidRequest);
        }
    }
    let line_end = header
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or(AuthorityError::InvalidRequest)?;
    let line =
        std::str::from_utf8(&header[..line_end]).map_err(|_| AuthorityError::InvalidRequest)?;
    let request =
        crate::connect_wire::decode_request(line).ok_or(AuthorityError::InvalidRequest)?;
    if !request.strict_shape {
        return Err(AuthorityError::InvalidRequest);
    }
    let fields = &header[line_end + 2..];
    let field_count = fields
        .windows(2)
        .filter(|w| *w == b"\r\n")
        .count()
        .saturating_sub(1);
    let mut parsed = vec![httparse::EMPTY_HEADER; field_count];
    match httparse::parse_headers(fields, &mut parsed) {
        Ok(httparse::Status::Complete((n, _))) if n == fields.len() => {}
        _ => return Err(AuthorityError::InvalidRequest),
    }
    let target = line
        .strip_prefix("CONNECT ")
        .and_then(|s| s.split_once(' ').map(|(target, _)| target))
        .ok_or(AuthorityError::InvalidRequest)?;
    let authority = parse_authority(target)?;
    Ok(HeaderPrefix::Complete {
        authority,
        consumed_header_bytes: consumed,
    })
}

/// Complete-only boundary rejects, rather than discards, every suffix byte.
pub(crate) fn parse_connect(input: &[u8], budget: usize) -> Result<Authority, AuthorityError> {
    match inspect_prefix(input, budget)? {
        HeaderPrefix::Partial => Err(AuthorityError::InvalidRequest),
        HeaderPrefix::Complete {
            authority,
            consumed_header_bytes,
        } if consumed_header_bytes == input.len() => Ok(authority),
        HeaderPrefix::Complete { .. } => Err(AuthorityError::TrailingInput),
    }
}

fn parse_authority(target: &str) -> Result<Authority, AuthorityError> {
    if target.chars().any(|c| {
        c.is_control() || c.is_whitespace() || matches!(c, '@' | '/' | '\\' | '?' | '#' | '%')
    }) {
        return Err(AuthorityError::InvalidAuthority);
    }
    let (host_text, port_text) = target
        .rsplit_once(':')
        .ok_or(AuthorityError::InvalidAuthority)?;
    if host_text.is_empty()
        || port_text.is_empty()
        || !port_text.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(AuthorityError::InvalidAuthority);
    }
    let port = port_text
        .parse::<u16>()
        .ok()
        .filter(|p| *p != 0)
        .ok_or(AuthorityError::InvalidAuthority)?;
    let bracketed = host_text.starts_with('[');
    if bracketed {
        if !host_text.ends_with(']') || host_text[1..host_text.len() - 1].contains(['[', ']']) {
            return Err(AuthorityError::InvalidAuthority);
        }
    } else if host_text.contains(['[', ']', ':']) {
        return Err(AuthorityError::InvalidAuthority);
    }
    let host = match Host::parse(host_text).map_err(|_| AuthorityError::InvalidAuthority)? {
        Host::Domain(domain) if !bracketed => {
            let domain = domain.strip_suffix('.').unwrap_or(&domain);
            if domain.is_empty()
                || domain.len() > 253
                || domain
                    .split('.')
                    .any(|label| label.is_empty() || label.len() > 63)
            {
                return Err(AuthorityError::InvalidAuthority);
            }
            Host::Domain(domain.to_string())
        }
        Host::Ipv4(ip) if !bracketed => Host::Ipv4(ip),
        Host::Ipv6(ip) if bracketed => Host::Ipv6(ip),
        _ => return Err(AuthorityError::InvalidAuthority),
    };
    let class = if port == 443
        && matches!(&host, Host::Domain(name) if crate::gate_hosts::is_gate_host(name))
    {
        Class::Gate
    } else {
        Class::NonGate
    };
    Ok(Authority { host, port, class })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse_connect(input: &str) -> Result<Authority, AuthorityError> {
        super::parse_connect(input.as_bytes(), input.len().max(1))
    }

    #[test]
    fn direct_authority_canonicalizes_and_classifies() {
        assert_eq!(
            parse_connect("CONNECT CloudCode-PA.GoogleAPIs.com.:443 HTTP/1.1\r\n\r\n").unwrap(),
            Authority {
                host: Host::Domain("cloudcode-pa.googleapis.com".into()),
                port: 443,
                class: Class::Gate
            }
        );
        assert_eq!(
            parse_connect("CONNECT bücher.example:8443 HTTP/1.0\r\n\r\n").unwrap(),
            Authority {
                host: Host::Domain("xn--bcher-kva.example".into()),
                port: 8443,
                class: Class::NonGate
            }
        );
        assert_eq!(
            parse_connect("CONNECT 2130706433:80 HTTP/1.1\r\n\r\n").unwrap(),
            Authority {
                host: Host::Ipv4("127.0.0.1".parse().unwrap()),
                port: 80,
                class: Class::NonGate
            }
        );
        assert_eq!(
            parse_connect("CONNECT [2001:db8::1]:65535 HTTP/1.1\r\n\r\n").unwrap(),
            Authority {
                host: Host::Ipv6("2001:db8::1".parse().unwrap()),
                port: 65535,
                class: Class::NonGate
            }
        );
        assert_eq!(
            parse_connect("CONNECT cloudcode-pa.googleapis.com:80 HTTP/1.1\r\n\r\n")
                .unwrap()
                .class,
            Class::NonGate
        );
        assert_eq!(
            parse_connect("CONNECT DAILY-CLOUDCODE-PA.GOOGLEAPIS.COM:443 HTTP/1.1\r\n\r\n")
                .unwrap()
                .class,
            Class::Gate
        );
        assert_eq!(
            parse_connect("CONNECT storage.googleapis.com:443 HTTP/1.1\r\n\r\n")
                .unwrap()
                .class,
            Class::NonGate
        );
    }

    #[test]
    fn direct_authority_rejects_ambiguous_or_malformed_inputs() {
        for target in [
            "",
            "host",
            ":443",
            "host:",
            "host:0",
            "host:65536",
            "host:+443",
            "host: 443",
            "a..b:443",
            "host..:443",
            "user@host:443",
            "host/path:443",
            "host\\path:443",
            "host?x:443",
            "host#x:443",
            "host%2ecom:443",
            "[fe80::1%eth0]:443",
            "[::1:443",
            "[[::1]]:443",
            "::1:443",
            "[example.com]:443",
        ] {
            let head = format!("CONNECT {target} HTTP/1.1\r\n\r\n");
            assert!(parse_connect(&head).is_err(), "{target}");
        }
        for head in [
            "CONNECT host:443 HTTP/2\r\n\r\n",
            "connect host:443 HTTP/1.1\r\n\r\n",
            "CONNECT host:443 HTTP/1.1 extra\r\n\r\n",
            "CONNECT host:443 HTTP/1.1\n\n",
            "CONNECT host:443 HTTP/1.1\r\n",
        ] {
            assert!(parse_connect(head).is_err(), "{head:?}");
        }
        let overlong = format!("CONNECT {}.example:443 HTTP/1.1\r\n\r\n", "a".repeat(64));
        assert!(parse_connect(&overlong).is_err());
        let domain_too_long = format!(
            "CONNECT {}.{}.{}.{}.a:443 HTTP/1.1\r\n\r\n",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(63)
        );
        assert!(parse_connect(&domain_too_long).is_err());
    }

    #[test]
    fn direct_header_rejects_malformed_and_complete_suffix() {
        let bad: &[&[u8]] = &[
            b"CONNECT example.com:443 HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\n\r\n",
            b"CONNECT example.com:443 HTTP/1.1\r\nBad\0Field: x\r\n\r\n",
            b"CONNECT example.com:443 HTTP/1.1\r\nX: \0\r\n\r\n",
            b"CONNECT example.com:443 HTTP/1.1\r\nX: \x7f\r\n\r\n",
            b"CONNECT example.com:443 HTTP/1.1\r\nX : x\r\n\r\n",
            b"CONNECT example.com:443 HTTP/1.1\r\n: x\r\n\r\n",
            b"CONNECT example.com:443 HTTP/1.1\r\nX\r\n\r\n",
            b"CONNECT example.com:443 HTTP/1.1\r\nX: x\r\n continuation\r\n\r\n",
            b"CONNECT example.com:443 HTTP/1.1\r\nX: x\nY: y\r\n\r\n",
            b"CONNECT example.com:443 HTTP/1.1\r\nX: x\rY: y\r\n\r\n",
        ];
        for input in bad {
            assert!(
                super::parse_connect(input, input.len()).is_err(),
                "{input:?}"
            );
        }
        assert_eq!(
            super::parse_connect(b"CONNECT x:443 HTTP/1.1\r\nX: x\r\n", 64),
            Err(AuthorityError::InvalidRequest)
        );
    }

    #[test]
    fn direct_header_prefix_preserves_binary_tail_and_budget() {
        let header = b"CONNECT example.com:8443 HTTP/1.1\r\nHost: example.com\r\nEmpty:\r\nX-Test:\t\xff\x80\r\n\r\n";
        let tail: Vec<u8> = (0..=255).chain([13, 10, 13, 10]).collect();
        let input = [header.as_slice(), tail.as_slice()].concat();
        for split in 0..header.len() {
            assert_eq!(
                inspect_prefix(&input[..split], header.len()).unwrap(),
                HeaderPrefix::Partial
            );
        }
        match inspect_prefix(&input, header.len()).unwrap() {
            HeaderPrefix::Complete {
                authority,
                consumed_header_bytes,
            } => {
                assert_eq!(authority.port, 8443);
                assert_eq!(consumed_header_bytes, header.len());
                assert_eq!(&input[consumed_header_bytes..], tail.as_slice());
            }
            HeaderPrefix::Partial => panic!("complete header reported partial"),
        }
        assert_eq!(
            super::parse_connect(&input, header.len()),
            Err(AuthorityError::TrailingInput)
        );
        assert_eq!(
            inspect_prefix(header, header.len() - 1),
            Err(AuthorityError::HeaderBudgetExceeded)
        );
        assert_eq!(
            inspect_prefix(&header[..header.len() - 1], header.len() - 1),
            Err(AuthorityError::HeaderBudgetExceeded)
        );
        assert_eq!(
            inspect_prefix(b"", 0),
            Err(AuthorityError::HeaderBudgetExceeded)
        );
    }
}
