//! Target resolution through the tunnel: the `PlainResolver` `leas-dns` calls
//! when a `WireGuard` profile carries `dns` servers.
//!
//! Only the wire is here — a plain UDP query to `ip:53` over the stack's own
//! UDP flow, one A/AAAA answer set with CNAME following. Policy (liveness, the
//! local fallback, scope reporting) stays in `leas-dns`.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::time::Duration;

use super::WgStack;

/// One DNS exchange's budget, including the tunnel's own round trip.
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);
/// CNAME chains longer than this are treated as a loop.
const MAX_CNAME_DEPTH: usize = 4;

const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

/// A resolver that sends its queries through the `WireGuard` stack.
pub struct TunnelDns {
    /// Weak on purpose: the pool's idle sweep reads the stack's strong count
    /// to decide "no flow holds this device", and a resolver is not a flow.
    stack: Weak<WgStack>,
    servers: Vec<IpAddr>,
    timeout: Duration,
}

impl std::fmt::Debug for TunnelDns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelDns")
            .field("stack", &"WgStack")
            .field("servers", &self.servers)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl TunnelDns {
    /// Build a resolver over `servers` (the profile's `dns` list).
    #[must_use]
    pub fn new(stack: &Arc<WgStack>, servers: Vec<IpAddr>) -> Self {
        Self {
            stack: Arc::downgrade(stack),
            servers,
            timeout: QUERY_TIMEOUT,
        }
    }

    /// Resolve `name` to A (and optionally AAAA) addresses.
    ///
    /// # Errors
    ///
    /// Fails when no server answers, the answer is a DNS error, or the name has
    /// no record of the requested type.
    pub async fn resolve(&self, name: &str, ipv6: bool) -> anyhow::Result<Vec<IpAddr>> {
        let mut current = name.trim_end_matches('.').to_string();
        for _ in 0..MAX_CNAME_DEPTH {
            let ipv4 = self.query(&current, TYPE_A).await?;
            let mut out = ipv4.0;
            if let Some(target) = ipv4.1 {
                current = target;
                continue;
            }
            if ipv6 && let Ok((mut v6, _)) = self.query(&current, TYPE_AAAA).await {
                out.append(&mut v6);
            }
            if out.is_empty() {
                anyhow::bail!("{name}: no address record through the tunnel");
            }
            return Ok(out);
        }
        anyhow::bail!("{name}: CNAME chain longer than {MAX_CNAME_DEPTH}")
    }

    async fn query(&self, name: &str, qtype: u16) -> anyhow::Result<(Vec<IpAddr>, Option<String>)> {
        let last_error = match self.send_one(name, qtype).await {
            Ok(answer) => return Ok(answer),
            Err(error) => error,
        };
        anyhow::bail!("{name}: tunnel DNS failed: {last_error}")
    }

    async fn send_one(
        &self,
        name: &str,
        qtype: u16,
    ) -> anyhow::Result<(Vec<IpAddr>, Option<String>)> {
        let Some(stack) = self.stack.upgrade() else {
            anyhow::bail!("{name}: the wireguard device is gone");
        };
        let mut last: Option<anyhow::Error> = None;
        for server in &self.servers {
            let flow = match stack.open_udp().await {
                Ok(flow) => flow,
                Err(error) => return Err(error.into()),
            };
            let id = query_id();
            let query = encode_query(id, name, qtype)?;
            let destination = SocketAddr::new(*server, 53);
            if let Err(error) = flow.try_send_to(destination, &query) {
                last = Some(error.into());
                continue;
            }
            let mut flow = flow;
            let answer = tokio::time::timeout(self.timeout, flow.recv_from()).await;
            match answer {
                Ok(Some((_, response))) => match parse_response(id, &response, qtype) {
                    Ok(answer) => return Ok(answer),
                    Err(error) => last = Some(error),
                },
                Ok(None) => last = Some(anyhow::anyhow!("the stack closed the UDP socket")),
                Err(_) => last = Some(anyhow::anyhow!("{server}: timed out")),
            }
        }
        Err(last.unwrap_or_else(|| anyhow::anyhow!("no tunnel DNS server configured")))
    }
}

impl leas_dns::PlainResolver for TunnelDns {
    fn lookup<'a>(
        &'a self,
        hostname: &'a str,
        ipv6: bool,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Vec<IpAddr>>> + Send + 'a>> {
        Box::pin(self.resolve(hostname, ipv6))
    }
}

fn query_id() -> u16 {
    let mut bytes = [0u8; 2];
    crate::rand::fill_nonsecret(&mut bytes);
    u16::from_le_bytes(bytes)
}

/// A recursive query for `qtype` (`RD` set, one question).
pub fn encode_query(id: u16, name: &str, qtype: u16) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(32 + name.len());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    let mut labels = 0usize;
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            anyhow::bail!("{name}: invalid DNS label");
        }
        labels += 1;
        out.push(u8::try_from(label.len()).expect("label length checked"));
        out.extend_from_slice(label.as_bytes());
    }
    if labels == 0 || out.len() > 255 {
        anyhow::bail!("{name}: DNS name too long");
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(out)
}

/// Parse a response: the addresses of `qtype` plus the first CNAME target (the
/// caller re-queries it).
pub fn parse_response(
    id: u16,
    message: &[u8],
    qtype: u16,
) -> anyhow::Result<(Vec<IpAddr>, Option<String>)> {
    if message.len() < 12 {
        return Err(anyhow::anyhow!("short DNS response"));
    }
    if u16::from_be_bytes([message[0], message[1]]) != id {
        return Err(anyhow::anyhow!("DNS response id mismatch"));
    }
    let flags = u16::from_be_bytes([message[2], message[3]]);
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return Err(anyhow::anyhow!("DNS error rcode {rcode}"));
    }
    let questions = u16::from_be_bytes([message[4], message[5]]) as usize;
    let answers = u16::from_be_bytes([message[6], message[7]]) as usize;
    let mut position = 12;
    for _ in 0..questions {
        position = skip_name(message, position)?;
        position = position.checked_add(4).ok_or_else(short)?;
    }
    let mut addresses = Vec::new();
    let mut cname = None;
    for _ in 0..answers {
        position = skip_name(message, position)?;
        let body = message.get(position..position + 10).ok_or_else(short)?;
        let rtype = u16::from_be_bytes([body[0], body[1]]);
        let rdlength = u16::from_be_bytes([body[8], body[9]]) as usize;
        position += 10;
        let rdata = message
            .get(position..position + rdlength)
            .ok_or_else(short)?;
        if rtype == qtype {
            match (rtype, rdlength) {
                (TYPE_A, 4) => addresses.push(IpAddr::V4(Ipv4Addr::new(
                    rdata[0], rdata[1], rdata[2], rdata[3],
                ))),
                (TYPE_AAAA, 16) => {
                    let octets: [u8; 16] = rdata.try_into().expect("length checked");
                    addresses.push(IpAddr::V6(Ipv6Addr::from(octets)));
                }
                _ => {}
            }
        } else if rtype == TYPE_CNAME && cname.is_none() {
            cname = read_name(message, position).ok();
        }
        position += rdlength;
    }
    Ok((addresses, cname))
}

fn short() -> anyhow::Error {
    anyhow::anyhow!("truncated DNS response")
}

/// Skip a (possibly compressed) name, returning the offset just past it.
fn skip_name(message: &[u8], mut position: usize) -> anyhow::Result<usize> {
    loop {
        let length = *message.get(position).ok_or_else(short)?;
        if length == 0 {
            return Ok(position + 1);
        }
        if length & 0xC0 == 0xC0 {
            // A compression pointer is two bytes and ends the name.
            return Ok(position + 2);
        }
        position = position
            .checked_add(1 + usize::from(length))
            .ok_or_else(short)?;
        if position > message.len() {
            return Err(short());
        }
    }
}

/// Read a name at `position`, following compression pointers inside `message`.
fn read_name(message: &[u8], mut position: usize) -> anyhow::Result<String> {
    let mut out = String::new();
    let mut hops = 0;
    loop {
        let length = *message.get(position).ok_or_else(short)?;
        if length == 0 {
            return Ok(out.trim_end_matches('.').to_string());
        }
        if length & 0xC0 == 0xC0 {
            let second = *message.get(position + 1).ok_or_else(short)?;
            position = (usize::from(length & 0x3F) << 8) | usize::from(second);
            hops += 1;
            if hops > 8 {
                anyhow::bail!("DNS name compression loop");
            }
            continue;
        }
        let label = message
            .get(position + 1..position + 1 + usize::from(length))
            .ok_or_else(short)?;
        out.push_str(std::str::from_utf8(label).map_err(|_| anyhow::anyhow!("non-UTF-8 label"))?);
        out.push('.');
        position += 1 + usize::from(length);
    }
}

#[cfg(test)]
mod tests {
    use super::{TYPE_A, encode_query, parse_response};
    use std::net::{IpAddr, Ipv4Addr};

    /// A response for `example.com A 192.0.2.1`, built by hand.
    fn answer(id: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&0x8180u16.to_be_bytes()); // QR + RD + RA
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        // question: example.com A IN
        out.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
        out.extend_from_slice(&[3, b'c', b'o', b'm', 0]);
        out.extend_from_slice(&TYPE_A.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        // answer: pointer to the question name, A, IN, TTL, 4 bytes
        out.extend_from_slice(&[0xC0, 12]);
        out.extend_from_slice(&TYPE_A.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&60u32.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&[192, 0, 2, 1]);
        out
    }

    #[test]
    fn a_query_round_trips_through_our_own_parser() {
        let query = encode_query(7, "example.com", TYPE_A).unwrap();
        assert_eq!(&query[..2], &7u16.to_be_bytes());
        assert_eq!(&query[2..4], &0x0100u16.to_be_bytes());
        assert_eq!(query[12], 7, "first label length");
        assert_eq!(
            u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]]),
            TYPE_A
        );
    }

    #[test]
    fn an_answer_yields_the_address() {
        let (ips, cname) = parse_response(9, &answer(9), TYPE_A).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))]);
        assert!(cname.is_none());
    }

    #[test]
    fn a_mismatched_id_or_error_rcode_is_refused() {
        assert!(
            parse_response(8, &answer(9), TYPE_A).is_err(),
            "id mismatch"
        );
        let mut refused = answer(9);
        refused[3] = 0x03; // SERVFAIL
        assert!(parse_response(9, &refused, TYPE_A).is_err(), "rcode");
    }

    #[test]
    fn a_truncated_answer_is_refused() {
        let mut message = answer(9);
        message.truncate(message.len() - 2);
        assert!(parse_response(9, &message, TYPE_A).is_err());
    }

    #[test]
    fn a_bad_label_is_refused() {
        assert!(encode_query(1, "", TYPE_A).is_err());
        assert!(encode_query(1, "a..b", TYPE_A).is_err());
        assert!(encode_query(1, &"x".repeat(64), TYPE_A).is_err());
    }
}
