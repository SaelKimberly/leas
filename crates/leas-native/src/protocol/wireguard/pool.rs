//! One device per profile identity, shared by every flow of that profile.
//!
//! A `WireGuard` peer keeps **one session per key**: two devices with the same
//! key would keep replacing each other's handshake (`ZeroNet/wg_stack.rs` says
//! the same). The pool therefore keys on the wire-visible identity and hands
//! back the same `Arc<WgStack>` for every SOCKS leg.
//!
//! Lifetime: an entry with no live flow (its `Arc` is held only by the pool)
//! and no use for [`IDLE_TEARDOWN`] is dropped, which aborts its driver task
//! and closes the UDP socket.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use leas_proto::proto_spec::{ProtocolConfig, WireguardConfig};
use smoltcp::wire::{IpCidr, Ipv4Cidr, Ipv6Cidr};
use tokio::net::UdpSocket;

use super::core::device::Tunnel;
use super::keys::{KeyError, decode_preshared, decode_private, decode_public};
use super::stack::{StackConfig, TunnelDns, WgLink, WgStack};
use crate::BoxStream;
use crate::addr::{Host, TargetAddr};
use crate::error::NativeError;
use crate::error::timeouts;
use blake2::Digest as _;

/// A device with no flow and no use for this long is dropped.
const IDLE_TEARDOWN: Duration = Duration::from_secs(300);
/// The default inner MTU when the config names none (`inject_singbox`'s value).
const DEFAULT_MTU: usize = 1420;
/// The tunnel MTU floor (IPv6 minimum, what WARP paths survive).
const MIN_MTU: usize = 1280;

/// The wire identity that makes two profiles one device.
#[derive(Clone, PartialEq, Eq, Hash)]
struct WgKey {
    server: SocketAddr,
    peer: [u8; 32],
    /// BLAKE2s-256 of the private key: the pool never stores the key itself.
    secret_hash: [u8; 32],
    psk_hash: [u8; 32],
    address: String,
    mtu: usize,
    reserved: [u8; 3],
    /// The resolver configuration is part of the identity: the device owns the
    /// `leas-dns` resolver built from the FIRST config that created it.
    dns: String,
}

struct WgDevice {
    stack: Arc<WgStack>,
    /// `None` when the profile carries no usable `dns` (local resolution).
    dns: Option<Arc<leas_dns::DnsResolver>>,
    families: (bool, bool),
    last_used: AtomicU64,
}

static POOL: LazyLock<Mutex<HashMap<WgKey, Arc<WgDevice>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Dial `target` through the profile's `WireGuard` device.
pub async fn open(
    proxy: &crate::inbound::outbound::ProxyOutbound,
    target: &TargetAddr,
) -> Result<BoxStream, NativeError> {
    let ProtocolConfig::Wireguard(config) = &proxy.protocol else {
        return Err(NativeError::Config(
            "wireguard pool opened for a non-wireguard row".into(),
        ));
    };
    let device = device_for(proxy, config).await?;
    let remote = resolve(&device, target).await?;
    let flow = device
        .stack
        .connect_tcp(remote)
        .await
        .map_err(|error| NativeError::Dial(format!("wireguard tcp to {remote}: {error}")))?;
    Ok(Box::new(flow))
}

/// Open one UDP association through the profile's device (SOCKS5 UDP
/// ASSOCIATE). Each datagram is a full inner IP/UDP packet.
pub async fn open_udp(
    params: &crate::context::NativeConnectParams,
) -> Result<super::stack::WgUdpConn, NativeError> {
    let ProtocolConfig::Wireguard(config) = params.protocol.clone() else {
        return Err(NativeError::Config(
            "wireguard udp opened for a non-wireguard row".into(),
        ));
    };
    let proxy = crate::inbound::outbound::ProxyOutbound {
        protocol: ProtocolConfig::Wireguard(config.clone()),
        kind: leas_proto::proto_spec::ProtocolKind::WireGuard,
        server: params.server.clone(),
        resolved_ip: params.resolved_ip,
    };
    let device = device_for(&proxy, &config).await?;
    let flow = device
        .stack
        .open_udp()
        .await
        .map_err(|error| NativeError::Dial(format!("wireguard udp flow: {error}")))?;
    Ok(crate::protocol::wireguard::stack::WgUdpConn::new(
        flow,
        device.dns.clone(),
    ))
}

async fn device_for(
    proxy: &crate::inbound::outbound::ProxyOutbound,
    config: &WireguardConfig,
) -> Result<Arc<WgDevice>, NativeError> {
    let server = server_addr(proxy).await?;
    let key = pool_key(server, config)?;
    sweep();
    let existing = {
        let mut pool = POOL.lock().expect("wireguard pool lock");
        match pool.get(&key) {
            Some(device) if device.stack.handle.cmd.is_closed() => {
                // The driver exited (fatal handshake / link error): keeping it
                // would fail every later connection with "wireguard stack is
                // closed". Check and removal share the lock, so a device
                // another caller installed in between is not evicted.
                pool.remove(&key);
                None
            }
            Some(device) => Some(Arc::clone(device)),
            None => None,
        }
    };
    if let Some(device) = existing {
        device.last_used.store(unix_secs(), Ordering::Relaxed);
        return Ok(device);
    }
    let device = Arc::new(build(server, config).await?);
    let entry = {
        let mut pool = POOL.lock().expect("wireguard pool lock");
        pool.entry(key)
            .or_insert_with(|| Arc::clone(&device))
            .clone()
    };
    entry.last_used.store(unix_secs(), Ordering::Relaxed);
    Ok(entry)
}

/// Drop every device no flow holds and nobody used recently.
fn sweep() {
    let now = unix_secs();
    let mut pool = POOL.lock().expect("wireguard pool lock");
    pool.retain(|_, device| {
        let idle = now.saturating_sub(device.last_used.load(Ordering::Relaxed));
        // One strong reference means only the pool (a live flow's guard adds
        // one, and the device's own field is inside the counted value).
        Arc::strong_count(&device.stack) > 1 || idle < IDLE_TEARDOWN.as_secs()
    });
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

async fn server_addr(
    proxy: &crate::inbound::outbound::ProxyOutbound,
) -> Result<SocketAddr, NativeError> {
    if let Some(ip) = proxy.resolved_ip {
        return Ok(ip);
    }
    let host = proxy.server.host.as_str().to_string();
    let port = proxy.server.port;
    let addrs = tokio::time::timeout(
        timeouts::DIAL,
        tokio::net::lookup_host((host.as_str(), port)),
    )
    .await
    .map_err(|_| NativeError::Timeout {
        step: "wireguard server dns",
        limit: timeouts::DIAL,
    })?
    .map_err(|error| NativeError::Dial(format!("{host}: {error}")))?;
    addrs
        .into_iter()
        .next()
        .ok_or_else(|| NativeError::Dial(format!("{host}: no address for the wireguard server")))
}

fn pool_key(server: SocketAddr, config: &WireguardConfig) -> Result<WgKey, NativeError> {
    let secret = decode_private(&config.private_key)?;
    let peer = decode_public(&config.public_key)?;
    let psk = decode_psk(config)?;
    let mut hasher = blake2::Blake2s256::new();
    hasher.update(&secret[..]);
    let secret_hash: [u8; 32] = hasher.finalize().into();
    let mut psk_hasher = blake2::Blake2s256::new();
    psk_hasher.update(&psk[..]);
    let psk_hash: [u8; 32] = psk_hasher.finalize().into();
    Ok(WgKey {
        server,
        peer,
        secret_hash,
        psk_hash,
        address: config.address.to_string(),
        mtu: mtu_of(config),
        reserved: reserved_of(config),
        dns: dns_identity(config),
    })
}

impl From<KeyError> for NativeError {
    fn from(error: KeyError) -> Self {
        Self::Config(format!("wireguard key: {error}"))
    }
}

fn decode_psk(config: &WireguardConfig) -> Result<zeroize::Zeroizing<[u8; 32]>, NativeError> {
    config
        .preshared_key
        .as_deref()
        .filter(|psk| !psk.trim().is_empty())
        .map_or_else(
            || Ok(zeroize::Zeroizing::new([0u8; 32])),
            |psk| decode_preshared(psk).map_err(Into::into),
        )
}

fn mtu_of(config: &WireguardConfig) -> usize {
    config
        .mtu
        .as_deref()
        .and_then(|mtu| mtu.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_MTU)
        .clamp(MIN_MTU, DEFAULT_MTU)
}

/// The DNS settings a device's resolver is built from, folded into the pool
/// key: two rows with the same wire identity but different `dns` must not
/// share the device that owns the resolver.
fn dns_identity(config: &WireguardConfig) -> String {
    let servers = config
        .dns
        .as_ref()
        .map_or_else(String::new, |servers| servers.join(","));
    format!("{}|{:?}", servers, config.remote_dns_resolve)
}

fn reserved_of(config: &WireguardConfig) -> [u8; 3] {
    config
        .reserved
        .as_deref()
        .and_then(leas_proto::proto_spec::parse_reserved_bytes)
        .and_then(|bytes| bytes.try_into().ok())
        .unwrap_or([0u8; 3])
}

async fn build(server: SocketAddr, config: &WireguardConfig) -> Result<WgDevice, NativeError> {
    let secret = decode_private(&config.private_key)?;
    let peer = decode_public(&config.public_key)?;
    let psk = match decode_psk(config)? {
        psk if psk[..] == [0u8; 32][..] => None,
        psk => Some(psk),
    };
    let mtu = mtu_of(config);
    let reserved = reserved_of(config);
    let (addresses, families) = parse_addresses(&config.address)?;

    let bind = if server.is_ipv4() {
        SocketAddr::from(([0u8, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|error| NativeError::Dial(format!("wireguard udp bind: {error}")))?;
    socket
        .connect(server)
        .await
        .map_err(|error| NativeError::Dial(format!("wireguard udp connect {server}: {error}")))?;

    let index = crate::rand::u32_below(u32::MAX);
    let keepalive = config.persistent_keepalive.unwrap_or(0);
    let keepalive = u16::try_from(keepalive).unwrap_or(u16::MAX);
    let tunnel = Tunnel::new(secret, peer, psk, mtu, reserved, index, keepalive)?;
    let stack = Arc::new(
        WgStack::start(
            WgLink::new(socket, tunnel),
            StackConfig::new(addresses, mtu),
        )
        .map_err(|error| NativeError::Config(format!("wireguard stack: {error}")))?,
    );

    let dns = plain_dns(config, &stack);
    Ok(WgDevice {
        stack,
        dns,
        families,
        last_used: AtomicU64::new(unix_secs()),
    })
}

fn plain_dns(config: &WireguardConfig, stack: &Arc<WgStack>) -> Option<Arc<leas_dns::DnsResolver>> {
    if config.remote_dns_resolve == Some(false) {
        return None;
    }
    let servers: Vec<IpAddr> = config
        .dns
        .as_ref()?
        .iter()
        .filter_map(|server| server.trim().parse::<IpAddr>().ok())
        .collect();
    if servers.is_empty() {
        return None;
    }
    let resolver = leas_dns::DnsResolver::new();
    resolver.set_plain_resolver(Arc::new(TunnelDns::new(stack, servers)));
    Some(Arc::new(resolver))
}

/// Whether a config's `address` list parses, for the capability gate (which
/// must not build a device to answer).
///
/// # Errors
///
/// Returns the gate's human-readable reason when the list is empty or an entry
/// is neither a CIDR nor a bare IP.
pub fn parse_addresses_for_gate(raw: &str) -> Result<(), String> {
    parse_addresses(raw)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn parse_addresses(raw: &str) -> Result<(Vec<IpCidr>, (bool, bool)), NativeError> {
    let mut addresses = Vec::new();
    let mut families = (false, false);
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let cidr = if let Ok(cidr) = part.parse::<IpCidr>() {
            cidr
        } else {
            let ip: IpAddr = part
                .parse()
                .map_err(|_| NativeError::Config(format!("wireguard address: {part}")))?;
            match ip {
                IpAddr::V4(v4) => IpCidr::Ipv4(Ipv4Cidr::new(v4, 32)),
                IpAddr::V6(v6) => IpCidr::Ipv6(Ipv6Cidr::new(v6, 128)),
            }
        };
        match cidr {
            IpCidr::Ipv4(v4) => families.0 |= v4.prefix_len() > 0,
            IpCidr::Ipv6(v6) => families.1 |= v6.prefix_len() > 0,
        }
        addresses.push(cidr);
    }
    if addresses.is_empty() {
        return Err(NativeError::Config(
            "wireguard address is empty; the tunnel needs one interface address".into(),
        ));
    }
    Ok((addresses, families))
}

async fn resolve(device: &WgDevice, target: &TargetAddr) -> Result<SocketAddr, NativeError> {
    let ip = match &target.host {
        Host::Ip(ip) => *ip,
        Host::Domain(name) => {
            let ips = match &device.dns {
                Some(dns) => {
                    // `leas-dns` owns the policy and logs the one permitted
                    // fallback per installed resolver; a per-dial warn here is
                    // the log flood that bound exists to prevent.
                    let (ips, _scope) =
                        dns.lookup_ip_scoped(name, true).await.map_err(|error| {
                            NativeError::Dial(format!("wireguard dns {name}: {error}"))
                        })?;
                    ips
                }
                None => local_lookup(name, target.port).await?,
            };
            pick_family(&ips, device.families).ok_or_else(|| {
                NativeError::Dial(format!(
                    "wireguard dns {name}: no address of a configured tunnel family"
                ))
            })?
        }
    };
    Ok(SocketAddr::new(ip, target.port))
}

async fn local_lookup(name: &str, port: u16) -> Result<Box<[IpAddr]>, NativeError> {
    let addrs = tokio::time::timeout(timeouts::DIAL, tokio::net::lookup_host((name, port)))
        .await
        .map_err(|_| NativeError::Timeout {
            step: "wireguard target dns",
            limit: timeouts::DIAL,
        })?
        .map_err(|error| NativeError::Dial(format!("{name}: {error}")))?;
    let ips: Vec<IpAddr> = addrs.map(|addr| addr.ip()).collect();
    if ips.is_empty() {
        return Err(NativeError::Dial(format!("{name}: no address")));
    }
    Ok(ips.into_boxed_slice())
}

fn pick_family(ips: &[IpAddr], families: (bool, bool)) -> Option<IpAddr> {
    ips.iter().copied().find(|ip| match ip {
        IpAddr::V4(_) => families.0,
        IpAddr::V6(_) => families.1,
    })
}

#[cfg(test)]
mod tests {
    use super::{mtu_of, parse_addresses, pick_family, reserved_of};
    use leas_proto::proto_spec::WireguardConfig;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn config() -> WireguardConfig {
        WireguardConfig {
            private_key: String::new(),
            security: leas_proto::proto_spec::SecurityConfig::default(),
            address: "172.16.0.2/32".into(),
            public_key: String::new(),
            preshared_key: None,
            reserved: None,
            mtu: None,
            persistent_keepalive: None,
            dns: None,
            remote_dns_resolve: None,
            remarks: None,
        }
    }

    /// A row whose key does not decode is refused by the pool before any
    /// socket is opened — the dispatcher reached the pool, not `not_impl`.
    #[tokio::test]
    async fn a_bad_key_is_refused_before_any_socket() {
        use crate::addr::TargetAddr;
        use crate::inbound::outbound::ProxyOutbound;
        use leas_proto::proto_spec::{EndpointEssentials, ProtocolConfig, ProtocolKind};

        let mut cfg = config();
        cfg.private_key = "not-a-key".into();
        let proxy = ProxyOutbound {
            protocol: ProtocolConfig::Wireguard(cfg),
            kind: ProtocolKind::WireGuard,
            server: EndpointEssentials::new(String::from("127.0.0.1"), 9),
            resolved_ip: Some(std::net::SocketAddr::from(([127, 0, 0, 1], 9))),
        };
        let error = super::open(&proxy, &TargetAddr::new("192.0.2.1", 443))
            .await
            .err()
            .expect("a bad key must be refused");
        assert!(
            error.to_string().contains("wireguard key"),
            "expected the pool's key refusal, got: {error}"
        );
    }

    #[test]
    fn mtu_defaults_to_1420_and_clamps() {
        let mut cfg = config();
        assert_eq!(mtu_of(&cfg), 1420);
        cfg.mtu = Some("1280".into());
        assert_eq!(mtu_of(&cfg), 1280);
        cfg.mtu = Some("900".into());
        assert_eq!(mtu_of(&cfg), 1280, "the IPv6 floor holds");
        cfg.mtu = Some("9000".into());
        assert_eq!(mtu_of(&cfg), 1420, "the xray ceiling holds");
    }

    #[test]
    fn a_bare_address_gets_a_host_prefix_and_sets_the_family() {
        let (addresses, families) = parse_addresses("172.16.0.2, 2606:4700::1").unwrap();
        assert_eq!(addresses.len(), 2);
        assert!(families.0 && families.1);
        assert!(parse_addresses("").is_err());
        assert!(parse_addresses("not-an-ip").is_err());
    }

    #[test]
    fn reserved_is_three_bytes_or_absent() {
        let mut cfg = config();
        assert_eq!(reserved_of(&cfg), [0, 0, 0]);
        cfg.reserved = Some("236,163,162".into());
        assert_eq!(reserved_of(&cfg), [236, 163, 162]);
        cfg.reserved = Some("1,2".into());
        assert_eq!(reserved_of(&cfg), [0, 0, 0], "wrong length is ignored");
    }

    #[test]
    fn a_target_only_takes_a_configured_family() {
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(pick_family(&[v4, v6], (true, false)), Some(v4));
        assert_eq!(pick_family(&[v4, v6], (false, true)), Some(v6));
        assert_eq!(pick_family(&[v4], (false, true)), None);
    }
}
