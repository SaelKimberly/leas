//! TUIC UDP association: QUIC DATAGRAM (`native`) or one PACKET frame per
//! unidirectional stream (`quic`), with one bounded defragmenter per driver.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use quinn::{Connection, SendDatagramError};
use tokio::sync::mpsc;

use leas_proto::proto_spec::TuicConfig;

use crate::addr::TargetAddr;
use crate::context::LinkContext;
use crate::error::NativeError;

use super::quic::{self, ConnectionGuard};
use super::wire::{self, Address, Defragger, FragmentPlan};

const MAX_STREAM_FRAME: usize = 128 * 1024;
const MAX_UDP_PAYLOAD: usize = 65_535;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Native,
    Quic,
}

enum Control {
    Dissociate(u16),
}

struct Session {
    conn: Connection,
    control: mpsc::Sender<Control>,
    _guard: ConnectionGuard,
    id: u16,
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.control.try_send(Control::Dissociate(self.id));
    }
}

struct Datagram {
    destination: Option<SocketAddr>,
    payload: Bytes,
}

pub struct UdpConn {
    reader: UdpReader,
    writer: UdpWriter,
}

impl UdpConn {
    pub(crate) async fn send(
        &mut self,
        dest: Option<SocketAddr>,
        payload: &[u8],
    ) -> io::Result<()> {
        self.writer.send(dest, payload).await
    }

    pub(crate) async fn recv(&mut self) -> io::Result<Option<(Option<SocketAddr>, Bytes)>> {
        self.reader.recv().await
    }

    #[must_use]
    pub(crate) fn split(self) -> (UdpReader, UdpWriter) {
        (self.reader, self.writer)
    }
}

pub struct UdpReader {
    rx: mpsc::Receiver<Datagram>,
    _session: Arc<Session>,
}

impl UdpReader {
    pub(crate) async fn recv(&mut self) -> io::Result<Option<(Option<SocketAddr>, Bytes)>> {
        Ok(self
            .rx
            .recv()
            .await
            .map(|datagram| (datagram.destination, datagram.payload)))
    }
}

pub struct UdpWriter {
    session: Arc<Session>,
    target: TargetAddr,
    mode: Mode,
    packet_id: u16,
    send_buf: Vec<u8>,
}

impl UdpWriter {
    pub(crate) async fn send(
        &mut self,
        dest: Option<SocketAddr>,
        payload: &[u8],
    ) -> io::Result<()> {
        if payload.len() > MAX_UDP_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("tuic udp datagram too large: {}", payload.len()),
            ));
        }
        let (address, port) = match dest {
            Some(dest) => (address_of_ip(dest.ip()), dest.port()),
            None => (
                Address::of_host(&self.target.host)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?,
                self.target.port,
            ),
        };
        let packet_id = self.packet_id;
        self.packet_id = self.packet_id.wrapping_add(1);

        let conn = &self.session.conn;
        let session = self.session.id;
        if self.mode == Mode::Quic {
            return send_stream(
                conn,
                session,
                &mut self.send_buf,
                packet_id,
                address,
                port,
                payload,
            )
            .await;
        }

        let Some(max) = conn.max_datagram_size() else {
            // The peer did not advertise DATAGRAM support; the quic lane is
            // the protocol's own fallback, not a second wire.
            self.mode = Mode::Quic;
            return send_stream(
                conn,
                session,
                &mut self.send_buf,
                packet_id,
                address,
                port,
                payload,
            )
            .await;
        };

        wire::encode_packet_into(
            session,
            packet_id,
            1,
            0,
            Some((address, port)),
            payload,
            &mut self.send_buf,
        )
        .map_err(wire_io)?;
        if self.send_buf.len() <= max {
            return send_datagram(conn, &self.send_buf);
        }

        let Some(plan) = wire::fragment_plan(max, address.wire_len(), payload.len()) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tuic UDP payload does not fit the datagram budget",
            ));
        };
        send_fragments(
            conn,
            session,
            &mut self.send_buf,
            packet_id,
            address,
            port,
            payload,
            plan,
        )
    }
}

fn send_datagram(conn: &Connection, buf: &[u8]) -> io::Result<()> {
    match conn.send_datagram(Bytes::copy_from_slice(buf)) {
        Ok(()) => Ok(()),
        Err(SendDatagramError::UnsupportedByPeer | SendDatagramError::Disabled) => {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "tuic peer does not accept QUIC datagrams",
            ))
        }
        Err(SendDatagramError::TooLarge) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tuic PACKET exceeds the datagram budget",
        )),
        Err(SendDatagramError::ConnectionLost(error)) => {
            Err(io::Error::other(format!("tuic datagram: {error}")))
        }
    }
}

fn send_fragments(
    conn: &Connection,
    session: u16,
    buf: &mut Vec<u8>,
    packet_id: u16,
    address: Address<'_>,
    port: u16,
    payload: &[u8],
    plan: FragmentPlan,
) -> io::Result<()> {
    let mut offset = 0;
    for index in 0..plan.total {
        let take = payload.len().saturating_sub(offset).min(if index == 0 {
            plan.first
        } else {
            plan.continuation
        });
        let destination = (index == 0).then_some((address, port));
        wire::encode_packet_into(
            session,
            packet_id,
            plan.total,
            index,
            destination,
            &payload[offset..offset + take],
            buf,
        )
        .map_err(wire_io)?;
        send_datagram(conn, buf)?;
        offset += take;
    }
    Ok(())
}

async fn send_stream(
    conn: &Connection,
    session: u16,
    buf: &mut Vec<u8>,
    packet_id: u16,
    address: Address<'_>,
    port: u16,
    payload: &[u8],
) -> io::Result<()> {
    wire::encode_packet_into(
        session,
        packet_id,
        1,
        0,
        Some((address, port)),
        payload,
        buf,
    )
    .map_err(wire_io)?;
    let mut stream = conn
        .open_uni()
        .await
        .map_err(|e| io::Error::other(format!("tuic PACKET stream: {e}")))?;
    tokio::io::AsyncWriteExt::write_all(&mut stream, buf)
        .await
        .map_err(|e| io::Error::other(format!("tuic PACKET write: {e}")))?;
    stream
        .finish()
        .map_err(|e| io::Error::other(format!("tuic PACKET finish: {e}")))
}

const fn address_of_ip(ip: IpAddr) -> Address<'static> {
    match ip {
        IpAddr::V4(ip) => Address::V4(ip.octets()),
        IpAddr::V6(ip) => Address::V6(ip.octets()),
    }
}

fn wire_io(error: wire::WireError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}

/// Dial a TUIC UDP association. The QUIC handshake completes before the
/// association is returned: 0-RTT is a TCP CONNECT feature only (a rejected
/// early DATAGRAM would be silently lost).
pub(crate) async fn connect_udp(
    ctx: &LinkContext,
    cfg: &TuicConfig,
) -> Result<UdpConn, NativeError> {
    let mode = match cfg.udp_relay_mode.as_deref() {
        None | Some("native") => Mode::Native,
        Some("quic") => Mode::Quic,
        Some(other) => {
            return Err(NativeError::Config(format!(
                "unsupported TUIC udp_relay_mode: {other}"
            )));
        }
    };
    let dialed = quic::dial(ctx, cfg, false).await?;
    let session_id = 0;
    let (control, control_rx) = mpsc::channel(8);
    let (data_tx, data_rx) = mpsc::channel(64);
    spawn_driver(dialed.conn.clone(), control_rx, data_tx, session_id);
    let session = Arc::new(Session {
        conn: dialed.conn,
        control,
        _guard: dialed.guard,
        id: session_id,
    });
    Ok(UdpConn {
        reader: UdpReader {
            rx: data_rx,
            _session: Arc::clone(&session),
        },
        writer: UdpWriter {
            session,
            target: ctx.target.clone(),
            mode,
            packet_id: 0,
            send_buf: Vec::with_capacity(1500),
        },
    })
}

fn spawn_driver(
    conn: Connection,
    mut control: mpsc::Receiver<Control>,
    data: mpsc::Sender<Datagram>,
    _session: u16,
) {
    tokio::spawn(async move {
        let mut defrag = Defragger::new();
        loop {
            tokio::select! {
                message = control.recv() => match message {
                    Some(Control::Dissociate(session)) => {
                        let _ = send_dissociate(&conn, session).await;
                    }
                    None => break,
                },
                uni = conn.accept_uni() => match uni {
                    Ok(mut stream) => {
                        let Ok(frame) = stream.read_to_end(MAX_STREAM_FRAME).await else {
                            continue;
                        };
                        if !handle_frame(&mut defrag, &data, &frame) {
                            conn.close(0_u32.into(), b"tuic malformed PACKET");
                            break;
                        }
                    }
                    Err(_) => break,
                },
                datagram = conn.read_datagram() => match datagram {
                    Ok(bytes) => {
                        if !handle_datagram(&mut defrag, &data, &bytes) {
                            conn.close(0_u32.into(), b"tuic malformed datagram");
                            break;
                        }
                    }
                    Err(_) => break,
                },
            }
        }
    });
}

async fn send_dissociate(conn: &Connection, session: u16) -> Result<(), ()> {
    let mut stream = conn.open_uni().await.map_err(|_| ())?;
    tokio::io::AsyncWriteExt::write_all(&mut stream, &wire::dissociate_frame(session))
        .await
        .map_err(|_| ())?;
    stream.finish().map_err(|_| ())
}

fn handle_datagram(defrag: &mut Defragger, data: &mpsc::Sender<Datagram>, bytes: &[u8]) -> bool {
    let Some(version) = bytes.first() else {
        return true;
    };
    if *version != wire::VERSION {
        return false;
    }
    match bytes.get(1).copied() {
        Some(wire::PACKET) => deliver(defrag, data, bytes),
        _ => true,
    }
}

fn handle_frame(defrag: &mut Defragger, data: &mpsc::Sender<Datagram>, bytes: &[u8]) -> bool {
    if bytes.len() < 2 {
        return true;
    }
    if bytes[0] != wire::VERSION {
        return false;
    }
    if bytes[1] == wire::PACKET {
        deliver(defrag, data, bytes)
    } else {
        true
    }
}

fn deliver(defrag: &mut Defragger, data: &mpsc::Sender<Datagram>, bytes: &[u8]) -> bool {
    let Ok(packet) = wire::parse_packet(bytes) else {
        return false;
    };
    let Some(assembled) = defrag.feed(packet, Instant::now()) else {
        return true;
    };
    let destination = assembled.destination.0.socket_addr(assembled.destination.1);
    let _ = data.try_send(Datagram {
        destination,
        payload: Bytes::from(assembled.payload),
    });
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_of_ip_matches_the_wire_families() {
        assert_eq!(
            address_of_ip("192.0.2.1".parse().expect("ipv4")),
            Address::V4([192, 0, 2, 1])
        );
        assert_eq!(
            address_of_ip("2001:db8::1".parse().expect("ipv6")),
            Address::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        );
    }

    #[test]
    fn datagram_and_stream_classifiers_ignore_heartbeats() {
        let (tx, _rx) = mpsc::channel(1);
        let mut defrag = Defragger::new();
        assert!(handle_datagram(&mut defrag, &tx, &[5, 4]));
        assert!(handle_frame(&mut defrag, &tx, &[5, 4]));
        assert!(!handle_datagram(&mut defrag, &tx, &[4, 4]));
        assert!(!handle_datagram(&mut defrag, &tx, &[5, 2]));
    }
}
