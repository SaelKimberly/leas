//! The UDP carrier: a connected socket plus one [`Tunnel`] behind the stack's
//! [`PacketLink`] seam.
//!
//! The link owns the `WireGuard` timers. `recv` polls them between datagrams and
//! sleeps only until the tunnel's own next deadline, so a driver that is idle
//! never spins: the stack's `poll_delay` and the tunnel's `next_deadline` are
//! the only timers in the system.

use std::io;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;

use super::PacketLink;
use crate::protocol::wireguard::core::device::{Event, Tunnel};

/// Receiver scratch: an MTU-sized packet plus `WireGuard` overhead and padding.
const SCRATCH: usize = 2048;

/// A `WireGuard` datagram carrier for the stack.
pub struct WgLink {
    socket: UdpSocket,
    tunnel: Tunnel,
    scratch: Vec<u8>,
    /// Datagrams the tunnel produced but the socket has not sent yet.
    ///
    /// Flushing inside `select!` is cancellable: a `Command` or timer winning
    /// the race would drop the remaining staged payloads even though their
    /// flow already returned success. Draining here at loop entry makes the
    /// loss window one datagram (which TCP/smoltcp retransmits anyway).
    outbox: std::collections::VecDeque<Vec<u8>>,
}

impl std::fmt::Debug for WgLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgLink")
            .field("local", &self.socket.local_addr().ok())
            .field("tunnel", &self.tunnel)
            .field("scratch", &self.scratch.len())
            .field("outbox", &self.outbox.len())
            .finish()
    }
}

impl WgLink {
    /// Wrap a connected UDP socket and its tunnel.
    #[must_use]
    pub fn new(socket: UdpSocket, tunnel: Tunnel) -> Self {
        Self {
            socket,
            tunnel,
            scratch: vec![0u8; SCRATCH],
            outbox: std::collections::VecDeque::new(),
        }
    }
}

impl PacketLink for WgLink {
    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        {
            loop {
                while let Some(datagram) = self.outbox.pop_front() {
                    self.socket.send(&datagram).await?;
                }
                let now = unix_secs();
                let mut events = Vec::new();
                self.tunnel.poll(now, &mut events);
                for event in events {
                    match event {
                        Event::Send(datagram) => self.outbox.push_back(datagram),
                        Event::Inbound(packet) => {
                            let len = packet.len().min(buf.len());
                            buf[..len].copy_from_slice(&packet[..len]);
                            return Ok(len);
                        }
                        Event::Established | Event::Failed => {}
                        Event::Dead => {
                            return Err(io::Error::new(
                                io::ErrorKind::NotConnected,
                                "wireguard handshake failed: the peer is unreachable",
                            ));
                        }
                    }
                }
                // `poll` just produced datagrams (keepalives, retransmits).
                // Flush them BEFORE deciding how long to sleep: with no
                // session timer the select would otherwise park with the
                // datagram stranded in the outbox.
                while let Some(datagram) = self.outbox.pop_front() {
                    self.socket.send(&datagram).await?;
                }

                let deadline = self
                    .tunnel
                    .next_deadline()
                    .map(|at| Duration::from_secs(at.saturating_sub(unix_secs())));
                let Self {
                    socket,
                    tunnel,
                    scratch,
                    outbox,
                } = self;
                tokio::select! {
                    received = socket.recv(scratch) => {
                        let len = received?;
                        let mut events = Vec::new();
                        tunnel.receive(unix_secs(), &mut scratch[..len], &mut events);
                        for event in events {
                            match event {
                                Event::Send(datagram) => outbox.push_back(datagram),
                                Event::Inbound(packet) => {
                                    let len = packet.len().min(buf.len());
                                    buf[..len].copy_from_slice(&packet[..len]);
                                    return Ok(len);
                                }
                                Event::Established | Event::Failed => {}
                                Event::Dead => {
                                    return Err(io::Error::new(
                                        io::ErrorKind::NotConnected,
                                        "wireguard handshake failed: the peer is unreachable",
                                    ));
                                }
                            }
                        }
                    }
                    () = sleep_until(deadline) => {}
                }
            }
        }
    }

    async fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        {
            let mut events = Vec::new();
            self.tunnel.send(unix_secs(), packet, &mut events);
            for event in events {
                if let Event::Send(datagram) = event {
                    self.outbox.push_back(datagram);
                }
            }
            while let Some(datagram) = self.outbox.pop_front() {
                self.socket.send(&datagram).await?;
            }
            if self.tunnel.is_dead() {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "wireguard handshake failed: the peer is unreachable",
                ));
            }
            Ok(())
        }
    }
}

async fn sleep_until(deadline: Option<Duration>) {
    match deadline {
        // A deadline that already passed (the second clock ticked between the
        // poll and this call) must poll again, not sleep forever.
        Some(duration) if duration.is_zero() => tokio::task::yield_now().await,
        Some(duration) => tokio::time::sleep(duration).await,
        None => std::future::pending().await,
    }
}

/// Unix seconds — the tunnel's clock.
fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}
