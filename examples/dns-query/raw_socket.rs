//! Linux raw IPv4 socket lifecycle for the example.

use std::{
    io::{self, Read},
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use net_wire::ipv4::Ipv4Address;

use crate::{
    dns::DnsError,
    packet::{PacketError, ResponseExpectation, parse_response_packet},
};

const RECEIVE_BUFFER_LEN: usize = 65_535;
const READ_TIMEOUT: Duration = Duration::from_secs(5);

pub fn send_and_receive(
    source: Ipv4Address,
    server: Ipv4Address,
    request: &[u8],
    expected: ResponseExpectation,
) -> Result<Vec<u8>, SocketError> {
    let socket =
        Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP)).map_err(SocketError::Io)?;
    socket
        .set_header_included_v4(true)
        .map_err(SocketError::Io)?;
    let source_address = SockAddr::from(SocketAddrV4::new(Ipv4Addr::from(source.octets()), 0));
    let server_address = SockAddr::from(SocketAddrV4::new(Ipv4Addr::from(server.octets()), 0));
    socket.bind(&source_address).map_err(SocketError::Io)?;
    socket.connect(&server_address).map_err(SocketError::Io)?;
    socket
        .set_read_timeout(Some(READ_TIMEOUT))
        .map_err(SocketError::Io)?;
    let sent = socket.send(request).map_err(SocketError::Io)?;
    if sent != request.len() {
        return Err(SocketError::Io(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("raw socket sent {sent} of {} packet bytes", request.len()),
        )));
    }

    let mut buffer = [0u8; RECEIVE_BUFFER_LEN];
    let mut reader = &socket;
    loop {
        let length = reader.read(&mut buffer).map_err(SocketError::Io)?;
        let packet = &buffer[..length];
        match parse_response_packet(packet, expected) {
            Ok(_) => return Ok(packet.to_vec()),
            Err(PacketError::UnexpectedDatagram)
            | Err(PacketError::Dns(DnsError::TransactionIdMismatch { .. })) => continue,
            Err(error) => return Err(SocketError::Packet(error)),
        }
    }
}

#[derive(Debug)]
pub enum SocketError {
    Io(io::Error),
    Packet(PacketError),
}
impl core::fmt::Display for SocketError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "raw socket error: {error}"),
            Self::Packet(error) => write!(f, "response packet rejected: {error}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_socket_entry_point_is_type_checked() {
        let entry: fn(
            Ipv4Address,
            Ipv4Address,
            &[u8],
            ResponseExpectation,
        ) -> Result<Vec<u8>, SocketError> = send_and_receive;
        let _ = entry;
    }
}
