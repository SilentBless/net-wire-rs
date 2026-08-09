//! IPv4/UDP envelope for DNS queries and replies.

use core::fmt;

use net_wire::{
    ParseError,
    ipv4::{Ipv4Address, Ipv4Packet, Ipv4PacketBuilder, Ipv4Protocol},
    udp::{UdpChecksumStatus, UdpDatagramBuilder},
};

use crate::dns::{self, DnsError, Message, QueryType};

const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryParameters<'a> {
    pub source: Ipv4Address,
    pub destination: Ipv4Address,
    pub source_port: u16,
    pub destination_port: u16,
    pub transaction_id: u16,
    pub qname: &'a str,
    pub query_type: QueryType,
    pub ipv4_identification: u16,
    pub ttl: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponseExpectation {
    pub source: Ipv4Address,
    pub destination: Ipv4Address,
    pub source_port: u16,
    pub destination_port: u16,
    pub transaction_id: u16,
}

impl<'a> From<QueryParameters<'a>> for ResponseExpectation {
    fn from(query: QueryParameters<'a>) -> Self {
        Self {
            source: query.destination,
            destination: query.source,
            source_port: query.destination_port,
            destination_port: query.source_port,
            transaction_id: query.transaction_id,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponsePacket<'a> {
    pub dns: Message<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketError {
    Dns(DnsError),
    Ip(ParseError),
    Udp(ParseError),
    UdpBuild(net_wire::udp::UdpDatagramBuildError),
    IpBuild(net_wire::ipv4::Ipv4PacketBuildError),
    BufferTooShort { required: usize, available: usize },
    InvalidIpv4Checksum,
    InvalidUdpChecksum,
    UnexpectedDatagram,
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(error) => write!(f, "DNS error: {error}"),
            Self::Ip(error) => write!(f, "IPv4 parse error: {error}"),
            Self::Udp(error) => write!(f, "UDP parse error: {error}"),
            Self::UdpBuild(error) => write!(f, "UDP build error: {error}"),
            Self::IpBuild(error) => write!(f, "IPv4 build error: {error}"),
            Self::BufferTooShort {
                required,
                available,
            } => {
                write!(
                    f,
                    "packet buffer is too short: need {required}, have {available}"
                )
            }
            Self::InvalidIpv4Checksum => f.write_str("invalid IPv4 header checksum"),
            Self::InvalidUdpChecksum => f.write_str("invalid UDP checksum"),
            Self::UnexpectedDatagram => f.write_str("unexpected IPv4/UDP datagram"),
        }
    }
}

impl From<DnsError> for PacketError {
    fn from(error: DnsError) -> Self {
        Self::Dns(error)
    }
}

/// Builds DNS, then UDP, then IPv4 in `buffer` and returns the exact packet bytes.
pub fn build_query_packet<'a>(
    buffer: &'a mut [u8],
    query: QueryParameters<'_>,
) -> Result<&'a [u8], PacketError> {
    let minimum = IPV4_HEADER_LEN + UDP_HEADER_LEN;
    if buffer.len() < minimum {
        return Err(PacketError::BufferTooShort {
            required: minimum,
            available: buffer.len(),
        });
    }
    let dns_length = dns::build_query(
        &mut buffer[minimum..],
        query.transaction_id,
        query.qname,
        query.query_type,
    )?;
    let udp_length = UDP_HEADER_LEN + dns_length;
    {
        let mut udp = UdpDatagramBuilder::new(
            &mut buffer[IPV4_HEADER_LEN..IPV4_HEADER_LEN + udp_length],
            dns_length,
        )
        .source_port(query.source_port)
        .destination_port(query.destination_port)
        .build()
        .map_err(PacketError::UdpBuild)?;
        udp.update_checksum_ipv4(query.source, query.destination);
    }
    let total_length = IPV4_HEADER_LEN + udp_length;
    {
        let _ip = Ipv4PacketBuilder::new(&mut buffer[..total_length], udp_length)
            .source(query.source)
            .destination(query.destination)
            .protocol(Ipv4Protocol::UDP)
            .ttl(query.ttl)
            .identification(query.ipv4_identification)
            .build()
            .map_err(PacketError::IpBuild)?;
    }
    Ok(&buffer[..total_length])
}

/// Validates and filters a raw IPv4 datagram before exposing its DNS response.
pub fn parse_response_packet<'a>(
    bytes: &'a [u8],
    expected: ResponseExpectation,
) -> Result<ResponsePacket<'a>, PacketError> {
    let ip = Ipv4Packet::parse(bytes).map_err(PacketError::Ip)?;
    if ip.source() != expected.source || ip.destination() != expected.destination {
        return Err(PacketError::UnexpectedDatagram);
    }
    if !ip.checksum_is_valid() {
        return Err(PacketError::InvalidIpv4Checksum);
    }
    let udp = ip
        .udp()
        .map_err(PacketError::Udp)?
        .ok_or(PacketError::UnexpectedDatagram)?;
    if udp.source_port() != expected.source_port
        || udp.destination_port() != expected.destination_port
    {
        return Err(PacketError::UnexpectedDatagram);
    }
    match udp.checksum_status_ipv4(ip.source(), ip.destination()) {
        UdpChecksumStatus::Valid | UdpChecksumStatus::NotPresent => {}
        UdpChecksumStatus::Invalid => return Err(PacketError::InvalidUdpChecksum),
    }
    let dns = Message::parse(udp.payload())?.require_response(expected.transaction_id)?;
    Ok(ResponsePacket { dns })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> QueryParameters<'static> {
        QueryParameters {
            source: Ipv4Address::new([192, 0, 2, 10]),
            destination: Ipv4Address::new([192, 0, 2, 53]),
            source_port: 53000,
            destination_port: 53,
            transaction_id: 0x1234,
            qname: "example.com",
            query_type: QueryType::A,
            ipv4_identification: 7,
            ttl: 64,
        }
    }

    #[test]
    fn packet_has_valid_ipv4_and_udp_checksums() {
        let mut bytes = [0; 128];
        let packet = build_query_packet(&mut bytes, query()).unwrap();
        let ip = Ipv4Packet::parse(packet).unwrap();
        assert!(ip.checksum_is_valid());
        let udp = ip.udp().unwrap().unwrap();
        assert_eq!(
            udp.checksum_status_ipv4(ip.source(), ip.destination()),
            UdpChecksumStatus::Valid
        );
        assert_eq!(udp.payload()[..2], [0x12, 0x34]);
    }

    #[test]
    fn response_filter_rejects_wrong_addresses_and_bad_checksums() {
        let mut bytes = [0; 128];
        let packet = build_query_packet(&mut bytes, query()).unwrap().to_vec();
        let expected = ResponseExpectation::from(query());
        let wrong_address = ResponseExpectation {
            destination: Ipv4Address::new([192, 0, 2, 11]),
            ..expected
        };
        assert_eq!(
            parse_response_packet(&packet, wrong_address),
            Err(PacketError::UnexpectedDatagram)
        );

        let mut damaged = packet;
        damaged[8] ^= 1;
        let query_direction = ResponseExpectation {
            source: query().source,
            destination: query().destination,
            source_port: query().source_port,
            destination_port: query().destination_port,
            transaction_id: query().transaction_id,
        };
        assert_eq!(
            parse_response_packet(&damaged, query_direction),
            Err(PacketError::InvalidIpv4Checksum)
        );
    }

    #[test]
    fn ipv4_response_accepts_an_absent_udp_checksum() {
        let mut bytes = [0; 128];
        let packet_length = build_query_packet(&mut bytes, query()).unwrap().len();
        bytes[30] |= 0x80;
        bytes[26..28].fill(0);

        let expected = ResponseExpectation {
            source: query().source,
            destination: query().destination,
            source_port: query().source_port,
            destination_port: query().destination_port,
            transaction_id: query().transaction_id,
        };
        assert!(parse_response_packet(&bytes[..packet_length], expected).is_ok());
    }
}
