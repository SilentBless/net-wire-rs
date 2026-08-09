use std::fmt::Write;

use net_wire::{
    ethernet::{EtherType, EthernetFrame, EthernetFrameBuilder, MacAddress},
    ipv4::{Ipv4Address, Ipv4Packet, Ipv4PacketBuilder, Ipv4Protocol},
    ipv6::{Ipv6Packet, Ipv6PayloadLength},
    udp::{UdpChecksumStatus, UdpDatagramBuilder},
};

const DEMO_PAYLOAD: &[u8] = b"demo";
const ETHERNET_HEADER_LENGTH: usize = 14;
const IPV4_HEADER_LENGTH: usize = 20;
const UDP_HEADER_LENGTH: usize = 8;

pub fn demo_frame() -> Result<Vec<u8>, String> {
    let source = Ipv4Address::new([192, 0, 2, 10]);
    let destination = Ipv4Address::new([198, 51, 100, 20]);
    let udp_length = UDP_HEADER_LENGTH + DEMO_PAYLOAD.len();
    let ip_length = IPV4_HEADER_LENGTH + udp_length;
    let mut bytes = vec![0; ETHERNET_HEADER_LENGTH + ip_length];

    {
        let mut udp = UdpDatagramBuilder::new(
            &mut bytes[ETHERNET_HEADER_LENGTH + IPV4_HEADER_LENGTH..],
            DEMO_PAYLOAD.len(),
        )
        .source_port(49152)
        .destination_port(443)
        .build()
        .map_err(|error| format!("could not build the demo UDP datagram: {error}"))?;
        udp.payload_mut().copy_from_slice(DEMO_PAYLOAD);
        udp.update_checksum_ipv4(source, destination);
    }

    Ipv4PacketBuilder::new(&mut bytes[ETHERNET_HEADER_LENGTH..], udp_length)
        .source(source)
        .destination(destination)
        .protocol(Ipv4Protocol::UDP)
        .ttl(64)
        .identification(0x1234)
        .build()
        .map_err(|error| format!("could not build the demo IPv4 packet: {error}"))?;

    EthernetFrameBuilder::new(&mut bytes, ip_length)
        .destination(MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]))
        .source(MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]))
        .ether_type(EtherType::IPV4)
        .build()
        .map_err(|error| format!("could not build the demo Ethernet frame: {error}"))?;

    Ok(bytes)
}

pub fn report(bytes: &[u8]) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "Frame: {} bytes supplied", bytes.len());

    let frame = match EthernetFrame::parse(bytes) {
        Ok(frame) => frame,
        Err(error) => {
            let _ = writeln!(output, "Ethernet: parse failed: {error}");
            return output;
        }
    };

    let ether_type = frame.ether_type();
    let _ = writeln!(output, "Ethernet:");
    let _ = writeln!(output, "  destination: {}", frame.destination());
    let _ = writeln!(output, "  source:      {}", frame.source());
    let _ = writeln!(output, "  EtherType:   0x{:04x}", ether_type.raw());
    let _ = writeln!(
        output,
        "  represented: {} bytes ({} payload)",
        frame.as_bytes().len(),
        frame.payload().len()
    );

    match ether_type {
        EtherType::IPV4 => inspect_ipv4(frame.payload(), &mut output),
        EtherType::IPV6 => inspect_ipv6(frame.payload(), &mut output),
        value => {
            let _ = writeln!(
                output,
                "Network: unsupported EtherType 0x{:04x}",
                value.raw()
            );
        }
    }

    output
}

fn inspect_ipv4(bytes: &[u8], output: &mut String) {
    let packet = match Ipv4Packet::parse(bytes) {
        Ok(packet) => packet,
        Err(error) => {
            let _ = writeln!(output, "IPv4: parse failed: {error}");
            return;
        }
    };
    let source = packet.source();
    let destination = packet.destination();
    let protocol = packet.protocol();

    let _ = writeln!(output, "IPv4:");
    let _ = writeln!(output, "  source:      {}", ipv4_address(source));
    let _ = writeln!(output, "  destination: {}", ipv4_address(destination));
    let _ = writeln!(output, "  protocol:    {}", protocol.raw());
    let _ = writeln!(
        output,
        "  represented: {} bytes ({} payload)",
        packet.as_bytes().len(),
        packet.payload().len()
    );
    let _ = writeln!(
        output,
        "  header checksum: {} (0x{:04x})",
        validity(packet.checksum_is_valid()),
        packet.header_checksum()
    );

    if is_ipv4_fragment(&packet) {
        let _ = writeln!(output, "Transport: not inspected (IPv4 fragment)");
        return;
    }

    match protocol {
        Ipv4Protocol::UDP => match packet.udp() {
            Ok(Some(datagram)) => inspect_udp_ipv4(datagram, source, destination, output),
            Ok(None) => transport_unavailable(output),
            Err(error) => transport_parse_failed(output, error),
        },
        Ipv4Protocol::TCP => match packet.tcp() {
            Ok(Some(segment)) => inspect_tcp_ipv4(segment, source, destination, output),
            Ok(None) => transport_unavailable(output),
            Err(error) => transport_parse_failed(output, error),
        },
        value => {
            let _ = writeln!(
                output,
                "Transport: unsupported IPv4 protocol {}",
                value.raw()
            );
        }
    }
}

fn inspect_ipv6(bytes: &[u8], output: &mut String) {
    let packet = match Ipv6Packet::parse(bytes) {
        Ok(packet) => packet,
        Err(error) => {
            let _ = writeln!(output, "IPv6: parse failed: {error}");
            return;
        }
    };
    let source = packet.source();
    let destination = packet.destination();
    let next_header = packet.next_header();

    let _ = writeln!(output, "IPv6:");
    let _ = writeln!(output, "  source:      {source}");
    let _ = writeln!(output, "  destination: {destination}");
    let _ = writeln!(output, "  next header: {}", next_header.raw());
    let _ = writeln!(
        output,
        "  payload length: {}",
        ipv6_payload_length(packet.payload_length())
    );
    let _ = writeln!(
        output,
        "  represented: {} bytes ({} payload)",
        packet.as_bytes().len(),
        packet.payload().len()
    );

    match packet.udp() {
        Ok(Some(datagram)) => inspect_udp_ipv6(datagram, source, destination, output),
        Ok(None) => match packet.tcp() {
            Ok(Some(segment)) => inspect_tcp_ipv6(segment, source, destination, output),
            Ok(None) => {
                let _ = writeln!(
                    output,
                    "Transport: not UDP/TCP (IPv6 next header {})",
                    next_header.raw()
                );
            }
            Err(error) => {
                let _ = writeln!(output, "Transport: not inspected: {error}");
            }
        },
        Err(error) => {
            let _ = writeln!(output, "Transport: not inspected: {error}");
        }
    }
}

fn inspect_udp_ipv4(
    datagram: net_wire::udp::UdpDatagram<'_>,
    source: Ipv4Address,
    destination: Ipv4Address,
    output: &mut String,
) {
    let status = match datagram.checksum_status_ipv4(source, destination) {
        UdpChecksumStatus::NotPresent => "not present",
        UdpChecksumStatus::Valid => "valid",
        UdpChecksumStatus::Invalid => "invalid",
    };
    inspect_udp(
        datagram.source_port(),
        datagram.destination_port(),
        datagram.length(),
        datagram.payload().len(),
        datagram.checksum(),
        status,
        output,
    );
}

fn inspect_udp_ipv6(
    datagram: net_wire::udp::UdpDatagram<'_>,
    source: net_wire::ipv6::Ipv6Address,
    destination: net_wire::ipv6::Ipv6Address,
    output: &mut String,
) {
    let status = validity(datagram.checksum_is_valid_ipv6(source, destination));
    inspect_udp(
        datagram.source_port(),
        datagram.destination_port(),
        datagram.length(),
        datagram.payload().len(),
        datagram.checksum(),
        status,
        output,
    );
}

fn inspect_udp(
    source: u16,
    destination: u16,
    length: u16,
    payload_length: usize,
    checksum: u16,
    status: &str,
    output: &mut String,
) {
    let _ = writeln!(output, "UDP:");
    let _ = writeln!(output, "  ports:       {source} -> {destination}");
    let _ = writeln!(
        output,
        "  represented: {length} bytes ({payload_length} payload)"
    );
    let _ = writeln!(output, "  checksum:    {status} (0x{checksum:04x})");
}

fn inspect_tcp_ipv4(
    segment: net_wire::tcp::TcpSegment<'_>,
    source: Ipv4Address,
    destination: Ipv4Address,
    output: &mut String,
) {
    match segment.checksum_is_valid_ipv4(source, destination) {
        Ok(valid) => inspect_tcp(segment, validity(valid), output),
        Err(error) => inspect_tcp(segment, &format!("could not validate: {error}"), output),
    }
}

fn inspect_tcp_ipv6(
    segment: net_wire::tcp::TcpSegment<'_>,
    source: net_wire::ipv6::Ipv6Address,
    destination: net_wire::ipv6::Ipv6Address,
    output: &mut String,
) {
    match segment.checksum_is_valid_ipv6(source, destination) {
        Ok(valid) => inspect_tcp(segment, validity(valid), output),
        Err(error) => inspect_tcp(segment, &format!("could not validate: {error}"), output),
    }
}

fn inspect_tcp(segment: net_wire::tcp::TcpSegment<'_>, checksum: &str, output: &mut String) {
    let _ = writeln!(output, "TCP:");
    let _ = writeln!(
        output,
        "  ports:       {} -> {}",
        segment.source_port(),
        segment.destination_port()
    );
    let _ = writeln!(
        output,
        "  represented: {} bytes ({} header, {} payload)",
        segment.as_bytes().len(),
        segment.header_length(),
        segment.payload().len()
    );
    let _ = writeln!(
        output,
        "  checksum:    {checksum} (0x{:04x})",
        segment.checksum()
    );
}

fn is_ipv4_fragment(packet: &Ipv4Packet<'_>) -> bool {
    packet.flags_fragment_offset() & 0x3fff != 0
}

fn transport_unavailable(output: &mut String) {
    let _ = writeln!(
        output,
        "Transport: not inspected (fragmented or unsupported extension header)"
    );
}

fn transport_parse_failed(output: &mut String, error: impl std::fmt::Display) {
    let _ = writeln!(output, "Transport: parse failed: {error}");
}

fn ipv4_address(address: Ipv4Address) -> String {
    let [a, b, c, d] = address.octets();
    format!("{a}.{b}.{c}.{d}")
}

fn ipv6_payload_length(length: Ipv6PayloadLength) -> String {
    match length {
        Ipv6PayloadLength::Declared(length) => format!("{length} bytes"),
        Ipv6PayloadLength::Unspecified => "unspecified (zero field)".to_owned(),
    }
}

fn validity(valid: bool) -> &'static str {
    if valid { "valid" } else { "invalid" }
}
