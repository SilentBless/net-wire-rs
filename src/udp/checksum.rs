//! UDP checksum integration for IP pseudoheaders.

use crate::internet_checksum;
#[cfg(all(feature = "udp", feature = "ipv4"))]
use crate::internet_checksum::add_ipv4_pseudoheader;
#[cfg(all(feature = "udp", feature = "ipv6"))]
use crate::internet_checksum::add_ipv6_pseudoheader;
#[cfg(all(feature = "udp", feature = "ipv4"))]
use crate::ipv4::address::Ipv4Address;
#[cfg(all(feature = "udp", feature = "ipv6"))]
use crate::ipv6::address::Ipv6Address;
use crate::udp::datagram::{UdpDatagram, UdpDatagramMut};

const UDP_PROTOCOL: u8 = 17;

/// The validation state of an IPv4 UDP checksum.
#[cfg(all(feature = "udp", feature = "ipv4"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpChecksumStatus {
    /// UDP has no IPv4 checksum.
    NotPresent,
    /// The encoded checksum is valid.
    Valid,
    /// The encoded checksum is invalid.
    Invalid,
}

#[cfg(all(feature = "udp", feature = "ipv4"))]
impl UdpDatagram<'_> {
    /// Returns the validation state of this datagram's IPv4 checksum.
    pub fn checksum_status_ipv4(
        &self,
        source: Ipv4Address,
        destination: Ipv4Address,
    ) -> UdpChecksumStatus {
        if self.checksum() == 0 {
            return UdpChecksumStatus::NotPresent;
        }
        if udp_ipv4_checksum_sum(self.as_bytes(), source, destination) == 0xffff {
            UdpChecksumStatus::Valid
        } else {
            UdpChecksumStatus::Invalid
        }
    }
}

#[cfg(all(feature = "udp", feature = "ipv4"))]
impl UdpDatagramMut<'_> {
    /// Returns the validation state of this datagram's IPv4 checksum.
    pub fn checksum_status_ipv4(
        &self,
        source: Ipv4Address,
        destination: Ipv4Address,
    ) -> UdpChecksumStatus {
        if self.checksum() == 0 {
            return UdpChecksumStatus::NotPresent;
        }
        if udp_ipv4_checksum_sum(self.as_bytes(), source, destination) == 0xffff {
            UdpChecksumStatus::Valid
        } else {
            UdpChecksumStatus::Invalid
        }
    }

    /// Recomputes this datagram's IPv4 checksum.
    pub fn update_checksum_ipv4(&mut self, source: Ipv4Address, destination: Ipv4Address) {
        let bytes = self.as_bytes_mut();
        bytes[6..8].fill(0);
        let value = internet_checksum::checksum(udp_ipv4_checksum_sum(bytes, source, destination));
        bytes[6..8].copy_from_slice(&(if value == 0 { 0xffff } else { value }).to_be_bytes());
    }
}

#[cfg(all(feature = "udp", feature = "ipv4"))]
fn udp_ipv4_checksum_sum(bytes: &[u8], source: Ipv4Address, destination: Ipv4Address) -> u32 {
    let length = u16::try_from(bytes.len()).expect("UDP length is validated");
    internet_checksum::add_bytes(
        add_ipv4_pseudoheader(
            0,
            source.octets(),
            destination.octets(),
            UDP_PROTOCOL,
            length,
        ),
        bytes,
    )
}

#[cfg(all(feature = "udp", feature = "ipv6"))]
impl UdpDatagram<'_> {
    /// Checks this datagram against its required IPv6 pseudoheader checksum.
    pub fn checksum_is_valid_ipv6(&self, source: Ipv6Address, destination: Ipv6Address) -> bool {
        self.checksum() != 0
            && udp_ipv6_checksum_sum(
                self.as_bytes(),
                source,
                destination,
                u32::from(self.length()),
            ) == 0xffff
    }
}

#[cfg(all(feature = "udp", feature = "ipv6"))]
impl UdpDatagramMut<'_> {
    /// Checks this datagram against its required IPv6 pseudoheader checksum.
    pub fn checksum_is_valid_ipv6(&self, source: Ipv6Address, destination: Ipv6Address) -> bool {
        self.checksum() != 0
            && udp_ipv6_checksum_sum(
                self.as_bytes(),
                source,
                destination,
                u32::from(self.length()),
            ) == 0xffff
    }

    /// Recomputes this datagram's IPv6 pseudoheader checksum.
    pub fn update_checksum_ipv6(&mut self, source: Ipv6Address, destination: Ipv6Address) {
        let length = u32::from(self.length());
        let bytes = self.as_bytes_mut();
        bytes[6..8].fill(0);
        let value =
            internet_checksum::checksum(udp_ipv6_checksum_sum(bytes, source, destination, length));
        bytes[6..8].copy_from_slice(&(if value == 0 { 0xffff } else { value }).to_be_bytes());
    }
}

#[cfg(all(feature = "udp", feature = "ipv6"))]
fn udp_ipv6_checksum_sum(
    bytes: &[u8],
    source: Ipv6Address,
    destination: Ipv6Address,
    length: u32,
) -> u32 {
    internet_checksum::add_bytes(
        add_ipv6_pseudoheader(
            0,
            source.octets(),
            destination.octets(),
            UDP_PROTOCOL,
            length,
        ),
        bytes,
    )
}
