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
use crate::udp::datagram::{UdpDatagram, UdpDatagramMut, UdpDatagramMutationError};

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
        if udp_ipv4_checksum_sum(
            source,
            destination,
            self.source_port(),
            self.destination_port(),
            self.length(),
            self.checksum(),
            self.payload(),
        ) == 0xffff
        {
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
        if udp_ipv4_checksum_sum(
            source,
            destination,
            self.source_port(),
            self.destination_port(),
            self.length(),
            self.checksum(),
            self.payload(),
        ) == 0xffff
        {
            UdpChecksumStatus::Valid
        } else {
            UdpChecksumStatus::Invalid
        }
    }

    /// Recomputes this datagram's IPv4 checksum.
    pub fn update_checksum_ipv4(
        &mut self,
        source: Ipv4Address,
        destination: Ipv4Address,
    ) -> Result<(), UdpDatagramMutationError> {
        let value = internet_checksum::checksum(udp_ipv4_checksum_sum(
            source,
            destination,
            self.source_port(),
            self.destination_port(),
            self.length(),
            0,
            self.payload(),
        ));
        self.set_checksum(if value == 0 { 0xffff } else { value })
    }
}

#[cfg(all(feature = "udp", feature = "ipv4"))]
fn udp_ipv4_checksum_sum(
    source: Ipv4Address,
    destination: Ipv4Address,
    source_port: u16,
    destination_port: u16,
    length: u16,
    checksum: u16,
    payload: &[u8],
) -> u32 {
    let sum = add_ipv4_pseudoheader(
        0,
        source.octets(),
        destination.octets(),
        UDP_PROTOCOL,
        length,
    );
    udp_checksum_sum(
        sum,
        source_port,
        destination_port,
        length,
        checksum,
        payload,
    )
}

#[cfg(all(feature = "udp", feature = "ipv6"))]
impl UdpDatagram<'_> {
    /// Checks this datagram against its required IPv6 pseudoheader checksum.
    pub fn checksum_is_valid_ipv6(&self, source: Ipv6Address, destination: Ipv6Address) -> bool {
        self.checksum() != 0
            && udp_ipv6_checksum_sum(
                source,
                destination,
                self.source_port(),
                self.destination_port(),
                self.length(),
                self.checksum(),
                self.payload(),
            ) == 0xffff
    }
}

#[cfg(all(feature = "udp", feature = "ipv6"))]
impl UdpDatagramMut<'_> {
    /// Checks this datagram against its required IPv6 pseudoheader checksum.
    pub fn checksum_is_valid_ipv6(&self, source: Ipv6Address, destination: Ipv6Address) -> bool {
        self.checksum() != 0
            && udp_ipv6_checksum_sum(
                source,
                destination,
                self.source_port(),
                self.destination_port(),
                self.length(),
                self.checksum(),
                self.payload(),
            ) == 0xffff
    }

    /// Recomputes this datagram's IPv6 pseudoheader checksum.
    pub fn update_checksum_ipv6(
        &mut self,
        source: Ipv6Address,
        destination: Ipv6Address,
    ) -> Result<(), UdpDatagramMutationError> {
        let value = internet_checksum::checksum(udp_ipv6_checksum_sum(
            source,
            destination,
            self.source_port(),
            self.destination_port(),
            self.length(),
            0,
            self.payload(),
        ));
        self.set_checksum(if value == 0 { 0xffff } else { value })
    }
}

#[cfg(all(feature = "udp", feature = "ipv6"))]
fn udp_ipv6_checksum_sum(
    source: Ipv6Address,
    destination: Ipv6Address,
    source_port: u16,
    destination_port: u16,
    length: u16,
    checksum: u16,
    payload: &[u8],
) -> u32 {
    let sum = add_ipv6_pseudoheader(
        0,
        source.octets(),
        destination.octets(),
        UDP_PROTOCOL,
        u32::from(length),
    );
    udp_checksum_sum(
        sum,
        source_port,
        destination_port,
        length,
        checksum,
        payload,
    )
}

fn udp_checksum_sum(
    sum: u32,
    source_port: u16,
    destination_port: u16,
    length: u16,
    checksum: u16,
    payload: &[u8],
) -> u32 {
    let sum = internet_checksum::add_bytes(sum, &source_port.to_be_bytes());
    let sum = internet_checksum::add_bytes(sum, &destination_port.to_be_bytes());
    let sum = internet_checksum::add_bytes(sum, &length.to_be_bytes());
    let sum = internet_checksum::add_bytes(sum, &checksum.to_be_bytes());
    internet_checksum::add_bytes(sum, payload)
}
