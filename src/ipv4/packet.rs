//! IPv4 packet views and header-checksum handling (RFC 791).

use super::Ipv4Protocol;
#[cfg(feature = "ethernet")]
use crate::{EtherType, EthernetFrame, EthernetFrameMut};
use crate::{Ipv4Address, ParseError};
const HEADER: usize = 20;

/// A structurally validated immutable RFC 791 packet view.
///
/// Parsing validates version, IHL, and declared total length, then excludes trailing capture
/// bytes. It deliberately accepts bad checksums and reserved flags for capture/offload and
/// malformed-packet inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4Packet<'a> {
    bytes: &'a [u8],
    header_length: usize,
}
impl<'a> Ipv4Packet<'a> {
    /// Validates RFC 791 structural bounds; use `checksum_is_valid` for checksum acceptance.
    #[inline]
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let (header_length, total_length) = validate(bytes)?;
        Ok(Self {
            bytes: &bytes[..total_length],
            header_length,
        })
    }
    /// Returns the combined DSCP/ECN octet.
    #[inline]
    pub fn dscp_ecn(&self) -> u8 {
        self.bytes[1]
    }
    /// Returns the RFC 791 total-length field.
    #[inline]
    pub fn total_length(&self) -> u16 {
        read_u16(self.bytes, 2)
    }
    /// Returns the identification field.
    #[inline]
    pub fn identification(&self) -> u16 {
        read_u16(self.bytes, 4)
    }
    /// Returns the raw flags and fragment-offset field, including the reserved flag.
    #[inline]
    pub fn flags_fragment_offset(&self) -> u16 {
        read_u16(self.bytes, 6)
    }
    /// Returns the time-to-live field.
    #[inline]
    pub fn ttl(&self) -> u8 {
        self.bytes[8]
    }
    /// Returns the protocol field while preserving unknown values.
    #[inline]
    pub fn protocol(&self) -> Ipv4Protocol {
        Ipv4Protocol::new(self.bytes[9])
    }
    /// Returns the encoded RFC 791 header checksum.
    #[inline]
    pub fn header_checksum(&self) -> u16 {
        read_u16(self.bytes, 10)
    }
    /// Returns the source address.
    #[inline]
    pub fn source(&self) -> Ipv4Address {
        Ipv4Address::new(
            self.bytes[12..16]
                .try_into()
                .expect("validated IPv4 header"),
        )
    }
    /// Returns the destination address.
    #[inline]
    pub fn destination(&self) -> Ipv4Address {
        Ipv4Address::new(
            self.bytes[16..20]
                .try_into()
                .expect("validated IPv4 header"),
        )
    }
    /// Returns RFC 791 option bytes included by IHL.
    #[inline]
    pub fn options(&self) -> &'a [u8] {
        &self.bytes[HEADER..self.header_length]
    }
    /// Returns declared payload bytes; they are not header-checksum covered.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[self.header_length..]
    }
    /// Returns exactly the declared IPv4 packet bytes.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
    /// Checks the one's-complement checksum across the complete IHL, including options.
    #[inline]
    pub fn checksum_is_valid(&self) -> bool {
        checksum_sum(&self.bytes[..self.header_length]) == 0xffff
    }
}
/// A structurally validated mutable RFC 791 packet view.
#[derive(Debug, Eq, PartialEq)]
pub struct Ipv4PacketMut<'a> {
    bytes: &'a mut [u8],
    header_length: usize,
}
impl<'a> Ipv4PacketMut<'a> {
    /// Validates RFC 791 structural bounds and excludes trailing bytes.
    #[inline]
    pub fn parse(bytes: &'a mut [u8]) -> Result<Self, ParseError> {
        let (header_length, total_length) = validate(bytes)?;
        Ok(Self::from_validated(
            &mut bytes[..total_length],
            header_length,
        ))
    }
    pub(super) fn from_validated(bytes: &'a mut [u8], header_length: usize) -> Self {
        Self {
            bytes,
            header_length,
        }
    }
    /// Returns the combined DSCP/ECN octet.
    #[inline]
    pub fn dscp_ecn(&self) -> u8 {
        self.bytes[1]
    }
    /// Returns the RFC 791 total-length field.
    #[inline]
    pub fn total_length(&self) -> u16 {
        read_u16(self.bytes, 2)
    }
    /// Returns the identification field.
    #[inline]
    pub fn identification(&self) -> u16 {
        read_u16(self.bytes, 4)
    }
    /// Returns raw flags and fragment offset.
    #[inline]
    pub fn flags_fragment_offset(&self) -> u16 {
        read_u16(self.bytes, 6)
    }
    /// Returns the time-to-live field.
    #[inline]
    pub fn ttl(&self) -> u8 {
        self.bytes[8]
    }
    /// Returns the protocol value, including unknown values.
    #[inline]
    pub fn protocol(&self) -> Ipv4Protocol {
        Ipv4Protocol::new(self.bytes[9])
    }
    /// Returns the encoded header checksum.
    #[inline]
    pub fn header_checksum(&self) -> u16 {
        read_u16(self.bytes, 10)
    }
    /// Returns the source address.
    #[inline]
    pub fn source(&self) -> Ipv4Address {
        Ipv4Address::new(
            self.bytes[12..16]
                .try_into()
                .expect("validated IPv4 header"),
        )
    }
    /// Returns the destination address.
    #[inline]
    pub fn destination(&self) -> Ipv4Address {
        Ipv4Address::new(
            self.bytes[16..20]
                .try_into()
                .expect("validated IPv4 header"),
        )
    }
    /// Returns option bytes included by IHL.
    #[inline]
    pub fn options(&self) -> &[u8] {
        &self.bytes[HEADER..self.header_length]
    }
    /// Returns payload bytes, which are not header-checksum covered.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.bytes[self.header_length..]
    }
    /// Returns mutable options; this does not update the header checksum.
    #[inline]
    pub fn options_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[HEADER..self.header_length]
    }
    /// Returns mutable payload bytes, which are not header-checksum covered.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[self.header_length..]
    }
    /// Returns the represented packet bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
    }
    /// Returns all represented bytes mutably.
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        self.bytes
    }
    /// Replaces DSCP/ECN without updating the checksum.
    #[inline]
    pub fn set_dscp_ecn(&mut self, v: u8) {
        self.bytes[1] = v
    }
    /// Replaces identification without updating the checksum.
    #[inline]
    pub fn set_identification(&mut self, v: u16) {
        write_u16(self.bytes, 4, v)
    }
    /// Replaces raw flags and fragment offset without updating the checksum.
    #[inline]
    pub fn set_flags_fragment_offset(&mut self, v: u16) {
        write_u16(self.bytes, 6, v)
    }
    /// Replaces TTL without updating the checksum.
    #[inline]
    pub fn set_ttl(&mut self, v: u8) {
        self.bytes[8] = v
    }
    /// Replaces protocol without updating the checksum.
    #[inline]
    pub fn set_protocol(&mut self, v: Ipv4Protocol) {
        self.bytes[9] = v.raw()
    }
    /// Replaces the encoded checksum directly.
    #[inline]
    pub fn set_header_checksum(&mut self, v: u16) {
        write_u16(self.bytes, 10, v)
    }
    /// Replaces source without updating the checksum.
    #[inline]
    pub fn set_source(&mut self, v: Ipv4Address) {
        self.bytes[12..16].copy_from_slice(&v.octets())
    }
    /// Replaces destination without updating the checksum.
    #[inline]
    pub fn set_destination(&mut self, v: Ipv4Address) {
        self.bytes[16..20].copy_from_slice(&v.octets())
    }
    /// Recomputes and writes the checksum across the full IHL, including options.
    #[inline]
    pub fn update_header_checksum(&mut self) {
        self.bytes[10] = 0;
        self.bytes[11] = 0;
        write_u16(
            self.bytes,
            10,
            !checksum_sum(&self.bytes[..self.header_length]),
        )
    }
    /// Checks the current checksum across the full IHL.
    #[inline]
    pub fn checksum_is_valid(&self) -> bool {
        checksum_sum(&self.bytes[..self.header_length]) == 0xffff
    }
}
#[inline]
fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("validated IPv4 header"),
    )
}
#[inline]
fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes())
}
#[inline]
pub(super) fn checksum_sum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut offset = 0;
    while offset < bytes.len() {
        sum += u32::from(
            (u16::from(bytes[offset]) << 8) | u16::from(*bytes.get(offset + 1).unwrap_or(&0)),
        );
        offset += 2;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16)
    }
    sum as u16
}
#[inline]
fn validate(bytes: &[u8]) -> Result<(usize, usize), ParseError> {
    if bytes.len() < HEADER {
        return Err(ParseError::Truncated {
            minimum: HEADER,
            available: bytes.len(),
        });
    }
    let version = bytes[0] >> 4;
    if version != 4 {
        return Err(ParseError::InvalidVersion {
            expected: 4,
            actual: version,
        });
    }
    let header_length = usize::from(bytes[0] & 15) * 4;
    if header_length < HEADER {
        return Err(ParseError::InvalidHeaderLength {
            minimum: HEADER,
            actual: header_length,
        });
    }
    if bytes.len() < header_length {
        return Err(ParseError::Truncated {
            minimum: header_length,
            available: bytes.len(),
        });
    }
    let total_length = usize::from(read_u16(bytes, 2));
    if total_length < header_length {
        return Err(ParseError::InvalidTotalLength {
            header_length,
            total_length,
        });
    }
    if bytes.len() < total_length {
        return Err(ParseError::Truncated {
            minimum: total_length,
            available: bytes.len(),
        });
    }
    Ok((header_length, total_length))
}
#[cfg(feature = "ethernet")]
impl<'a> EthernetFrame<'a> {
    /// Parses IPv4 only for the IPv4 EtherType.
    #[inline]
    pub fn ipv4(&self) -> Result<Option<Ipv4Packet<'a>>, ParseError> {
        if self.ether_type() != EtherType::IPV4 {
            return Ok(None);
        }
        Ipv4Packet::parse(self.payload()).map(Some)
    }
}
#[cfg(feature = "ethernet")]
impl<'a> EthernetFrameMut<'a> {
    /// Parses mutable IPv4 only for the IPv4 EtherType.
    #[inline]
    pub fn ipv4_mut(&mut self) -> Result<Option<Ipv4PacketMut<'_>>, ParseError> {
        if self.ether_type() != EtherType::IPV4 {
            return Ok(None);
        }
        Ipv4PacketMut::parse(self.payload_mut()).map(Some)
    }
}
