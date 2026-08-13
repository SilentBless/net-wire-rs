//! IPv4 packet views and header-checksum handling (RFC 791).

use super::address::Ipv4Address;
use super::layout::Ipv4FixedHeaderView;
use super::protocol::Ipv4Protocol;
use crate::{error::ParseError, internet_checksum};

pub(super) const HEADER_LENGTH: usize = 20;

/// A structurally validated immutable RFC 791 packet view.
///
/// Parsing validates version, IHL, and declared total length, then excludes trailing capture
/// bytes. It deliberately accepts bad checksums and reserved flags for capture/offload and
/// malformed-packet inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4Packet<'a> {
    bytes: &'a [u8],
    fixed_header: Ipv4FixedHeaderView<'a>,
    header_length: usize,
}

impl<'a> Ipv4Packet<'a> {
    /// Validates RFC 791 structural bounds; use `checksum_is_valid` for checksum acceptance.
    #[inline]
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let (fixed_header, header_length, total_length) = validate(bytes)?;
        Ok(Self {
            bytes: &bytes[..total_length],
            fixed_header,
            header_length,
        })
    }

    /// Returns the combined DSCP/ECN octet.
    #[inline]
    pub fn dscp_ecn(&self) -> u8 {
        self.fixed_header.dscp_ecn()
    }

    /// Returns the RFC 791 total-length field.
    #[inline]
    pub fn total_length(&self) -> u16 {
        self.fixed_header.total_length()
    }

    /// Returns the identification field.
    #[inline]
    pub fn identification(&self) -> u16 {
        self.fixed_header.identification()
    }

    /// Returns the raw flags and fragment-offset field, including the reserved flag.
    #[inline]
    pub fn flags_fragment_offset(&self) -> u16 {
        self.fixed_header.flags_fragment_offset()
    }

    /// Returns the time-to-live field.
    #[inline]
    pub fn ttl(&self) -> u8 {
        self.fixed_header.ttl()
    }

    /// Returns the protocol field while preserving unknown values.
    #[inline]
    pub fn protocol(&self) -> Ipv4Protocol {
        Ipv4Protocol::new(self.fixed_header.protocol())
    }

    /// Returns the encoded RFC 791 header checksum.
    #[inline]
    pub fn header_checksum(&self) -> u16 {
        self.fixed_header.header_checksum()
    }

    /// Returns the source address.
    #[inline]
    pub fn source(&self) -> Ipv4Address {
        let octets = self.fixed_header.source();
        Ipv4Address::new([octets[0], octets[1], octets[2], octets[3]])
    }

    /// Returns the destination address.
    #[inline]
    pub fn destination(&self) -> Ipv4Address {
        let octets = self.fixed_header.destination();
        Ipv4Address::new([octets[0], octets[1], octets[2], octets[3]])
    }

    /// Returns RFC 791 option bytes included by IHL.
    #[inline]
    pub fn options(&self) -> &'a [u8] {
        &self.bytes[HEADER_LENGTH..self.header_length]
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
        internet_checksum::sum(&self.bytes[..self.header_length]) == 0xffff
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
        let (_, header_length, total_length) = validate(bytes)?;
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
        u16::from_be_bytes([self.bytes[2], self.bytes[3]])
    }
    /// Returns the identification field.
    #[inline]
    pub fn identification(&self) -> u16 {
        u16::from_be_bytes([self.bytes[4], self.bytes[5]])
    }
    /// Returns raw flags and fragment offset.
    #[inline]
    pub fn flags_fragment_offset(&self) -> u16 {
        u16::from_be_bytes([self.bytes[6], self.bytes[7]])
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
        u16::from_be_bytes([self.bytes[10], self.bytes[11]])
    }
    /// Returns the source address.
    #[inline]
    pub fn source(&self) -> Ipv4Address {
        Ipv4Address::new([
            self.bytes[12],
            self.bytes[13],
            self.bytes[14],
            self.bytes[15],
        ])
    }
    /// Returns the destination address.
    #[inline]
    pub fn destination(&self) -> Ipv4Address {
        Ipv4Address::new([
            self.bytes[16],
            self.bytes[17],
            self.bytes[18],
            self.bytes[19],
        ])
    }
    /// Returns option bytes included by IHL.
    #[inline]
    pub fn options(&self) -> &[u8] {
        &self.bytes[HEADER_LENGTH..self.header_length]
    }
    /// Returns payload bytes, which are not header-checksum covered.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.bytes[self.header_length..]
    }
    /// Returns mutable options; this does not update the header checksum.
    #[inline]
    pub fn options_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[HEADER_LENGTH..self.header_length]
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
    pub fn set_dscp_ecn(&mut self, value: u8) {
        self.bytes[1] = value;
    }
    /// Replaces identification without updating the checksum.
    #[inline]
    pub fn set_identification(&mut self, value: u16) {
        self.bytes[4..6].copy_from_slice(&value.to_be_bytes());
    }
    /// Replaces raw flags and fragment offset without updating the checksum.
    #[inline]
    pub fn set_flags_fragment_offset(&mut self, value: u16) {
        self.bytes[6..8].copy_from_slice(&value.to_be_bytes());
    }
    /// Replaces TTL without updating the checksum.
    #[inline]
    pub fn set_ttl(&mut self, value: u8) {
        self.bytes[8] = value;
    }
    /// Replaces protocol without updating the checksum.
    #[inline]
    pub fn set_protocol(&mut self, value: Ipv4Protocol) {
        self.bytes[9] = value.raw();
    }
    /// Replaces the encoded checksum directly.
    #[inline]
    pub fn set_header_checksum(&mut self, value: u16) {
        self.bytes[10..12].copy_from_slice(&value.to_be_bytes());
    }
    /// Replaces source without updating the checksum.
    #[inline]
    pub fn set_source(&mut self, value: Ipv4Address) {
        self.bytes[12..16].copy_from_slice(&value.octets());
    }
    /// Replaces destination without updating the checksum.
    #[inline]
    pub fn set_destination(&mut self, value: Ipv4Address) {
        self.bytes[16..20].copy_from_slice(&value.octets());
    }
    /// Recomputes and writes the checksum across the full IHL, including options.
    #[inline]
    pub fn update_header_checksum(&mut self) {
        self.set_header_checksum(0);
        self.set_header_checksum(!internet_checksum::sum(&self.bytes[..self.header_length]));
    }
    /// Checks the current checksum across the full IHL.
    #[inline]
    pub fn checksum_is_valid(&self) -> bool {
        internet_checksum::sum(&self.bytes[..self.header_length]) == 0xffff
    }
}

#[inline]
fn validate(bytes: &[u8]) -> Result<(Ipv4FixedHeaderView<'_>, usize, usize), ParseError> {
    if bytes.len() < HEADER_LENGTH {
        return Err(ParseError::Truncated {
            minimum: HEADER_LENGTH,
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
    if header_length < HEADER_LENGTH {
        return Err(ParseError::InvalidHeaderLength {
            minimum: HEADER_LENGTH,
            actual: header_length,
        });
    }
    if bytes.len() < header_length {
        return Err(ParseError::Truncated {
            minimum: header_length,
            available: bytes.len(),
        });
    }
    let fixed_header = Ipv4FixedHeaderView::parse_exact(&bytes[..HEADER_LENGTH]).map_err(|_| {
        ParseError::Truncated {
            minimum: HEADER_LENGTH,
            available: bytes.len(),
        }
    })?;
    let total_length = usize::from(fixed_header.total_length());
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
    Ok((fixed_header, header_length, total_length))
}
