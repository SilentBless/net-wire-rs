use super::address::Ipv4Address;
use super::packet::{HEADER_LENGTH, Ipv4PacketMut};
use super::protocol::Ipv4Protocol;
use crate::internet_checksum;
use core::fmt;
/// IPv4 builder validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ipv4PacketBuildError {
    /// Source is missing.
    MissingSource,
    /// Destination is missing.
    MissingDestination,
    /// Protocol is missing.
    MissingProtocol,
    /// TTL is missing.
    MissingTtl,
    /// Options are invalid.
    InvalidOptionsLength,
    /// Total length exceeds 65535.
    TotalLengthTooLarge,
    /// Reserved flag is set.
    ReservedFlagSet,
    /// Buffer capacity is insufficient.
    BufferTooShort {
        /// Required bytes.
        required: usize,
        /// Available bytes.
        available: usize,
    },
}
impl fmt::Display for Ipv4PacketBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSource => f.write_str("missing IPv4 source address"),
            Self::MissingDestination => f.write_str("missing IPv4 destination address"),
            Self::MissingProtocol => f.write_str("missing IPv4 protocol"),
            Self::MissingTtl => f.write_str("missing IPv4 TTL"),
            Self::InvalidOptionsLength => {
                f.write_str("IPv4 options length must be a multiple of four and at most 40")
            }
            Self::TotalLengthTooLarge => f.write_str("IPv4 total length exceeds 65535"),
            Self::ReservedFlagSet => f.write_str("IPv4 reserved flag bit is set"),
            Self::BufferTooShort {
                required,
                available,
            } => write!(
                f,
                "IPv4 buffer is too short: need {required} bytes, have {available}"
            ),
        }
    }
}
/// Caller-buffer IPv4 builder.
pub struct Ipv4PacketBuilder<'buffer, 'input> {
    buffer: &'buffer mut [u8],
    payload: usize,
    source: Option<Ipv4Address>,
    destination: Option<Ipv4Address>,
    protocol: Option<Ipv4Protocol>,
    ttl: Option<u8>,
    identification: u16,
    flags: u16,
    dscp: u8,
    options: &'input [u8],
}
impl<'buffer, 'input> Ipv4PacketBuilder<'buffer, 'input> {
    /// Starts a builder with untouched payload bytes.
    #[inline]
    pub fn new(buffer: &'buffer mut [u8], payload: usize) -> Self {
        Self {
            buffer,
            payload,
            source: None,
            destination: None,
            protocol: None,
            ttl: None,
            identification: 0,
            flags: 0,
            dscp: 0,
            options: &[],
        }
    }
    /// Supplies source.
    #[inline]
    pub fn source(mut self, v: Ipv4Address) -> Self {
        self.source = Some(v);
        self
    }
    /// Supplies destination.
    #[inline]
    pub fn destination(mut self, v: Ipv4Address) -> Self {
        self.destination = Some(v);
        self
    }
    /// Supplies protocol.
    #[inline]
    pub fn protocol(mut self, v: Ipv4Protocol) -> Self {
        self.protocol = Some(v);
        self
    }
    /// Supplies TTL.
    #[inline]
    pub fn ttl(mut self, v: u8) -> Self {
        self.ttl = Some(v);
        self
    }
    /// Supplies identification.
    #[inline]
    pub fn identification(mut self, v: u16) -> Self {
        self.identification = v;
        self
    }
    /// Supplies flags and offset.
    #[inline]
    pub fn flags_fragment_offset(mut self, v: u16) -> Self {
        self.flags = v;
        self
    }
    /// Supplies DSCP/ECN.
    #[inline]
    pub fn dscp_ecn(mut self, v: u8) -> Self {
        self.dscp = v;
        self
    }
    /// Supplies copied options.
    #[inline]
    pub fn options(mut self, v: &'input [u8]) -> Self {
        self.options = v;
        self
    }
    /// Validates before all writes, writes/header-checksums only the header, and preserves payload and trailing capacity.
    #[inline]
    pub fn build(self) -> Result<Ipv4PacketMut<'buffer>, Ipv4PacketBuildError> {
        let source = self.source.ok_or(Ipv4PacketBuildError::MissingSource)?;
        let destination = self
            .destination
            .ok_or(Ipv4PacketBuildError::MissingDestination)?;
        let protocol = self.protocol.ok_or(Ipv4PacketBuildError::MissingProtocol)?;
        let ttl = self.ttl.ok_or(Ipv4PacketBuildError::MissingTtl)?;
        if self.flags & 0x8000 != 0 {
            return Err(Ipv4PacketBuildError::ReservedFlagSet);
        }
        if self.options.len() > 40 || !self.options.len().is_multiple_of(4) {
            return Err(Ipv4PacketBuildError::InvalidOptionsLength);
        }
        let header = HEADER_LENGTH + self.options.len();
        let total = header
            .checked_add(self.payload)
            .ok_or(Ipv4PacketBuildError::TotalLengthTooLarge)?;
        if total > u16::MAX as usize {
            return Err(Ipv4PacketBuildError::TotalLengthTooLarge);
        }
        if self.buffer.len() < total {
            return Err(Ipv4PacketBuildError::BufferTooShort {
                required: total,
                available: self.buffer.len(),
            });
        }
        let b = &mut self.buffer[..total];
        b[0] = 0x40 | ((header / 4) as u8);
        b[1] = self.dscp;
        b[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        b[4..6].copy_from_slice(&self.identification.to_be_bytes());
        b[6..8].copy_from_slice(&self.flags.to_be_bytes());
        b[8] = ttl;
        b[9] = protocol.raw();
        b[10] = 0;
        b[11] = 0;
        b[12..16].copy_from_slice(&source.octets());
        b[16..20].copy_from_slice(&destination.octets());
        b[HEADER_LENGTH..header].copy_from_slice(self.options);
        let checksum = !internet_checksum::sum(&b[..header]);
        b[10..12].copy_from_slice(&checksum.to_be_bytes());
        Ok(Ipv4PacketMut::from_validated(b, header))
    }
}
