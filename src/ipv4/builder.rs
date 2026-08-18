use super::address::Ipv4Address;
use super::layout::{Ipv4AddressRepr, Ipv4PacketLayoutBuilder, Ipv4PacketLayoutWriteError};
use super::packet::{HEADER_LENGTH, Ipv4PacketMut};
use super::protocol::Ipv4Protocol;
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
    /// A field value could not be encoded at its required wire width.
    InvalidFieldEncoding {
        /// The field whose encoding was invalid.
        field: &'static str,
        /// The required fixed width.
        expected: usize,
        /// The encoded width that was produced.
        actual: usize,
    },
    /// The validated packet could not be represented by the IPv4 layout.
    InvalidRepresentation,
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
            Self::InvalidFieldEncoding {
                field,
                expected,
                actual,
            } => write!(
                f,
                "IPv4 field {field} encoding: expected {expected} bytes, got {actual}"
            ),
            Self::InvalidRepresentation => {
                f.write_str("validated IPv4 packet could not be represented")
            }
        }
    }
}
impl core::error::Error for Ipv4PacketBuildError {}

fn representation_error(error: Ipv4PacketLayoutWriteError) -> Ipv4PacketBuildError {
    match error {
        Ipv4PacketLayoutWriteError::FieldVersionIhl(error)
        | Ipv4PacketLayoutWriteError::FieldDscpEcn(error)
        | Ipv4PacketLayoutWriteError::FieldTotalLength(error)
        | Ipv4PacketLayoutWriteError::FieldIdentification(error)
        | Ipv4PacketLayoutWriteError::FieldFlagsFragmentOffset(error)
        | Ipv4PacketLayoutWriteError::FieldTtl(error)
        | Ipv4PacketLayoutWriteError::FieldProtocol(error)
        | Ipv4PacketLayoutWriteError::FieldHeaderChecksum(error)
        | Ipv4PacketLayoutWriteError::FieldSource(error)
        | Ipv4PacketLayoutWriteError::FieldDestination(error) => match error {},
        Ipv4PacketLayoutWriteError::InvalidPlanLength {
            field,
            expected,
            actual,
        } => Ipv4PacketBuildError::InvalidFieldEncoding {
            field,
            expected,
            actual,
        },
        Ipv4PacketLayoutWriteError::MissingContext { .. }
        | Ipv4PacketLayoutWriteError::InvalidCodecWidth { .. }
        | Ipv4PacketLayoutWriteError::InvalidRangeSource { .. }
        | Ipv4PacketLayoutWriteError::ConflictingRangeSources { .. }
        | Ipv4PacketLayoutWriteError::InvalidPrefixPlanLength { .. }
        | Ipv4PacketLayoutWriteError::InvalidLayoutExtent { .. }
        | Ipv4PacketLayoutWriteError::OutputTooShort { .. }
        | Ipv4PacketLayoutWriteError::MissingField { .. } => {
            Ipv4PacketBuildError::InvalidRepresentation
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

        let mut fixed = [0_u8; HEADER_LENGTH];
        let (fixed_view, fixed_suffix) = Ipv4PacketLayoutBuilder::new()
            .version_ihl(0x40 | (header / 4) as u8)
            .dscp_ecn(self.dscp)
            .total_length(total as u16)
            .identification(self.identification)
            .flags_fragment_offset(self.flags)
            .ttl(ttl)
            .protocol(protocol.raw())
            .header_checksum(0)
            .source(Ipv4AddressRepr::from_address(source))
            .destination(Ipv4AddressRepr::from_address(destination))
            .body(&[])
            .build_into(&mut fixed)
            .map_err(representation_error)?;
        if !fixed_suffix.is_empty() || fixed_view.as_bytes().len() != HEADER_LENGTH {
            return Err(Ipv4PacketBuildError::InvalidRepresentation);
        }

        let mut header_plan = [0_u8; 60];
        header_plan[..HEADER_LENGTH].copy_from_slice(fixed_view.as_bytes());
        header_plan[HEADER_LENGTH..header].copy_from_slice(self.options);
        let mut header_view = Ipv4PacketMut::from_exact(&mut header_plan[..header], header)
            .map_err(|_| Ipv4PacketBuildError::InvalidRepresentation)?;
        header_view
            .update_header_checksum()
            .map_err(|error| match error {
                super::packet::Ipv4PacketMutationError::InvalidFieldEncoding {
                    field,
                    expected,
                    actual,
                } => Ipv4PacketBuildError::InvalidFieldEncoding {
                    field,
                    expected,
                    actual,
                },
            })?;
        self.buffer[..header].copy_from_slice(header_view.as_bytes());
        Ipv4PacketMut::from_exact(&mut self.buffer[..total], header)
            .map_err(|_| Ipv4PacketBuildError::InvalidRepresentation)
    }
}
