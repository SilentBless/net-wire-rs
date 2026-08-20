//! Caller-buffer builders for QUIC packets.

use core::fmt;

use super::packet::{
    QuicPacketParseError,
    header::{QuicConnectionIdField, QuicVersion},
};
use super::varint::QuicVarIntBuildError;

mod long;
mod short;
mod terminal;

fn built_prefix_error(error: QuicPacketParseError) -> QuicPacketBuildError {
    match error {
        QuicPacketParseError::EmptyDatagram
        | QuicPacketParseError::ShortHeaderContextRequired
        | QuicPacketParseError::WrongHeaderForm { .. }
        | QuicPacketParseError::Incomplete { .. }
        | QuicPacketParseError::InvalidRepresentation
        | QuicPacketParseError::LengthOverflow { .. }
        | QuicPacketParseError::UnsupportedVersion { .. }
        | QuicPacketParseError::WrongVersion { .. }
        | QuicPacketParseError::EmptyVersionList
        | QuicPacketParseError::MisalignedVersionList { .. }
        | QuicPacketParseError::NotRetry { .. }
        | QuicPacketParseError::EmptyRetryToken
        | QuicPacketParseError::FixedBitNotSet { .. }
        | QuicPacketParseError::ConnectionIdTooLong { .. }
        | QuicPacketParseError::NotLengthDelimited { .. }
        | QuicPacketParseError::LengthNotRepresentable { .. }
        | QuicPacketParseError::ProtectedRemainderTooShort { .. } => {
            QuicPacketBuildError::InvalidRepresentation
        }
    }
}

/// Identifies a QUIC variable-length integer field during packet construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicPacketBuildField {
    /// The Initial packet token-length field.
    TokenLength,
    /// The protected packet-length field.
    ProtectedLength,
}

/// Failure to build a QUIC packet in caller-owned storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicPacketBuildError {
    /// The supplied unused-bit value exceeds the packet form's maximum.
    UnusedBitsOutOfRange {
        /// Greatest permitted unused-bit value.
        maximum: u8,
        /// Supplied unused-bit value.
        actual: u8,
    },
    /// The supplied protected-low-bit value exceeds the maximum permitted value.
    ProtectedLowBitsOutOfRange {
        /// Greatest permitted protected-low-bit value.
        maximum: u8,
        /// Supplied protected-low-bit value.
        actual: u8,
    },
    /// Packet construction supports only QUIC v1 and v2.
    UnsupportedVersion {
        /// Supplied raw version.
        version: QuicVersion,
    },
    /// A connection ID cannot be represented by this packet form.
    ConnectionIdTooLong {
        /// Connection-ID field that is too long.
        field: QuicConnectionIdField,
        /// Greatest permitted byte length.
        maximum: usize,
        /// Supplied byte length.
        actual: usize,
    },
    /// A Version Negotiation packet requires at least one advertised version.
    EmptyVersionList,
    /// A Retry packet requires at least one token byte.
    EmptyRetryToken,
    /// A protected packet remainder is too short to contain a packet number and payload.
    ProtectedRemainderTooShort {
        /// Minimum protected remainder byte length.
        minimum: usize,
        /// Supplied protected remainder byte length.
        actual: usize,
    },
    /// A packet variable-length field cannot represent its requested value or width.
    VarInt {
        /// Field that could not be encoded.
        field: QuicPacketBuildField,
        /// Exact variable-integer construction failure.
        error: QuicVarIntBuildError,
    },
    /// Packet-size arithmetic cannot represent an intermediate total.
    LengthOverflow {
        /// Named packet-size component being added.
        component: &'static str,
        /// Accumulated byte length before adding the component.
        offset: usize,
        /// Component byte length.
        length: usize,
    },
    /// The generated invariant-prefix representation could not encode validated inputs.
    InvalidRepresentation,
    /// The caller buffer cannot contain the complete packet.
    BufferTooShort {
        /// Complete packet byte length required.
        required: usize,
        /// Bytes available in the caller buffer.
        available: usize,
    },
}

impl fmt::Display for QuicPacketBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnusedBitsOutOfRange { maximum, actual } => write!(
                f,
                "QUIC unused bits value {actual:#04x} exceeds maximum {maximum:#04x}"
            ),
            Self::ProtectedLowBitsOutOfRange { maximum, actual } => write!(
                f,
                "QUIC protected low bits value {actual:#04x} exceeds maximum {maximum:#04x}"
            ),
            Self::UnsupportedVersion { version } => write!(
                f,
                "QUIC packet construction does not support version {:#010x}",
                version.raw()
            ),
            Self::ConnectionIdTooLong {
                field,
                maximum,
                actual,
            } => write!(
                f,
                "QUIC {field:?} connection ID length {actual} exceeds maximum {maximum}"
            ),
            Self::EmptyVersionList => write!(
                f,
                "QUIC Version Negotiation construction requires a nonempty version list"
            ),
            Self::EmptyRetryToken => {
                write!(f, "QUIC Retry construction requires a nonempty Retry Token")
            }
            Self::ProtectedRemainderTooShort { minimum, actual } => write!(
                f,
                "QUIC protected packet remainder is too short: need at least {minimum} bytes, have {actual}"
            ),
            Self::VarInt { field, error } => {
                write!(f, "QUIC {field:?} field cannot be encoded: {error}")
            }
            Self::LengthOverflow {
                component,
                offset,
                length,
            } => write!(
                f,
                "QUIC packet size overflows while adding {component}: offset {offset} plus length {length}"
            ),
            Self::InvalidRepresentation => {
                f.write_str("validated QUIC invariant prefix could not be represented")
            }
            Self::BufferTooShort {
                required,
                available,
            } => write!(
                f,
                "QUIC packet destination is too short: need {required} bytes, have {available}"
            ),
        }
    }
}

pub use long::{QuicHandshakePacketBuilder, QuicInitialPacketBuilder, QuicZeroRttPacketBuilder};
pub use short::QuicShortPacketBuilder;
pub use terminal::{QuicRetryPacketBuilder, QuicVersionNegotiationPacketBuilder};
