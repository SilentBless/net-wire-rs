//! QUIC packet-view parsing errors.

use core::fmt;

use super::header::{QuicConnectionIdField, QuicLongPacketType, QuicVersion};

/// Failure to parse a QUIC packet-header view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicPacketParseError {
    /// A supplied UDP datagram contains no packet bytes.
    EmptyDatagram,
    /// A short-header packet cannot be delimited without caller-supplied destination ID context.
    ShortHeaderContextRequired,
    /// The first byte has the opposite QUIC header form from the requested view.
    WrongHeaderForm {
        /// Whether the requested view requires the long-header form bit to be set.
        expected_long: bool,
        /// The observed first byte.
        first_byte: u8,
    },
    /// The input does not contain all bytes structurally required by the view.
    Incomplete {
        /// Absolute byte count required from the start of the supplied input.
        required: usize,
        /// Bytes available in the supplied input.
        available: usize,
    },
    /// A caller-supplied length cannot be represented when locating a field.
    LengthOverflow {
        /// Offset before adding the supplied length.
        offset: usize,
        /// Length that could not be added to the offset.
        length: usize,
    },
    /// A version-specific packet view does not define semantics for this QUIC version.
    UnsupportedVersion {
        /// The raw unsupported version.
        version: QuicVersion,
    },
    /// A terminal packet was parsed by a view requiring a different exact version.
    WrongVersion {
        /// The observed raw version.
        version: QuicVersion,
    },
    /// A Version Negotiation packet has no advertised versions after its invariant prefix.
    EmptyVersionList,
    /// A Version Negotiation version list does not contain a whole number of four-byte versions.
    MisalignedVersionList {
        /// The observed version-list byte length.
        length: usize,
    },
    /// A supported-version terminal packet is not a Retry packet.
    NotRetry {
        /// The observed semantic packet type.
        packet_type: QuicLongPacketType,
    },
    /// A Retry packet has an integrity tag but no Retry Token bytes.
    EmptyRetryToken,
    /// A supported-version long header has its required fixed bit cleared.
    FixedBitNotSet {
        /// The observed first byte.
        first_byte: u8,
    },
    /// A supported-version connection ID exceeds its 20-byte limit.
    ConnectionIdTooLong {
        /// The overlong connection-ID field.
        field: QuicConnectionIdField,
        /// The observed byte length.
        length: usize,
    },
    /// The packet type is terminal rather than length-delimited.
    NotLengthDelimited {
        /// The terminal semantic packet type.
        packet_type: QuicLongPacketType,
    },
    /// A decoded length cannot be represented as `usize` on this target.
    LengthNotRepresentable {
        /// The decoded wire value.
        value: u64,
    },
    /// A protected packet length is too short to contain a packet number and payload.
    ProtectedRemainderTooShort {
        /// Minimum protected remainder byte length.
        minimum: u64,
        /// Decoded protected remainder byte length.
        actual: u64,
    },
}

impl fmt::Display for QuicPacketParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyDatagram => write!(f, "QUIC UDP datagram is empty"),
            Self::ShortHeaderContextRequired => write!(
                f,
                "QUIC short-header packet requires destination connection-ID length context"
            ),
            Self::WrongHeaderForm {
                expected_long,
                first_byte,
            } => {
                let expected = if *expected_long { "long" } else { "short" };
                write!(
                    f,
                    "QUIC {expected} header view received first byte {first_byte:#04x} with the wrong header form"
                )
            }
            Self::Incomplete {
                required,
                available,
            } => write!(
                f,
                "QUIC packet input is incomplete: need {required} bytes, have {available}"
            ),
            Self::LengthOverflow { offset, length } => write!(
                f,
                "QUIC packet field end cannot be represented: offset {offset} plus length {length} overflows usize"
            ),
            Self::UnsupportedVersion { version } => write!(
                f,
                "QUIC version-specific long-packet semantics are unsupported for version {:#010x}",
                version.raw()
            ),
            Self::WrongVersion { version } => write!(
                f,
                "QUIC terminal packet view requires a different version than {:#010x}",
                version.raw()
            ),
            Self::EmptyVersionList => write!(
                f,
                "QUIC Version Negotiation packet has an empty version list"
            ),
            Self::MisalignedVersionList { length } => write!(
                f,
                "QUIC Version Negotiation version list has invalid byte length {length}; expected a nonzero multiple of 4"
            ),
            Self::NotRetry { packet_type } => {
                write!(f, "QUIC terminal packet is {packet_type:?}, not Retry")
            }
            Self::EmptyRetryToken => write!(f, "QUIC Retry packet has an empty Retry Token"),
            Self::FixedBitNotSet { first_byte } => write!(
                f,
                "QUIC supported-version long packet has fixed bit clear in first byte {first_byte:#04x}"
            ),
            Self::ConnectionIdTooLong { field, length } => write!(
                f,
                "QUIC {field:?} connection ID has invalid length {length}; supported versions permit at most 20 bytes"
            ),
            Self::NotLengthDelimited { packet_type } => write!(
                f,
                "QUIC {packet_type:?} packet is terminal and not length-delimited"
            ),
            Self::LengthNotRepresentable { value } => write!(
                f,
                "QUIC wire length {value} cannot be represented as usize on this target"
            ),
            Self::ProtectedRemainderTooShort { minimum, actual } => write!(
                f,
                "QUIC protected packet length is too short: need at least {minimum} bytes, have {actual}"
            ),
        }
    }
}
