//! RFC 9000 section 18 QUIC transport-parameter sequence parsing.

mod semantic;
mod value;

use core::{fmt, iter::FusedIterator};

use super::varint::{QuicVarInt, QuicVarIntParseError};
#[cfg(feature = "tls")]
use crate::tls::extensions::extension::TlsExtension;
#[cfg(feature = "tls")]
use crate::tls::types::TlsExtensionType;

pub use semantic::{
    QuicTransportParameterHandshakeContext, QuicTransportParameterHandshakeError,
    QuicTransportParameterSemanticError, QuicTransportParameterSender, QuicTransportParametersV1,
};
pub use value::{
    QuicPreferredAddress, QuicTransportParameterValueError, QuicTransportParameterValueKind,
};

/// A raw QUIC transport-parameter identifier, preserving unknown and reserved values.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct QuicTransportParameterId(u64);

impl QuicTransportParameterId {
    /// The original-destination-connection-ID parameter (`0x00`).
    pub const ORIGINAL_DESTINATION_CONNECTION_ID: Self = Self(0x00);
    /// The maximum-idle-timeout parameter (`0x01`).
    pub const MAX_IDLE_TIMEOUT: Self = Self(0x01);
    /// The stateless-reset-token parameter (`0x02`).
    pub const STATELESS_RESET_TOKEN: Self = Self(0x02);
    /// The maximum-UDP-payload-size parameter (`0x03`).
    pub const MAX_UDP_PAYLOAD_SIZE: Self = Self(0x03);
    /// The initial-maximum-data parameter (`0x04`).
    pub const INITIAL_MAX_DATA: Self = Self(0x04);
    /// The initial-maximum-stream-data-bidi-local parameter (`0x05`).
    pub const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: Self = Self(0x05);
    /// The initial-maximum-stream-data-bidi-remote parameter (`0x06`).
    pub const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: Self = Self(0x06);
    /// The initial-maximum-stream-data-uni parameter (`0x07`).
    pub const INITIAL_MAX_STREAM_DATA_UNI: Self = Self(0x07);
    /// The initial-maximum-streams-bidi parameter (`0x08`).
    pub const INITIAL_MAX_STREAMS_BIDI: Self = Self(0x08);
    /// The initial-maximum-streams-uni parameter (`0x09`).
    pub const INITIAL_MAX_STREAMS_UNI: Self = Self(0x09);
    /// The acknowledgment-delay-exponent parameter (`0x0a`).
    pub const ACK_DELAY_EXPONENT: Self = Self(0x0a);
    /// The maximum-acknowledgment-delay parameter (`0x0b`).
    pub const MAX_ACK_DELAY: Self = Self(0x0b);
    /// The disable-active-migration parameter (`0x0c`).
    pub const DISABLE_ACTIVE_MIGRATION: Self = Self(0x0c);
    /// The preferred-address parameter (`0x0d`).
    pub const PREFERRED_ADDRESS: Self = Self(0x0d);
    /// The active-connection-ID-limit parameter (`0x0e`).
    pub const ACTIVE_CONNECTION_ID_LIMIT: Self = Self(0x0e);
    /// The initial-source-connection-ID parameter (`0x0f`).
    pub const INITIAL_SOURCE_CONNECTION_ID: Self = Self(0x0f);
    /// The retry-source-connection-ID parameter (`0x10`).
    pub const RETRY_SOURCE_CONNECTION_ID: Self = Self(0x10);

    /// Creates an identifier from its decoded wire value.
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the decoded wire value.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Returns whether this identifier has RFC 9000's reserved `31 * N + 27` form.
    pub const fn is_reserved(self) -> bool {
        self.0 % 31 == 27
    }
}

/// Identifies a transport-parameter tuple field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicTransportParameterField {
    /// The tuple's parameter-ID variable integer.
    Id,
    /// The tuple's parameter-length variable integer.
    Length,
    /// The tuple's opaque parameter-value bytes.
    Value,
}

/// Failure to parse a QUIC transport-parameter extension payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicTransportParameterParseError {
    /// A tuple variable integer is incomplete.
    IncompleteVarInt {
        /// Tuple field whose variable integer is incomplete.
        field: QuicTransportParameterField,
        /// Absolute field offset from the extension-payload start.
        offset: usize,
        /// Exact variable-integer parsing failure.
        error: QuicVarIntParseError,
    },
    /// A decoded parameter length cannot be represented as `usize` on this target.
    LengthNotRepresentable {
        /// Absolute length-field offset from the extension-payload start.
        offset: usize,
        /// Decoded wire length.
        value: u64,
    },
    /// Computing a parameter-value end offset overflows `usize`.
    LengthOverflow {
        /// Absolute value offset from the extension-payload start.
        offset: usize,
        /// Representable decoded parameter length.
        length: usize,
    },
    /// A parameter value is incomplete.
    IncompleteValue {
        /// Absolute value offset from the extension-payload start.
        offset: usize,
        /// Bytes required by the value.
        required: usize,
        /// Bytes available for the value.
        available: usize,
    },
    /// A parameter identifier occurs more than once.
    DuplicateId {
        /// Repeated decoded parameter identifier.
        id: QuicTransportParameterId,
        /// Absolute tuple offset of the first occurrence.
        first_offset: usize,
        /// Absolute tuple offset of the duplicate occurrence.
        duplicate_offset: usize,
    },
}

impl fmt::Display for QuicTransportParameterParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompleteVarInt {
                field,
                offset,
                error,
            } => write!(
                f,
                "QUIC transport parameter {field:?} at offset {offset} cannot be parsed: {error}"
            ),
            Self::LengthNotRepresentable { offset, value } => write!(
                f,
                "QUIC transport parameter length at offset {offset} has unrepresentable value {value}"
            ),
            Self::LengthOverflow { offset, length } => write!(
                f,
                "QUIC transport parameter value at offset {offset} overflows with length {length}"
            ),
            Self::IncompleteValue {
                offset,
                required,
                available,
            } => write!(
                f,
                "QUIC transport parameter value at offset {offset} is incomplete: need {required} bytes, have {available}"
            ),
            Self::DuplicateId {
                id,
                first_offset,
                duplicate_offset,
            } => write!(
                f,
                "QUIC transport parameter ID {} is duplicated at offset {duplicate_offset}; first occurred at offset {first_offset}",
                id.raw()
            ),
        }
    }
}

/// Failure to interpret a TLS extension as RFC 9001 QUIC transport parameters.
#[cfg(feature = "tls")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicTransportParametersTlsExtensionError {
    /// The TLS extension has a type other than `quic_transport_parameters`.
    WrongExtensionType {
        /// Exact type carried by the TLS extension.
        actual: TlsExtensionType,
    },
    /// The extension payload is not a valid QUIC transport-parameter sequence.
    Parse(QuicTransportParameterParseError),
}

#[cfg(feature = "tls")]
impl fmt::Display for QuicTransportParametersTlsExtensionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongExtensionType { actual } => write!(
                f,
                "TLS extension type {} is not QUIC transport parameters",
                actual.raw()
            ),
            Self::Parse(error) => {
                write!(f, "TLS QUIC transport parameters cannot be parsed: {error}")
            }
        }
    }
}

/// A checked borrowed QUIC transport-parameter tuple.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicTransportParameter<'a> {
    bytes: &'a [u8],
    id: QuicVarInt<'a>,
    length: QuicVarInt<'a>,
    value: &'a [u8],
}

impl<'a> QuicTransportParameter<'a> {
    /// Returns the exact encoded tuple bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the exact encoded parameter-ID variable integer.
    pub const fn id(self) -> QuicVarInt<'a> {
        self.id
    }

    /// Returns the decoded parameter identifier.
    pub const fn parameter_id(self) -> QuicTransportParameterId {
        QuicTransportParameterId::new(self.id.value())
    }

    /// Returns the exact encoded parameter-length variable integer.
    pub const fn length(self) -> QuicVarInt<'a> {
        self.length
    }

    /// Returns the exact opaque parameter-value bytes, which may be empty.
    pub const fn value(self) -> &'a [u8] {
        self.value
    }
}

/// A complete validated borrowed QUIC transport-parameter extension payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicTransportParameters<'a> {
    bytes: &'a [u8],
}

impl<'a> QuicTransportParameters<'a> {
    /// Parses and validates a complete transport-parameter extension payload.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, QuicTransportParameterParseError> {
        let mut remaining = bytes;
        let mut offset = 0;
        while !remaining.is_empty() {
            let (parameter, suffix) = parse_at(remaining, offset)?;
            if let Some(first_offset) = first_id_offset(bytes, offset, parameter.parameter_id()) {
                return Err(QuicTransportParameterParseError::DuplicateId {
                    id: parameter.parameter_id(),
                    first_offset,
                    duplicate_offset: offset,
                });
            }
            let consumed = parameter.as_bytes().len();
            remaining = suffix;
            offset += consumed;
        }
        Ok(Self { bytes })
    }

    /// Validates all present known parameters against RFC 9000 version-1 role and value rules.
    pub fn validate_v1(
        self,
        sender: QuicTransportParameterSender,
    ) -> Result<QuicTransportParametersV1<'a>, QuicTransportParameterSemanticError> {
        semantic::validate(self.bytes, sender)
    }

    /// Returns the exact complete extension-payload bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns a fresh iterator over this already validated extension payload.
    pub const fn iter(self) -> QuicTransportParameterIter<'a> {
        QuicTransportParameterIter::new(self.bytes)
    }
}

#[cfg(feature = "tls")]
impl<'a> TlsExtension<'a> {
    /// Parses this RFC 9001 QUIC transport-parameters extension payload.
    ///
    /// RFC 9001 permits this extension in ClientHello and EncryptedExtensions and requires it
    /// in both. Callers that own the parent handshake-message context enforce its placement and
    /// presence; this accessor parses only the extension payload.
    pub fn quic_transport_parameters(
        &self,
    ) -> Result<QuicTransportParameters<'a>, QuicTransportParametersTlsExtensionError> {
        if self.extension_type() != TlsExtensionType::QUIC_TRANSPORT_PARAMETERS {
            return Err(
                QuicTransportParametersTlsExtensionError::WrongExtensionType {
                    actual: self.extension_type(),
                },
            );
        }
        QuicTransportParameters::parse(self.data())
            .map_err(QuicTransportParametersTlsExtensionError::Parse)
    }
}

/// A fallible fused iterator over a QUIC transport-parameter extension payload.
#[derive(Clone, Debug)]
pub struct QuicTransportParameterIter<'a> {
    remaining: &'a [u8],
    offset: usize,
    failed: bool,
}

impl<'a> QuicTransportParameterIter<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self {
            remaining: bytes,
            offset: 0,
            failed: false,
        }
    }
}

impl<'a> Iterator for QuicTransportParameterIter<'a> {
    type Item = Result<QuicTransportParameter<'a>, QuicTransportParameterParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.remaining.is_empty() {
            return None;
        }

        match parse_at(self.remaining, self.offset) {
            Ok((parameter, suffix)) => {
                let consumed = parameter.as_bytes().len();
                self.remaining = suffix;
                self.offset += consumed;
                Some(Ok(parameter))
            }
            Err(error) => {
                self.failed = true;
                self.remaining = &[];
                Some(Err(error))
            }
        }
    }
}

impl FusedIterator for QuicTransportParameterIter<'_> {}

fn parse_at<'a>(
    bytes: &'a [u8],
    offset: usize,
) -> Result<(QuicTransportParameter<'a>, &'a [u8]), QuicTransportParameterParseError> {
    let id = QuicVarInt::parse(bytes).map_err(|error| {
        QuicTransportParameterParseError::IncompleteVarInt {
            field: QuicTransportParameterField::Id,
            offset,
            error,
        }
    })?;
    let length_start = id.byte_len();
    let length_offset = offset + length_start;
    let length = QuicVarInt::parse(&bytes[length_start..]).map_err(|error| {
        QuicTransportParameterParseError::IncompleteVarInt {
            field: QuicTransportParameterField::Length,
            offset: length_offset,
            error,
        }
    })?;
    let value_start = length_start + length.byte_len();
    let value_offset = offset + value_start;
    let value_length = usize::try_from(length.value()).map_err(|_| {
        QuicTransportParameterParseError::LengthNotRepresentable {
            offset: length_offset,
            value: length.value(),
        }
    })?;
    let value_end = value_start.checked_add(value_length).ok_or(
        QuicTransportParameterParseError::LengthOverflow {
            offset: value_offset,
            length: value_length,
        },
    )?;
    let available = bytes.len() - value_start;
    if available < value_length {
        return Err(QuicTransportParameterParseError::IncompleteValue {
            offset: value_offset,
            required: value_length,
            available,
        });
    }

    Ok((
        QuicTransportParameter {
            bytes: &bytes[..value_end],
            id,
            length,
            value: &bytes[value_start..value_end],
        },
        &bytes[value_end..],
    ))
}

fn first_id_offset(bytes: &[u8], end: usize, id: QuicTransportParameterId) -> Option<usize> {
    let mut remaining = &bytes[..end];
    let mut offset = 0;
    while !remaining.is_empty() {
        let (parameter, suffix) = match parse_at(remaining, offset) {
            Ok(parsed) => parsed,
            Err(_) => return None,
        };
        if parameter.parameter_id() == id {
            return Some(offset);
        }
        offset += parameter.as_bytes().len();
        remaining = suffix;
    }
    None
}
