//! Typed RFC 9000 transport-parameter payload views.

use core::fmt;

use super::super::packet::header::QuicConnectionId;
use super::super::varint::{QuicVarInt, QuicVarIntParseError};
use super::{QuicTransportParameter, QuicTransportParameterId};

/// Identifies an RFC 9000 transport-parameter payload layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicTransportParameterValueKind {
    /// A payload containing exactly one QUIC variable integer.
    Integer,
    /// A payload containing an opaque connection ID.
    ConnectionId,
    /// A payload containing a 16-byte stateless reset token.
    StatelessResetToken,
    /// The empty disable-active-migration payload.
    DisableActiveMigration,
    /// The preferred-address payload.
    PreferredAddress,
}

/// Failure to interpret one raw transport-parameter value as an RFC 9000 payload layout.
///
/// Offsets in preferred-address errors are relative to the parameter value, not to an
/// enclosing extension payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicTransportParameterValueError {
    /// The accessor does not apply to this parameter ID.
    WrongId {
        /// Requested payload layout.
        kind: QuicTransportParameterValueKind,
        /// Actual decoded parameter ID.
        actual: QuicTransportParameterId,
    },
    /// The integer payload is empty or ends before its encoded width.
    MalformedInteger {
        /// Exact variable-integer parsing failure.
        error: QuicVarIntParseError,
    },
    /// Bytes follow an otherwise complete integer payload.
    TrailingIntegerBytes {
        /// Encoded integer length.
        parsed: usize,
        /// Complete payload length.
        available: usize,
    },
    /// A fixed-size payload has the wrong length.
    WrongLength {
        /// Requested payload layout.
        kind: QuicTransportParameterValueKind,
        /// Required exact length.
        expected: usize,
        /// Actual payload length.
        actual: usize,
    },
    /// A connection-ID payload exceeds RFC 9000's version-1 bound.
    ConnectionIdTooLong {
        /// Maximum permitted length.
        maximum: usize,
        /// Actual payload length.
        actual: usize,
    },
    /// The preferred-address connection-ID length is outside `1..=20`.
    PreferredAddressConnectionIdLength {
        /// Encoded connection-ID length.
        actual: u8,
    },
    /// A preferred-address field is incomplete.
    PreferredAddressIncomplete {
        /// Value-relative start offset of the incomplete field.
        offset: usize,
        /// Total value bytes required through this field.
        required: usize,
        /// Available value bytes.
        available: usize,
    },
    /// Bytes follow the complete preferred-address payload.
    PreferredAddressTrailingBytes {
        /// Value-relative offset of the first extra byte.
        offset: usize,
        /// Number of extra bytes.
        available: usize,
    },
}

impl fmt::Display for QuicTransportParameterValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongId { kind, actual } => write!(
                f,
                "QUIC transport parameter ID {} does not have the {kind:?} payload layout",
                actual.raw()
            ),
            Self::MalformedInteger { error } => {
                write!(
                    f,
                    "QUIC transport parameter integer payload cannot be parsed: {error}"
                )
            }
            Self::TrailingIntegerBytes { parsed, available } => write!(
                f,
                "QUIC transport parameter integer payload has trailing bytes: integer uses {parsed} bytes, payload has {available}"
            ),
            Self::WrongLength {
                kind,
                expected,
                actual,
            } => write!(
                f,
                "QUIC transport parameter {kind:?} payload has wrong length: need {expected} bytes, have {actual}"
            ),
            Self::ConnectionIdTooLong { maximum, actual } => write!(
                f,
                "QUIC transport parameter connection ID is too long: maximum {maximum} bytes, have {actual}"
            ),
            Self::PreferredAddressConnectionIdLength { actual } => write!(
                f,
                "QUIC preferred-address connection-ID length is outside 1..=20: {actual}"
            ),
            Self::PreferredAddressIncomplete {
                offset,
                required,
                available,
            } => write!(
                f,
                "QUIC preferred-address value at offset {offset} is incomplete: need {required} bytes, have {available}"
            ),
            Self::PreferredAddressTrailingBytes { offset, available } => write!(
                f,
                "QUIC preferred-address value has {available} trailing bytes at offset {offset}"
            ),
        }
    }
}

/// A checked borrowed RFC 9000 preferred-address payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicPreferredAddress<'a> {
    bytes: &'a [u8],
    ipv4_address: &'a [u8; 4],
    ipv4_port: u16,
    ipv6_address: &'a [u8; 16],
    ipv6_port: u16,
    connection_id: QuicConnectionId<'a>,
    stateless_reset_token: &'a [u8; 16],
}

impl<'a> QuicPreferredAddress<'a> {
    /// Returns the exact complete preferred-address value bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the four raw IPv4 address bytes.
    pub const fn ipv4_address(self) -> &'a [u8; 4] {
        self.ipv4_address
    }

    /// Returns the IPv4 port decoded in network byte order.
    pub const fn ipv4_port(self) -> u16 {
        self.ipv4_port
    }

    /// Returns the sixteen raw IPv6 address bytes.
    pub const fn ipv6_address(self) -> &'a [u8; 16] {
        self.ipv6_address
    }

    /// Returns the IPv6 port decoded in network byte order.
    pub const fn ipv6_port(self) -> u16 {
        self.ipv6_port
    }

    /// Returns the exact preferred-address connection ID.
    pub const fn connection_id(self) -> QuicConnectionId<'a> {
        self.connection_id
    }

    /// Returns the exact 16-byte stateless reset token.
    pub const fn stateless_reset_token(self) -> &'a [u8; 16] {
        self.stateless_reset_token
    }
}

impl<'a> QuicTransportParameter<'a> {
    /// Interprets an RFC 9000 integer-valued parameter while preserving its exact width.
    pub fn integer(self) -> Result<QuicVarInt<'a>, QuicTransportParameterValueError> {
        if !is_integer_id(self.parameter_id()) {
            return Err(wrong_id(
                QuicTransportParameterValueKind::Integer,
                self.parameter_id(),
            ));
        }
        let value = QuicVarInt::parse(self.value)
            .map_err(|error| QuicTransportParameterValueError::MalformedInteger { error })?;
        if value.byte_len() != self.value.len() {
            return Err(QuicTransportParameterValueError::TrailingIntegerBytes {
                parsed: value.byte_len(),
                available: self.value.len(),
            });
        }
        Ok(value)
    }

    /// Interprets an RFC 9000 connection-ID parameter with its version-1 length bound.
    pub fn connection_id(self) -> Result<QuicConnectionId<'a>, QuicTransportParameterValueError> {
        if !is_connection_id_id(self.parameter_id()) {
            return Err(wrong_id(
                QuicTransportParameterValueKind::ConnectionId,
                self.parameter_id(),
            ));
        }
        if self.value.len() > 20 {
            return Err(QuicTransportParameterValueError::ConnectionIdTooLong {
                maximum: 20,
                actual: self.value.len(),
            });
        }
        Ok(QuicConnectionId::new(self.value))
    }

    /// Interprets the stateless-reset-token parameter's exact 16-byte payload.
    pub fn stateless_reset_token(self) -> Result<&'a [u8; 16], QuicTransportParameterValueError> {
        if self.parameter_id() != QuicTransportParameterId::STATELESS_RESET_TOKEN {
            return Err(wrong_id(
                QuicTransportParameterValueKind::StatelessResetToken,
                self.parameter_id(),
            ));
        }
        if self.value.len() != 16 {
            return Err(QuicTransportParameterValueError::WrongLength {
                kind: QuicTransportParameterValueKind::StatelessResetToken,
                expected: 16,
                actual: self.value.len(),
            });
        }
        self.value
            .try_into()
            .map_err(|_| QuicTransportParameterValueError::WrongLength {
                kind: QuicTransportParameterValueKind::StatelessResetToken,
                expected: 16,
                actual: self.value.len(),
            })
    }

    /// Validates the empty disable-active-migration parameter payload.
    pub fn disable_active_migration(self) -> Result<(), QuicTransportParameterValueError> {
        if self.parameter_id() != QuicTransportParameterId::DISABLE_ACTIVE_MIGRATION {
            return Err(wrong_id(
                QuicTransportParameterValueKind::DisableActiveMigration,
                self.parameter_id(),
            ));
        }
        if !self.value.is_empty() {
            return Err(QuicTransportParameterValueError::WrongLength {
                kind: QuicTransportParameterValueKind::DisableActiveMigration,
                expected: 0,
                actual: self.value.len(),
            });
        }
        Ok(())
    }

    /// Interprets the RFC 9000 preferred-address payload without endpoint policy.
    pub fn preferred_address(
        self,
    ) -> Result<QuicPreferredAddress<'a>, QuicTransportParameterValueError> {
        if self.parameter_id() != QuicTransportParameterId::PREFERRED_ADDRESS {
            return Err(wrong_id(
                QuicTransportParameterValueKind::PreferredAddress,
                self.parameter_id(),
            ));
        }
        parse_preferred_address(self.value)
    }
}

fn wrong_id(
    kind: QuicTransportParameterValueKind,
    actual: QuicTransportParameterId,
) -> QuicTransportParameterValueError {
    QuicTransportParameterValueError::WrongId { kind, actual }
}

const fn is_integer_id(id: QuicTransportParameterId) -> bool {
    matches!(
        id.raw(),
        0x01 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07 | 0x08 | 0x09 | 0x0a | 0x0b | 0x0e
    )
}

const fn is_connection_id_id(id: QuicTransportParameterId) -> bool {
    matches!(id.raw(), 0x00 | 0x0f | 0x10)
}

fn preferred_incomplete(
    offset: usize,
    required: usize,
    available: usize,
) -> QuicTransportParameterValueError {
    QuicTransportParameterValueError::PreferredAddressIncomplete {
        offset,
        required,
        available,
    }
}

fn parse_preferred_address<'a>(
    bytes: &'a [u8],
) -> Result<QuicPreferredAddress<'a>, QuicTransportParameterValueError> {
    let available = bytes.len();
    if available < 4 {
        return Err(preferred_incomplete(0, 4, available));
    }
    if available < 6 {
        return Err(preferred_incomplete(4, 6, available));
    }
    if available < 22 {
        return Err(preferred_incomplete(6, 22, available));
    }
    if available < 24 {
        return Err(preferred_incomplete(22, 24, available));
    }
    if available < 25 {
        return Err(preferred_incomplete(24, 25, available));
    }

    let connection_id_len = usize::from(bytes[24]);
    if connection_id_len == 0 || connection_id_len > 20 {
        return Err(
            QuicTransportParameterValueError::PreferredAddressConnectionIdLength {
                actual: bytes[24],
            },
        );
    }
    let connection_id_end = 25 + connection_id_len;
    if available < connection_id_end {
        return Err(preferred_incomplete(25, connection_id_end, available));
    }
    let token_end = connection_id_end + 16;
    if available < token_end {
        return Err(preferred_incomplete(
            connection_id_end,
            token_end,
            available,
        ));
    }
    if available > token_end {
        return Err(
            QuicTransportParameterValueError::PreferredAddressTrailingBytes {
                offset: token_end,
                available: available - token_end,
            },
        );
    }

    let ipv4_address = bytes[..4]
        .try_into()
        .map_err(|_| preferred_incomplete(0, 4, available))?;
    let ipv6_address = bytes[6..22]
        .try_into()
        .map_err(|_| preferred_incomplete(6, 22, available))?;
    let stateless_reset_token = bytes[connection_id_end..token_end]
        .try_into()
        .map_err(|_| preferred_incomplete(connection_id_end, token_end, available))?;
    Ok(QuicPreferredAddress {
        bytes,
        ipv4_address,
        ipv4_port: u16::from_be_bytes([bytes[4], bytes[5]]),
        ipv6_address,
        ipv6_port: u16::from_be_bytes([bytes[22], bytes[23]]),
        connection_id: QuicConnectionId::new(&bytes[25..connection_id_end]),
        stateless_reset_token,
    })
}
