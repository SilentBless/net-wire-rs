//! RFC 9000 version-1 present-value transport-parameter validation.

use core::fmt;

use super::{
    QuicTransportParameter, QuicTransportParameterId, QuicTransportParameterIter,
    QuicTransportParameterParseError, QuicTransportParameterValueError,
};

/// The endpoint that sent a QUIC transport-parameter extension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicTransportParameterSender {
    /// Parameters sent by a client.
    Client,
    /// Parameters sent by a server.
    Server,
}

/// Packet-derived connection IDs used to validate an RFC 9000 handshake transport-parameter set.
///
/// Each ID is from the first Initial packet in the direction named by RFC 9000 section 7.3.
/// For [`Self::Server`], `Some(retry_source_connection_id)` means the client received a Retry;
/// its value is that Retry packet's source connection ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicTransportParameterHandshakeContext<'a> {
    /// Context for transport parameters sent by a client.
    Client {
        /// Source connection ID of the first Initial packet sent by the client.
        initial_source_connection_id: &'a [u8],
    },
    /// Context for transport parameters sent by a server.
    Server {
        /// Source connection ID of the first Initial packet sent by the server.
        initial_source_connection_id: &'a [u8],
        /// Destination connection ID of the first Initial packet received by the server before Retry.
        original_destination_connection_id: &'a [u8],
        /// Source connection ID of the Retry packet received by the client, when one was received.
        retry_source_connection_id: Option<&'a [u8]>,
    },
}

/// Failure to validate RFC 9000 section 7.3 handshake connection-ID consistency.
///
/// Tuple offsets are absolute offsets from the start of the transport-parameter extension payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicTransportParameterHandshakeError {
    /// The packet-derived context does not describe the validated parameter sender.
    SenderContextMismatch {
        /// Sender validated for the transport parameters.
        sender: QuicTransportParameterSender,
        /// Sender required by the supplied context.
        context_sender: QuicTransportParameterSender,
    },
    /// A structurally validated parameter no longer parses during handshake validation.
    Structural {
        /// Exact structural parsing failure.
        error: QuicTransportParameterParseError,
    },
    /// A required connection-ID parameter was absent.
    Missing {
        /// Required parameter identifier.
        id: QuicTransportParameterId,
    },
    /// A connection-ID parameter was present when the packet context prohibits it.
    Unexpected {
        /// Unexpected parameter identifier.
        id: QuicTransportParameterId,
        /// Absolute tuple offset from the extension-payload start.
        offset: usize,
    },
    /// A connection-ID parameter differs from its corresponding packet connection ID.
    ConnectionIdMismatch {
        /// Mismatched parameter identifier.
        id: QuicTransportParameterId,
        /// Absolute tuple offset from the extension-payload start.
        offset: usize,
    },
}

impl fmt::Display for QuicTransportParameterHandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SenderContextMismatch {
                sender,
                context_sender,
            } => write!(
                f,
                "QUIC transport-parameter sender {sender:?} does not match handshake context for {context_sender:?}"
            ),
            Self::Structural { error } => {
                write!(
                    f,
                    "QUIC handshake transport parameters are not structural: {error}"
                )
            }
            Self::Missing { id } => write!(
                f,
                "QUIC handshake transport parameter ID {} is required but missing",
                id.raw()
            ),
            Self::Unexpected { id, offset } => write!(
                f,
                "QUIC handshake transport parameter ID {} at tuple offset {offset} is unexpected",
                id.raw()
            ),
            Self::ConnectionIdMismatch { id, offset } => write!(
                f,
                "QUIC handshake transport parameter ID {} at tuple offset {offset} does not match its packet connection ID",
                id.raw()
            ),
        }
    }
}

/// Failure to validate present RFC 9000 version-1 transport parameters.
///
/// Tuple offsets are absolute offsets from the start of the transport-parameter
/// extension payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicTransportParameterSemanticError {
    /// A structurally validated parameter no longer parses during validation.
    Structural {
        /// Exact structural parsing failure.
        error: QuicTransportParameterParseError,
    },
    /// A known parameter has an invalid RFC 9000 payload layout.
    Value {
        /// Decoded parameter identifier.
        id: QuicTransportParameterId,
        /// Absolute tuple offset from the extension-payload start.
        offset: usize,
        /// Exact typed payload failure.
        error: QuicTransportParameterValueError,
    },
    /// A client sent a parameter reserved for servers.
    ForbiddenSender {
        /// Decoded parameter identifier.
        id: QuicTransportParameterId,
        /// Absolute tuple offset from the extension-payload start.
        offset: usize,
    },
    /// An integer parameter is below its RFC 9000 minimum.
    BelowMinimum {
        /// Decoded parameter identifier.
        id: QuicTransportParameterId,
        /// Absolute tuple offset from the extension-payload start.
        offset: usize,
        /// Decoded integer value.
        value: u64,
        /// Required inclusive minimum.
        minimum: u64,
    },
    /// An integer parameter exceeds its RFC 9000 maximum.
    AboveMaximum {
        /// Decoded parameter identifier.
        id: QuicTransportParameterId,
        /// Absolute tuple offset from the extension-payload start.
        offset: usize,
        /// Decoded integer value.
        value: u64,
        /// Required inclusive maximum.
        maximum: u64,
    },
}

impl fmt::Display for QuicTransportParameterSemanticError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Structural { error } => {
                write!(f, "QUIC transport parameters are not structural: {error}")
            }
            Self::Value { id, offset, error } => write!(
                f,
                "QUIC transport parameter ID {} at tuple offset {offset} has an invalid value: {error}",
                id.raw()
            ),
            Self::ForbiddenSender { id, offset } => write!(
                f,
                "QUIC client transport parameter ID {} at tuple offset {offset} is server-only",
                id.raw()
            ),
            Self::BelowMinimum {
                id,
                offset,
                value,
                minimum,
            } => write!(
                f,
                "QUIC transport parameter ID {} at tuple offset {offset} has value {value}, below minimum {minimum}",
                id.raw()
            ),
            Self::AboveMaximum {
                id,
                offset,
                value,
                maximum,
            } => write!(
                f,
                "QUIC transport parameter ID {} at tuple offset {offset} has value {value}, above maximum {maximum}",
                id.raw()
            ),
        }
    }
}

/// A checked borrowed view of present RFC 9000 version-1 transport parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicTransportParametersV1<'a> {
    bytes: &'a [u8],
    sender: QuicTransportParameterSender,
}

impl<'a> QuicTransportParametersV1<'a> {
    /// Returns the exact complete extension-payload bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the endpoint role used for validation.
    pub const fn sender(self) -> QuicTransportParameterSender {
        self.sender
    }

    /// Returns a fresh iterator over the original raw parameter tuples.
    pub const fn iter(self) -> QuicTransportParameterIter<'a> {
        QuicTransportParameterIter::new(self.bytes)
    }

    /// Validates RFC 9000 section 7.3 connection-ID parameters against packet-derived context.
    ///
    /// This checks only the packet consistency rules that require handshake context; construction
    /// of this type has already validated sender role and present parameter value layouts.
    pub fn validate_handshake(
        self,
        context: QuicTransportParameterHandshakeContext<'_>,
    ) -> Result<(), QuicTransportParameterHandshakeError> {
        let context_sender = match context {
            QuicTransportParameterHandshakeContext::Client { .. } => {
                QuicTransportParameterSender::Client
            }
            QuicTransportParameterHandshakeContext::Server { .. } => {
                QuicTransportParameterSender::Server
            }
        };
        if self.sender != context_sender {
            return Err(
                QuicTransportParameterHandshakeError::SenderContextMismatch {
                    sender: self.sender,
                    context_sender,
                },
            );
        }

        match context {
            QuicTransportParameterHandshakeContext::Client {
                initial_source_connection_id,
            } => validate_client_handshake(self, initial_source_connection_id),
            QuicTransportParameterHandshakeContext::Server {
                initial_source_connection_id,
                original_destination_connection_id,
                retry_source_connection_id,
            } => validate_server_handshake(
                self,
                initial_source_connection_id,
                original_destination_connection_id,
                retry_source_connection_id,
            ),
        }
    }
}

fn validate_client_handshake(
    parameters: QuicTransportParametersV1<'_>,
    initial_source_connection_id: &[u8],
) -> Result<(), QuicTransportParameterHandshakeError> {
    let mut initial_present = false;
    let mut offset = 0;
    for parameter in parameters.iter() {
        let parameter = parameter
            .map_err(|error| QuicTransportParameterHandshakeError::Structural { error })?;
        let id = parameter.parameter_id();
        if id == QuicTransportParameterId::INITIAL_SOURCE_CONNECTION_ID {
            initial_present = true;
            if parameter.value() != initial_source_connection_id {
                return Err(QuicTransportParameterHandshakeError::ConnectionIdMismatch {
                    id,
                    offset,
                });
            }
        }
        offset += parameter.as_bytes().len();
    }
    if !initial_present {
        return Err(QuicTransportParameterHandshakeError::Missing {
            id: QuicTransportParameterId::INITIAL_SOURCE_CONNECTION_ID,
        });
    }
    Ok(())
}

fn validate_server_handshake(
    parameters: QuicTransportParametersV1<'_>,
    initial_source_connection_id: &[u8],
    original_destination_connection_id: &[u8],
    retry_source_connection_id: Option<&[u8]>,
) -> Result<(), QuicTransportParameterHandshakeError> {
    let mut initial_present = false;
    let mut original_present = false;
    let mut retry_present = false;
    let mut offset = 0;
    for parameter in parameters.iter() {
        let parameter = parameter
            .map_err(|error| QuicTransportParameterHandshakeError::Structural { error })?;
        let id = parameter.parameter_id();
        match id {
            QuicTransportParameterId::INITIAL_SOURCE_CONNECTION_ID => {
                initial_present = true;
                if parameter.value() != initial_source_connection_id {
                    return Err(QuicTransportParameterHandshakeError::ConnectionIdMismatch {
                        id,
                        offset,
                    });
                }
            }
            QuicTransportParameterId::ORIGINAL_DESTINATION_CONNECTION_ID => {
                original_present = true;
                if parameter.value() != original_destination_connection_id {
                    return Err(QuicTransportParameterHandshakeError::ConnectionIdMismatch {
                        id,
                        offset,
                    });
                }
            }
            QuicTransportParameterId::RETRY_SOURCE_CONNECTION_ID => {
                let Some(expected) = retry_source_connection_id else {
                    return Err(QuicTransportParameterHandshakeError::Unexpected { id, offset });
                };
                retry_present = true;
                if parameter.value() != expected {
                    return Err(QuicTransportParameterHandshakeError::ConnectionIdMismatch {
                        id,
                        offset,
                    });
                }
            }
            _ => {}
        }
        offset += parameter.as_bytes().len();
    }
    if !initial_present {
        return Err(QuicTransportParameterHandshakeError::Missing {
            id: QuicTransportParameterId::INITIAL_SOURCE_CONNECTION_ID,
        });
    }
    if !original_present {
        return Err(QuicTransportParameterHandshakeError::Missing {
            id: QuicTransportParameterId::ORIGINAL_DESTINATION_CONNECTION_ID,
        });
    }
    if retry_source_connection_id.is_some() && !retry_present {
        return Err(QuicTransportParameterHandshakeError::Missing {
            id: QuicTransportParameterId::RETRY_SOURCE_CONNECTION_ID,
        });
    }
    Ok(())
}

pub(super) fn validate<'a>(
    bytes: &'a [u8],
    sender: QuicTransportParameterSender,
) -> Result<QuicTransportParametersV1<'a>, QuicTransportParameterSemanticError> {
    let mut offset = 0;
    let parameters = QuicTransportParameterIter::new(bytes);
    for parameter in parameters {
        let parameter =
            parameter.map_err(|error| QuicTransportParameterSemanticError::Structural { error })?;
        validate_parameter(parameter, sender, offset)?;
        offset += parameter.as_bytes().len();
    }
    Ok(QuicTransportParametersV1 { bytes, sender })
}

fn validate_parameter(
    parameter: QuicTransportParameter<'_>,
    sender: QuicTransportParameterSender,
    offset: usize,
) -> Result<(), QuicTransportParameterSemanticError> {
    let id = parameter.parameter_id();
    if sender == QuicTransportParameterSender::Client && is_server_only(id) {
        return Err(QuicTransportParameterSemanticError::ForbiddenSender { id, offset });
    }

    match id.raw() {
        0x00 | 0x0f | 0x10 => parameter
            .connection_id()
            .map(|_| ())
            .map_err(|error| value_error(id, offset, error)),
        0x01 | 0x04 | 0x05 | 0x06 | 0x07 => parameter
            .integer()
            .map(|_| ())
            .map_err(|error| value_error(id, offset, error)),
        0x02 => parameter
            .stateless_reset_token()
            .map(|_| ())
            .map_err(|error| value_error(id, offset, error)),
        0x03 => validate_minimum(parameter, offset, 1200),
        0x08 | 0x09 => validate_maximum(parameter, offset, 1u64 << 60),
        0x0a => validate_maximum(parameter, offset, 20),
        0x0b => validate_maximum(parameter, offset, (1u64 << 14) - 1),
        0x0c => parameter
            .disable_active_migration()
            .map_err(|error| value_error(id, offset, error)),
        0x0d => parameter
            .preferred_address()
            .map(|_| ())
            .map_err(|error| value_error(id, offset, error)),
        0x0e => validate_minimum(parameter, offset, 2),
        _ => Ok(()),
    }
}

fn validate_minimum(
    parameter: QuicTransportParameter<'_>,
    offset: usize,
    minimum: u64,
) -> Result<(), QuicTransportParameterSemanticError> {
    let id = parameter.parameter_id();
    let value = parameter
        .integer()
        .map_err(|error| value_error(id, offset, error))?
        .value();
    if value < minimum {
        return Err(QuicTransportParameterSemanticError::BelowMinimum {
            id,
            offset,
            value,
            minimum,
        });
    }
    Ok(())
}

fn validate_maximum(
    parameter: QuicTransportParameter<'_>,
    offset: usize,
    maximum: u64,
) -> Result<(), QuicTransportParameterSemanticError> {
    let id = parameter.parameter_id();
    let value = parameter
        .integer()
        .map_err(|error| value_error(id, offset, error))?
        .value();
    if value > maximum {
        return Err(QuicTransportParameterSemanticError::AboveMaximum {
            id,
            offset,
            value,
            maximum,
        });
    }
    Ok(())
}

fn value_error(
    id: QuicTransportParameterId,
    offset: usize,
    error: QuicTransportParameterValueError,
) -> QuicTransportParameterSemanticError {
    QuicTransportParameterSemanticError::Value { id, offset, error }
}

const fn is_server_only(id: QuicTransportParameterId) -> bool {
    matches!(id.raw(), 0x00 | 0x02 | 0x0d | 0x10)
}
