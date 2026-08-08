//! Allocation-free HTTP message-content accounting after HTTP/3 header validation.

use core::fmt;

use super::codepoints::Http3ErrorCode;
use super::enums::message::Http3HeadersKind;
use super::frame::Http3Data;
use super::headers::Http3DecodedHeaderSection;

/// Request context used to determine response content rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3ResponseContext {
    /// A response to an ordinary request.
    Ordinary,
    /// A response to a HEAD request.
    Head,
    /// A response to a CONNECT request.
    Connect,
}

/// The HTTP message role whose content is being accounted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3ContentKind {
    /// An incoming request.
    Request,
    /// An incoming response with its request context.
    Response(Http3ResponseContext),
    /// An incoming pushed response.
    Push,
}

/// The disposition selected after accepting a header section.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3ContentDisposition {
    /// An informational response was accepted; a final response is still required.
    AwaitingFinalResponse,
    /// Subsequent DATA frames are HTTP message content.
    HttpMessage,
    /// Subsequent stream bytes belong to a CONNECT tunnel.
    ConnectTunnel,
}

/// Header-section operation expected by message-content accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3ContentOperation {
    /// A DATA payload can be accepted.
    Data,
    /// Initial request headers are required.
    InitialRequestHeaders,
    /// An informational or final response header section is required.
    ResponseHeaders,
    /// A trailing header section is required.
    Trailers,
}

/// Failure while accounting for HTTP message content and Content-Length.
///
/// Local operation sequencing and tunnel handoff failures have no HTTP/3 peer error code. The
/// remaining variants describe peer message-content violations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3MessageContentError {
    /// A Content-Length list member is empty or not an ASCII decimal number.
    InvalidContentLength {
        /// Decoded field index in wire order.
        field_index: usize,
        /// Comma-separated member index within the field value.
        member_index: usize,
    },
    /// A Content-Length list member overflows `u64`.
    ContentLengthOverflow {
        /// Decoded field index in wire order.
        field_index: usize,
        /// Comma-separated member index within the field value.
        member_index: usize,
    },
    /// A Content-Length list member differs from the earlier normalized value.
    ConflictingContentLength {
        /// Decoded field index in wire order.
        field_index: usize,
        /// Comma-separated member index within the field value.
        member_index: usize,
        /// Earlier normalized Content-Length.
        expected: u64,
        /// Conflicting normalized Content-Length.
        actual: u64,
    },
    /// A trailer field section contains Content-Length.
    ContentLengthInTrailers {
        /// Decoded trailer field index in wire order.
        field_index: usize,
    },
    /// Content-Length is forbidden for this message form.
    ProhibitedContentLength {
        /// Decoded field index in wire order.
        field_index: usize,
    },
    /// A validated header section was supplied at the wrong content-accounting operation.
    UnexpectedHeaderSection {
        /// Operation expected by content accounting.
        expected: Http3ContentOperation,
        /// Validated role carried by the supplied section.
        actual: Http3HeadersKind,
    },
    /// A local content-accounting operation cannot proceed in the current message phase.
    OperationNotReady {
        /// Operation that cannot proceed.
        operation: Http3ContentOperation,
    },
    /// DATA is forbidden because this message form has no HTTP content.
    ContentNotAllowed {
        /// Forbidden DATA payload length.
        data_length: usize,
    },
    /// A DATA payload length cannot be represented as `u64`.
    DataLengthNotRepresentable {
        /// DATA payload length.
        length: usize,
    },
    /// Adding a DATA payload length overflows cumulative received length.
    ReceivedLengthOverflow {
        /// Cumulative length before the DATA frame.
        received_length: u64,
        /// DATA payload length after conversion to `u64`.
        frame_length: u64,
    },
    /// Received HTTP content does not equal the declared Content-Length.
    ContentLengthMismatch {
        /// Declared normalized Content-Length.
        declared: u64,
        /// Received HTTP content length.
        received: u64,
    },
    /// A caller supplied an HTTP-content operation after CONNECT tunnel handoff.
    NotHttpMessageContent,
    /// The message ended before required initial or final headers were accepted.
    IncompleteMessage,
}

impl Http3MessageContentError {
    /// Returns the HTTP/3 peer error code when this failure is peer-caused.
    pub const fn error_code(self) -> Option<Http3ErrorCode> {
        match self {
            Self::UnexpectedHeaderSection { .. }
            | Self::OperationNotReady { .. }
            | Self::NotHttpMessageContent => None,
            Self::InvalidContentLength { .. }
            | Self::ContentLengthOverflow { .. }
            | Self::ConflictingContentLength { .. }
            | Self::ContentLengthInTrailers { .. }
            | Self::ProhibitedContentLength { .. }
            | Self::ContentNotAllowed { .. }
            | Self::DataLengthNotRepresentable { .. }
            | Self::ReceivedLengthOverflow { .. }
            | Self::ContentLengthMismatch { .. }
            | Self::IncompleteMessage => Some(Http3ErrorCode::MESSAGE_ERROR),
        }
    }
}

impl fmt::Display for Http3MessageContentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContentLength {
                field_index,
                member_index,
            } => write!(
                f,
                "HTTP/3 Content-Length field {field_index} member {member_index} is invalid"
            ),
            Self::ContentLengthOverflow {
                field_index,
                member_index,
            } => write!(
                f,
                "HTTP/3 Content-Length field {field_index} member {member_index} overflows"
            ),
            Self::ConflictingContentLength {
                field_index,
                member_index,
                expected,
                actual,
            } => write!(
                f,
                "HTTP/3 Content-Length field {field_index} member {member_index} is {actual}, expected {expected}"
            ),
            Self::ContentLengthInTrailers { field_index } => {
                write!(
                    f,
                    "HTTP/3 trailer field {field_index} contains Content-Length"
                )
            }
            Self::ProhibitedContentLength { field_index } => {
                write!(
                    f,
                    "HTTP/3 field {field_index} has prohibited Content-Length"
                )
            }
            Self::UnexpectedHeaderSection { expected, actual } => write!(
                f,
                "HTTP/3 {actual:?} header section is unexpected while accepting {expected:?}"
            ),
            Self::OperationNotReady { operation } => {
                write!(
                    f,
                    "HTTP/3 {operation:?} operation is not ready in the current message phase"
                )
            }
            Self::ContentNotAllowed { data_length } => {
                write!(
                    f,
                    "HTTP/3 DATA payload of {data_length} bytes is not allowed"
                )
            }
            Self::DataLengthNotRepresentable { length } => {
                write!(
                    f,
                    "HTTP/3 DATA payload length {length} cannot be represented as u64"
                )
            }
            Self::ReceivedLengthOverflow {
                received_length,
                frame_length,
            } => write!(
                f,
                "HTTP/3 received content length overflows: {received_length} plus {frame_length}"
            ),
            Self::ContentLengthMismatch { declared, received } => write!(
                f,
                "HTTP/3 Content-Length mismatch: declared {declared}, received {received}"
            ),
            Self::NotHttpMessageContent => {
                f.write_str("HTTP/3 operation belongs to CONNECT tunnel handling, not HTTP content")
            }
            Self::IncompleteMessage => f.write_str("HTTP/3 message content headers are incomplete"),
        }
    }
}

impl core::error::Error for Http3MessageContentError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    BeforeInitial,
    BeforeFinal,
    Content,
    NoContent,
    NoContentTrailers,
    Tunnel,
    Trailers,
}

/// Bounded cumulative HTTP message-content and Content-Length state.
///
/// The caller supplies QPACK-decoded, semantically validated field sections before committing
/// the corresponding message-stream transition. This state does not sequence frames or own tunnel
/// bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http3MessageContentState {
    kind: Http3ContentKind,
    phase: Phase,
    declared_length: Option<u64>,
    received_length: u64,
}

impl Http3MessageContentState {
    /// Creates accounting state for one incoming request, response, or push message.
    pub const fn new(kind: Http3ContentKind) -> Self {
        let phase = match kind {
            Http3ContentKind::Request => Phase::BeforeInitial,
            Http3ContentKind::Response(_) | Http3ContentKind::Push => Phase::BeforeFinal,
        };
        Self {
            kind,
            phase,
            declared_length: None,
            received_length: 0,
        }
    }

    /// Returns this message's role.
    pub const fn kind(self) -> Http3ContentKind {
        self.kind
    }

    /// Returns the normalized initial Content-Length, if present.
    pub const fn declared_length(self) -> Option<u64> {
        self.declared_length
    }

    /// Returns HTTP message-content bytes accepted so far.
    ///
    /// Tunnel bytes are deliberately not counted.
    pub const fn received_length(self) -> u64 {
        self.received_length
    }

    /// Accepts an initial request header section or an informational/final response section.
    pub fn accept_initial_headers(
        &mut self,
        section: Http3DecodedHeaderSection<'_>,
    ) -> Result<Http3ContentDisposition, Http3MessageContentError> {
        match self.phase {
            Phase::BeforeInitial => self.accept_request(section),
            Phase::BeforeFinal => self.accept_response(section),
            _ => Err(Http3MessageContentError::OperationNotReady {
                operation: self.initial_headers_operation(),
            }),
        }
    }

    /// Accounts for one HTTP DATA payload without buffering it.
    pub fn receive_data(&mut self, data: Http3Data<'_>) -> Result<(), Http3MessageContentError> {
        match self.phase {
            Phase::Tunnel => Err(Http3MessageContentError::NotHttpMessageContent),
            Phase::NoContent | Phase::NoContentTrailers if data.data().is_empty() => Ok(()),
            Phase::NoContent | Phase::NoContentTrailers => {
                Err(Http3MessageContentError::ContentNotAllowed {
                    data_length: data.data().len(),
                })
            }
            Phase::Content => {
                let frame_length = u64::try_from(data.data().len()).map_err(|_| {
                    Http3MessageContentError::DataLengthNotRepresentable {
                        length: data.data().len(),
                    }
                })?;
                let received_length = self.received_length.checked_add(frame_length).ok_or(
                    Http3MessageContentError::ReceivedLengthOverflow {
                        received_length: self.received_length,
                        frame_length,
                    },
                )?;
                if let Some(declared) = self.declared_length
                    && received_length > declared
                {
                    return Err(Http3MessageContentError::ContentLengthMismatch {
                        declared,
                        received: received_length,
                    });
                }
                self.received_length = received_length;
                Ok(())
            }
            Phase::BeforeInitial | Phase::BeforeFinal | Phase::Trailers => {
                Err(Http3MessageContentError::OperationNotReady {
                    operation: Http3ContentOperation::Data,
                })
            }
        }
    }

    /// Accepts an analyzer-valid trailer section after content.
    pub fn accept_trailers(
        &mut self,
        section: Http3DecodedHeaderSection<'_>,
    ) -> Result<(), Http3MessageContentError> {
        if section.kind() != Http3HeadersKind::Trailers {
            return Err(Http3MessageContentError::UnexpectedHeaderSection {
                expected: Http3ContentOperation::Trailers,
                actual: section.kind(),
            });
        }
        match self.phase {
            Phase::Tunnel => return Err(Http3MessageContentError::NotHttpMessageContent),
            Phase::Content | Phase::NoContentTrailers => {}
            _ => {
                return Err(Http3MessageContentError::OperationNotReady {
                    operation: Http3ContentOperation::Trailers,
                });
            }
        }
        if let Some(field_index) = first_content_length(section) {
            return Err(Http3MessageContentError::ContentLengthInTrailers { field_index });
        }
        if self.phase == Phase::Content {
            self.length_matches()?;
        }
        self.phase = Phase::Trailers;
        Ok(())
    }

    /// Verifies that required headers arrived and Content-Length matches accepted HTTP content.
    pub fn finish(&self) -> Result<(), Http3MessageContentError> {
        match self.phase {
            Phase::BeforeInitial | Phase::BeforeFinal => {
                Err(Http3MessageContentError::IncompleteMessage)
            }
            Phase::Content => self.length_matches(),
            Phase::NoContent | Phase::NoContentTrailers | Phase::Tunnel | Phase::Trailers => Ok(()),
        }
    }

    fn accept_request(
        &mut self,
        section: Http3DecodedHeaderSection<'_>,
    ) -> Result<Http3ContentDisposition, Http3MessageContentError> {
        if section.kind() != Http3HeadersKind::Request {
            return Err(Http3MessageContentError::UnexpectedHeaderSection {
                expected: Http3ContentOperation::InitialRequestHeaders,
                actual: section.kind(),
            });
        }
        let declared_length = parse_content_length(section)?;
        let connect = section
            .section()
            .iter()
            .any(|field| field.name() == b":method" && field.value() == b"CONNECT");
        self.declared_length = declared_length;
        self.phase = if connect {
            Phase::Tunnel
        } else {
            Phase::Content
        };
        Ok(if connect {
            Http3ContentDisposition::ConnectTunnel
        } else {
            Http3ContentDisposition::HttpMessage
        })
    }

    fn accept_response(
        &mut self,
        section: Http3DecodedHeaderSection<'_>,
    ) -> Result<Http3ContentDisposition, Http3MessageContentError> {
        match section.kind() {
            Http3HeadersKind::InformationalResponse => {
                if let Some(field_index) = first_content_length(section) {
                    return Err(Http3MessageContentError::ProhibitedContentLength { field_index });
                }
                Ok(Http3ContentDisposition::AwaitingFinalResponse)
            }
            Http3HeadersKind::FinalResponse => self.accept_final_response(section),
            _ => Err(Http3MessageContentError::UnexpectedHeaderSection {
                expected: Http3ContentOperation::ResponseHeaders,
                actual: section.kind(),
            }),
        }
    }

    fn accept_final_response(
        &mut self,
        section: Http3DecodedHeaderSection<'_>,
    ) -> Result<Http3ContentDisposition, Http3MessageContentError> {
        let status = response_status(section);
        let prohibited = match self.kind {
            Http3ContentKind::Response(Http3ResponseContext::Connect) => {
                (200..=299).contains(&status)
            }
            Http3ContentKind::Response(Http3ResponseContext::Head)
            | Http3ContentKind::Response(Http3ResponseContext::Ordinary)
            | Http3ContentKind::Push => status == 204,
            Http3ContentKind::Request => false,
        };
        if prohibited && let Some(field_index) = first_content_length(section) {
            return Err(Http3MessageContentError::ProhibitedContentLength { field_index });
        }
        let declared_length = parse_content_length(section)?;
        let (phase, disposition) = match self.kind {
            Http3ContentKind::Response(Http3ResponseContext::Connect)
                if (200..=299).contains(&status) =>
            {
                (Phase::Tunnel, Http3ContentDisposition::ConnectTunnel)
            }
            _ if status == 204 => (Phase::NoContent, Http3ContentDisposition::HttpMessage),
            Http3ContentKind::Response(Http3ResponseContext::Ordinary)
            | Http3ContentKind::Response(Http3ResponseContext::Head)
            | Http3ContentKind::Push
                if status == 205 =>
            {
                (
                    Phase::NoContentTrailers,
                    Http3ContentDisposition::HttpMessage,
                )
            }
            Http3ContentKind::Response(Http3ResponseContext::Head) => (
                Phase::NoContentTrailers,
                Http3ContentDisposition::HttpMessage,
            ),
            Http3ContentKind::Response(Http3ResponseContext::Ordinary) | Http3ContentKind::Push
                if status == 304 =>
            {
                (
                    Phase::NoContentTrailers,
                    Http3ContentDisposition::HttpMessage,
                )
            }
            _ => (Phase::Content, Http3ContentDisposition::HttpMessage),
        };
        self.declared_length = declared_length;
        self.phase = phase;
        Ok(disposition)
    }

    fn length_matches(&self) -> Result<(), Http3MessageContentError> {
        match self.declared_length {
            Some(declared) if declared != self.received_length => {
                Err(Http3MessageContentError::ContentLengthMismatch {
                    declared,
                    received: self.received_length,
                })
            }
            _ => Ok(()),
        }
    }

    const fn initial_headers_operation(&self) -> Http3ContentOperation {
        match self.kind {
            Http3ContentKind::Request => Http3ContentOperation::InitialRequestHeaders,
            Http3ContentKind::Response(_) | Http3ContentKind::Push => {
                Http3ContentOperation::ResponseHeaders
            }
        }
    }
}

fn first_content_length(section: Http3DecodedHeaderSection<'_>) -> Option<usize> {
    section
        .section()
        .iter()
        .enumerate()
        .find_map(|(index, field)| (field.name() == b"content-length").then_some(index))
}

fn parse_content_length(
    section: Http3DecodedHeaderSection<'_>,
) -> Result<Option<u64>, Http3MessageContentError> {
    let mut declared = None;
    for (field_index, field) in section.section().iter().enumerate() {
        if field.name() != b"content-length" {
            continue;
        }
        for (member_index, member) in field.value().split(|byte| *byte == b',').enumerate() {
            let value = trim_ows(member);
            let actual = parse_decimal(value, field_index, member_index)?;
            if let Some(expected) = declared
                && expected != actual
            {
                return Err(Http3MessageContentError::ConflictingContentLength {
                    field_index,
                    member_index,
                    expected,
                    actual,
                });
            }
            declared = Some(actual);
        }
    }
    Ok(declared)
}

fn parse_decimal(
    value: &[u8],
    field_index: usize,
    member_index: usize,
) -> Result<u64, Http3MessageContentError> {
    if value.is_empty() || !value.iter().all(|byte| byte.is_ascii_digit()) {
        return Err(Http3MessageContentError::InvalidContentLength {
            field_index,
            member_index,
        });
    }
    let mut result = 0_u64;
    for byte in value {
        result = result
            .checked_mul(10)
            .and_then(|number| number.checked_add(u64::from(*byte - b'0')))
            .ok_or(Http3MessageContentError::ContentLengthOverflow {
                field_index,
                member_index,
            })?;
    }
    Ok(result)
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}

fn response_status(section: Http3DecodedHeaderSection<'_>) -> u16 {
    for field in section.section().iter() {
        if field.name() == b":status" {
            let value = field.value();
            if let (Some(hundreds), Some(tens), Some(ones)) =
                (value.first(), value.get(1), value.get(2))
            {
                return u16::from(*hundreds - b'0') * 100
                    + u16::from(*tens - b'0') * 10
                    + u16::from(*ones - b'0');
            }
        }
    }
    0
}
