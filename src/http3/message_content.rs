//! Allocation-free HTTP message-content accounting after HTTP/3 header validation.

use super::{
    Http3Data, Http3DecodedHeaderSection, Http3HeaderSectionKind, Http3MessageContentError,
};

/// Request context used to determine response content rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3ResponseRequestContext {
    /// A response to an ordinary request.
    Ordinary,
    /// A response to a HEAD request.
    Head,
    /// A response to a CONNECT request.
    Connect,
}

/// The HTTP message role whose content is being accounted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3MessageContentKind {
    /// An incoming request.
    Request,
    /// An incoming response with its request context.
    Response(Http3ResponseRequestContext),
    /// An incoming pushed response.
    Push,
}

/// The disposition selected after accepting a header section.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3MessageContentDisposition {
    /// An informational response was accepted; a final response is still required.
    AwaitingFinalResponse,
    /// Subsequent DATA frames are HTTP message content.
    HttpMessage,
    /// Subsequent stream bytes belong to a CONNECT tunnel.
    ConnectTunnel,
}

/// Header-section operation expected by message-content accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3MessageContentOperation {
    /// A DATA payload can be accepted.
    Data,
    /// Initial request headers are required.
    InitialRequestHeaders,
    /// An informational or final response header section is required.
    ResponseHeaders,
    /// A trailing header section is required.
    Trailers,
}

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
    kind: Http3MessageContentKind,
    phase: Phase,
    declared_length: Option<u64>,
    received_length: u64,
}

impl Http3MessageContentState {
    /// Creates accounting state for one incoming request, response, or push message.
    pub const fn new(kind: Http3MessageContentKind) -> Self {
        let phase = match kind {
            Http3MessageContentKind::Request => Phase::BeforeInitial,
            Http3MessageContentKind::Response(_) | Http3MessageContentKind::Push => {
                Phase::BeforeFinal
            }
        };
        Self {
            kind,
            phase,
            declared_length: None,
            received_length: 0,
        }
    }

    /// Returns this message's role.
    pub const fn kind(self) -> Http3MessageContentKind {
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
    ) -> Result<Http3MessageContentDisposition, Http3MessageContentError> {
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
                    operation: Http3MessageContentOperation::Data,
                })
            }
        }
    }

    /// Accepts an analyzer-valid trailer section after content.
    pub fn accept_trailers(
        &mut self,
        section: Http3DecodedHeaderSection<'_>,
    ) -> Result<(), Http3MessageContentError> {
        if section.kind() != Http3HeaderSectionKind::Trailers {
            return Err(Http3MessageContentError::UnexpectedHeaderSection {
                expected: Http3MessageContentOperation::Trailers,
                actual: section.kind(),
            });
        }
        match self.phase {
            Phase::Tunnel => return Err(Http3MessageContentError::NotHttpMessageContent),
            Phase::Content | Phase::NoContentTrailers => {}
            _ => {
                return Err(Http3MessageContentError::OperationNotReady {
                    operation: Http3MessageContentOperation::Trailers,
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
    ) -> Result<Http3MessageContentDisposition, Http3MessageContentError> {
        if section.kind() != Http3HeaderSectionKind::Request {
            return Err(Http3MessageContentError::UnexpectedHeaderSection {
                expected: Http3MessageContentOperation::InitialRequestHeaders,
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
            Http3MessageContentDisposition::ConnectTunnel
        } else {
            Http3MessageContentDisposition::HttpMessage
        })
    }

    fn accept_response(
        &mut self,
        section: Http3DecodedHeaderSection<'_>,
    ) -> Result<Http3MessageContentDisposition, Http3MessageContentError> {
        match section.kind() {
            Http3HeaderSectionKind::InformationalResponse => {
                if let Some(field_index) = first_content_length(section) {
                    return Err(Http3MessageContentError::ProhibitedContentLength { field_index });
                }
                Ok(Http3MessageContentDisposition::AwaitingFinalResponse)
            }
            Http3HeaderSectionKind::FinalResponse => self.accept_final_response(section),
            _ => Err(Http3MessageContentError::UnexpectedHeaderSection {
                expected: Http3MessageContentOperation::ResponseHeaders,
                actual: section.kind(),
            }),
        }
    }

    fn accept_final_response(
        &mut self,
        section: Http3DecodedHeaderSection<'_>,
    ) -> Result<Http3MessageContentDisposition, Http3MessageContentError> {
        let status = response_status(section);
        let prohibited = match self.kind {
            Http3MessageContentKind::Response(Http3ResponseRequestContext::Connect) => {
                (200..=299).contains(&status)
            }
            Http3MessageContentKind::Response(Http3ResponseRequestContext::Head)
            | Http3MessageContentKind::Response(Http3ResponseRequestContext::Ordinary)
            | Http3MessageContentKind::Push => status == 204,
            Http3MessageContentKind::Request => false,
        };
        if prohibited && let Some(field_index) = first_content_length(section) {
            return Err(Http3MessageContentError::ProhibitedContentLength { field_index });
        }
        let declared_length = parse_content_length(section)?;
        let (phase, disposition) = match self.kind {
            Http3MessageContentKind::Response(Http3ResponseRequestContext::Connect)
                if (200..=299).contains(&status) =>
            {
                (Phase::Tunnel, Http3MessageContentDisposition::ConnectTunnel)
            }
            _ if status == 204 => (
                Phase::NoContent,
                Http3MessageContentDisposition::HttpMessage,
            ),
            Http3MessageContentKind::Response(Http3ResponseRequestContext::Ordinary)
            | Http3MessageContentKind::Response(Http3ResponseRequestContext::Head)
            | Http3MessageContentKind::Push
                if status == 205 =>
            {
                (
                    Phase::NoContentTrailers,
                    Http3MessageContentDisposition::HttpMessage,
                )
            }
            Http3MessageContentKind::Response(Http3ResponseRequestContext::Head) => (
                Phase::NoContentTrailers,
                Http3MessageContentDisposition::HttpMessage,
            ),
            Http3MessageContentKind::Response(Http3ResponseRequestContext::Ordinary)
            | Http3MessageContentKind::Push
                if status == 304 =>
            {
                (
                    Phase::NoContentTrailers,
                    Http3MessageContentDisposition::HttpMessage,
                )
            }
            _ => (Phase::Content, Http3MessageContentDisposition::HttpMessage),
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

    const fn initial_headers_operation(&self) -> Http3MessageContentOperation {
        match self.kind {
            Http3MessageContentKind::Request => Http3MessageContentOperation::InitialRequestHeaders,
            Http3MessageContentKind::Response(_) | Http3MessageContentKind::Push => {
                Http3MessageContentOperation::ResponseHeaders
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
