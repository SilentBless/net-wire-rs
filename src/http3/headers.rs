//! Allocation-free semantic validation of QPACK-decoded HTTP/3 field sections.

use core::fmt;

use crate::qpack::QpackDecodedFieldSection;

use super::codepoints::Http3ErrorCode;
use super::enums::message::{Http3HeadersContext, Http3HeadersKind};

/// A semantically valid decoded HTTP/3 HEADERS field section.
///
/// This preserves the decoded QPACK section, including field ordering and indexing metadata. The
/// reported size is the RFC 9114 uncompressed field-section size; it is advisory and does not
/// enforce a peer SETTINGS limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http3DecodedHeaderSection<'a> {
    section: QpackDecodedFieldSection<'a>,
    kind: Http3HeadersKind,
    field_section_size: u64,
}

impl<'a> Http3DecodedHeaderSection<'a> {
    /// Returns the original decoded QPACK field section.
    pub const fn section(self) -> QpackDecodedFieldSection<'a> {
        self.section
    }

    /// Returns the validated HTTP/3 field-section role.
    pub const fn kind(self) -> Http3HeadersKind {
        self.kind
    }

    /// Returns the uncompressed RFC 9114 field-section size without enforcing a SETTINGS limit.
    pub const fn field_section_size(self) -> u64 {
        self.field_section_size
    }
}

/// A semantically valid decoded HTTP/3 PUSH_PROMISE request field section.
///
/// This distinct type deliberately has no [`Http3HeadersKind`] accessor, preventing it from
/// being supplied to HEADERS stream sequencing accidentally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http3DecodedPushPromise<'a> {
    section: QpackDecodedFieldSection<'a>,
    field_section_size: u64,
}

impl<'a> Http3DecodedPushPromise<'a> {
    /// Returns the original decoded QPACK field section.
    pub const fn section(self) -> QpackDecodedFieldSection<'a> {
        self.section
    }

    /// Returns the uncompressed RFC 9114 field-section size without enforcing a SETTINGS limit.
    pub const fn field_section_size(self) -> u64 {
        self.field_section_size
    }
}

/// Validates one decoded HTTP/3 HEADERS field section without decoding or mutating it.
pub fn analyze_decoded_header_section<'a>(
    section: QpackDecodedFieldSection<'a>,
    context: Http3HeadersContext,
) -> Result<Http3DecodedHeaderSection<'a>, Http3HeaderSectionError> {
    let (observed, field_section_size) = scan(section, context)?;
    let kind = match context {
        Http3HeadersContext::Request {
            extended_connect_enabled,
        } => {
            validate_request(observed, extended_connect_enabled)?;
            Http3HeadersKind::Request
        }
        Http3HeadersContext::Response => validate_response(observed)?,
        Http3HeadersContext::Trailers => Http3HeadersKind::Trailers,
    };
    Ok(Http3DecodedHeaderSection {
        section,
        kind,
        field_section_size,
    })
}

/// Validates one decoded HTTP/3 PUSH_PROMISE field section with request syntax.
///
/// This performs only section-local HTTP/3 syntax validation; push cacheability and stream-state
/// policy remain the caller's responsibility.
pub fn analyze_decoded_push_promise<'a>(
    section: QpackDecodedFieldSection<'a>,
    extended_connect_enabled: bool,
) -> Result<Http3DecodedPushPromise<'a>, Http3HeaderSectionError> {
    let context = Http3HeadersContext::Request {
        extended_connect_enabled,
    };
    let (observed, field_section_size) = scan(section, context)?;
    validate_request(observed, extended_connect_enabled)?;
    Ok(Http3DecodedPushPromise {
        section,
        field_section_size,
    })
}

#[derive(Clone, Copy)]
struct FieldObservation<'a> {
    value: &'a [u8],
    field_index: usize,
}

#[derive(Clone, Copy)]
struct Observed<'a> {
    method: Option<FieldObservation<'a>>,
    scheme: Option<FieldObservation<'a>>,
    authority: Option<FieldObservation<'a>>,
    path: Option<FieldObservation<'a>>,
    protocol: Option<FieldObservation<'a>>,
    status: Option<FieldObservation<'a>>,
    host: Option<FieldObservation<'a>>,
}

fn scan<'a>(
    section: QpackDecodedFieldSection<'a>,
    context: Http3HeadersContext,
) -> Result<(Observed<'a>, u64), Http3HeaderSectionError> {
    let mut observed = Observed {
        method: None,
        scheme: None,
        authority: None,
        path: None,
        protocol: None,
        status: None,
        host: None,
    };
    let mut size = 0_u64;
    let mut regular_seen = false;

    for (field_index, field) in section.iter().enumerate() {
        let name = field.name();
        let value = field.value();
        size = add_field_size(size, name, value, field_index)?;
        validate_field_value(value, field_index)?;
        if name.first() == Some(&b':') {
            if regular_seen {
                return Err(Http3HeaderSectionError::PseudoFieldAfterRegular { field_index });
            }
            if context == Http3HeadersContext::Trailers {
                return Err(Http3HeaderSectionError::PseudoFieldInTrailers { field_index });
            }
            observe_pseudo(&mut observed, name, value, field_index, context)?;
        } else {
            regular_seen = true;
            validate_regular_name(name, field_index)?;
            validate_regular_field(name, value, field_index, context, &mut observed)?;
        }
    }
    Ok((observed, size))
}

fn add_field_size(
    size: u64,
    name: &[u8],
    value: &[u8],
    field_index: usize,
) -> Result<u64, Http3HeaderSectionError> {
    let name_length = u64::try_from(name.len())
        .map_err(|_| Http3HeaderSectionError::FieldSectionSizeOverflow { field_index })?;
    let value_length = u64::try_from(value.len())
        .map_err(|_| Http3HeaderSectionError::FieldSectionSizeOverflow { field_index })?;
    name_length
        .checked_add(value_length)
        .and_then(|length| length.checked_add(32))
        .and_then(|length| size.checked_add(length))
        .ok_or(Http3HeaderSectionError::FieldSectionSizeOverflow { field_index })
}

fn validate_regular_name(name: &[u8], field_index: usize) -> Result<(), Http3HeaderSectionError> {
    if name.iter().any(|byte| byte.is_ascii_uppercase()) {
        return Err(Http3HeaderSectionError::UppercaseFieldName { field_index });
    }
    if name.is_empty() || !name.iter().all(|byte| is_token(*byte)) {
        return Err(Http3HeaderSectionError::InvalidFieldName { field_index });
    }
    Ok(())
}

fn validate_field_value(value: &[u8], field_index: usize) -> Result<(), Http3HeaderSectionError> {
    if matches!(value.first(), Some(b' ' | b'\t'))
        || matches!(value.last(), Some(b' ' | b'\t'))
        || value.iter().any(|byte| {
            *byte == b'\0'
                || *byte == b'\r'
                || *byte == b'\n'
                || (*byte < 0x20 && *byte != b'\t')
                || *byte == 0x7f
        })
    {
        return Err(Http3HeaderSectionError::InvalidFieldValue { field_index });
    }
    Ok(())
}

fn observe_pseudo<'a>(
    observed: &mut Observed<'a>,
    name: &[u8],
    value: &'a [u8],
    field_index: usize,
    context: Http3HeadersContext,
) -> Result<(), Http3HeaderSectionError> {
    let slot = match name {
        b":method" if matches!(context, Http3HeadersContext::Request { .. }) => {
            &mut observed.method
        }
        b":scheme" if matches!(context, Http3HeadersContext::Request { .. }) => {
            &mut observed.scheme
        }
        b":authority" if matches!(context, Http3HeadersContext::Request { .. }) => {
            &mut observed.authority
        }
        b":path" if matches!(context, Http3HeadersContext::Request { .. }) => &mut observed.path,
        b":protocol" if matches!(context, Http3HeadersContext::Request { .. }) => {
            &mut observed.protocol
        }
        b":status" if context == Http3HeadersContext::Response => &mut observed.status,
        _ => return Err(Http3HeaderSectionError::InvalidPseudoField { field_index }),
    };
    if slot.is_some() {
        return Err(Http3HeaderSectionError::DuplicatePseudoField { field_index });
    }
    *slot = Some(FieldObservation { value, field_index });
    Ok(())
}

fn validate_regular_field<'a>(
    name: &[u8],
    value: &'a [u8],
    field_index: usize,
    context: Http3HeadersContext,
    observed: &mut Observed<'a>,
) -> Result<(), Http3HeaderSectionError> {
    if matches!(
        name,
        b"connection" | b"keep-alive" | b"proxy-connection" | b"transfer-encoding" | b"upgrade"
    ) {
        return Err(Http3HeaderSectionError::ConnectionSpecificField { field_index });
    }
    if name == b"te"
        && (!matches!(context, Http3HeadersContext::Request { .. }) || !valid_te(value))
    {
        return Err(Http3HeaderSectionError::InvalidTe { field_index });
    }
    if name == b"host" {
        if observed.host.is_some() {
            return Err(Http3HeaderSectionError::DuplicateHost { field_index });
        }
        observed.host = Some(FieldObservation { value, field_index });
    }
    Ok(())
}

fn validate_request(
    observed: Observed<'_>,
    extended_connect_enabled: bool,
) -> Result<(), Http3HeaderSectionError> {
    let method = observed
        .method
        .ok_or(Http3HeaderSectionError::MissingPseudoField { name: b":method" })?;
    if method.value.is_empty() || !method.value.iter().all(|byte| is_token(*byte)) {
        return Err(Http3HeaderSectionError::InvalidMethod {
            field_index: method.field_index,
        });
    }
    let protocol = observed.protocol;
    let extended = protocol.is_some();
    if let Some(protocol) = protocol {
        if !extended_connect_enabled || method.value != b"CONNECT" {
            return Err(Http3HeaderSectionError::InvalidProtocol {
                field_index: protocol.field_index,
            });
        }
        if protocol.value.is_empty() || !protocol.value.iter().all(|byte| is_token(*byte)) {
            return Err(Http3HeaderSectionError::InvalidProtocol {
                field_index: protocol.field_index,
            });
        }
    }
    if method.value == b"CONNECT" && !extended {
        let forbidden = match (observed.scheme, observed.path) {
            (Some(scheme), Some(path)) if scheme.field_index < path.field_index => Some(scheme),
            (Some(_), Some(path)) => Some(path),
            (Some(scheme), None) => Some(scheme),
            (None, Some(path)) => Some(path),
            (None, None) => None,
        };
        if let Some(field) = forbidden {
            return Err(Http3HeaderSectionError::InvalidConnectPseudoFields {
                field_index: field.field_index,
            });
        }
        let authority = observed
            .authority
            .ok_or(Http3HeaderSectionError::MissingPseudoField {
                name: b":authority",
            })?;
        if !valid_connect_authority(authority.value) {
            return Err(Http3HeaderSectionError::InvalidAuthority {
                field_index: authority.field_index,
            });
        }
        validate_connect_host(authority, observed.host)?;
        return Ok(());
    }
    let scheme = observed
        .scheme
        .ok_or(Http3HeaderSectionError::MissingPseudoField { name: b":scheme" })?;
    let path = observed
        .path
        .ok_or(Http3HeaderSectionError::MissingPseudoField { name: b":path" })?;
    if scheme.value.is_empty() || !valid_scheme(scheme.value) {
        return Err(Http3HeaderSectionError::InvalidScheme {
            field_index: scheme.field_index,
        });
    }
    if path.value.is_empty()
        || ((scheme.value == b"http" || scheme.value == b"https")
            && !((method.value == b"OPTIONS" && path.value == b"*")
                || path.value.first() == Some(&b'/')))
    {
        return Err(Http3HeaderSectionError::InvalidPath {
            field_index: path.field_index,
        });
    }
    validate_request_authority(
        observed.authority,
        observed.host,
        extended || scheme.value == b"http" || scheme.value == b"https",
    )
}

fn validate_request_authority(
    authority: Option<FieldObservation<'_>>,
    host: Option<FieldObservation<'_>>,
    required: bool,
) -> Result<(), Http3HeaderSectionError> {
    if let Some(authority) = authority
        && (authority.value.is_empty() || authority.value.contains(&b'@'))
    {
        return Err(Http3HeaderSectionError::InvalidAuthority {
            field_index: authority.field_index,
        });
    }
    if let Some(host) = host
        && host.value.is_empty()
    {
        return Err(Http3HeaderSectionError::InvalidHost {
            field_index: host.field_index,
        });
    }
    if required {
        match (authority, host) {
            (Some(authority), Some(host)) if authority.value != host.value => {
                Err(Http3HeaderSectionError::AuthorityHostMismatch {
                    authority_field_index: authority.field_index,
                    host_field_index: host.field_index,
                })
            }
            (Some(_), _) | (None, Some(_)) => Ok(()),
            (None, None) => Err(Http3HeaderSectionError::MissingAuthorityOrHost),
        }
    } else {
        Ok(())
    }
}

fn validate_connect_host(
    authority: FieldObservation<'_>,
    host: Option<FieldObservation<'_>>,
) -> Result<(), Http3HeaderSectionError> {
    let Some(host) = host else {
        return Ok(());
    };
    if host.value.is_empty() {
        return Err(Http3HeaderSectionError::InvalidHost {
            field_index: host.field_index,
        });
    }
    if authority.value != host.value {
        return Err(Http3HeaderSectionError::AuthorityHostMismatch {
            authority_field_index: authority.field_index,
            host_field_index: host.field_index,
        });
    }
    Ok(())
}

fn validate_response(observed: Observed<'_>) -> Result<Http3HeadersKind, Http3HeaderSectionError> {
    let status_field = observed
        .status
        .ok_or(Http3HeaderSectionError::MissingPseudoField { name: b":status" })?;
    if status_field.value.len() != 3 || !status_field.value.iter().all(|byte| byte.is_ascii_digit())
    {
        return Err(Http3HeaderSectionError::InvalidStatus {
            field_index: status_field.field_index,
        });
    }
    let status = u16::from(status_field.value[0] - b'0') * 100
        + u16::from(status_field.value[1] - b'0') * 10
        + u16::from(status_field.value[2] - b'0');
    match status {
        100..=199 if status != 101 => Ok(Http3HeadersKind::InformationalResponse),
        200..=599 => Ok(Http3HeadersKind::FinalResponse),
        _ => Err(Http3HeaderSectionError::InvalidStatus {
            field_index: status_field.field_index,
        }),
    }
}

fn valid_te(value: &[u8]) -> bool {
    let mut item_seen = false;
    for item in value.split(|byte| *byte == b',') {
        let item = trim_ows(item);
        if !item.is_empty() {
            item_seen = true;
            if !item.eq_ignore_ascii_case(b"trailers") {
                return false;
            }
        }
    }
    item_seen
}

fn valid_connect_authority(authority: &[u8]) -> bool {
    if authority.is_empty() || authority.contains(&b'@') {
        return false;
    }
    let (host, port, bracketed) = if authority.first() == Some(&b'[') {
        let Some(end) = authority.iter().position(|byte| *byte == b']') else {
            return false;
        };
        if end == 1 || authority.get(end + 1) != Some(&b':') {
            return false;
        }
        (&authority[1..end], &authority[end + 2..], true)
    } else {
        let Some(port_start) = authority.iter().rposition(|byte| *byte == b':') else {
            return false;
        };
        (
            &authority[..port_start],
            &authority[port_start + 1..],
            false,
        )
    };
    !host.is_empty() && (bracketed || !host.contains(&b':')) && valid_port(port)
}

fn valid_port(port: &[u8]) -> bool {
    if port.is_empty() || !port.iter().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let mut value = 0_u32;
    for byte in port {
        value = match value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u32::from(*byte - b'0')))
        {
            Some(value) if value <= 65_535 => value,
            _ => return false,
        };
    }
    true
}

fn valid_scheme(scheme: &[u8]) -> bool {
    scheme
        .first()
        .is_some_and(|byte| byte.is_ascii_alphabetic())
        && scheme[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'+' | b'-' | b'.'))
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

const fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Failure to semantically validate a decoded HTTP/3 field section.
///
/// `field_index` values identify decoded fields in wire order. They are not byte offsets because
/// QPACK decoding does not retain a field's encoded wire offset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3HeaderSectionError {
    /// Adding a decoded field's RFC 9114 size contribution overflowed `u64`.
    FieldSectionSizeOverflow {
        /// Index of the field whose contribution overflowed.
        field_index: usize,
    },
    /// A regular field name is empty or not an HTTP token.
    InvalidFieldName {
        /// Index of the invalid field.
        field_index: usize,
    },
    /// A regular field name contains an uppercase ASCII byte.
    UppercaseFieldName {
        /// Index of the invalid field.
        field_index: usize,
    },
    /// A field value contains invalid HTTP field-content or leading/trailing whitespace.
    InvalidFieldValue {
        /// Index of the invalid field.
        field_index: usize,
    },
    /// A pseudo-field follows a regular field.
    PseudoFieldAfterRegular {
        /// Index of the misplaced pseudo-field.
        field_index: usize,
    },
    /// A trailer section contains a pseudo-field.
    PseudoFieldInTrailers {
        /// Index of the forbidden pseudo-field.
        field_index: usize,
    },
    /// A pseudo-field is unknown or forbidden for this section context.
    InvalidPseudoField {
        /// Index of the invalid pseudo-field.
        field_index: usize,
    },
    /// A pseudo-field repeats an earlier pseudo-field.
    DuplicatePseudoField {
        /// Index of the repeated pseudo-field.
        field_index: usize,
    },
    /// A required pseudo-field is absent.
    MissingPseudoField {
        /// Name of the missing pseudo-field.
        name: &'static [u8],
    },
    /// A connection-specific field is forbidden in HTTP/3.
    ConnectionSpecificField {
        /// Index of the forbidden field.
        field_index: usize,
    },
    /// A `te` field is forbidden here or does not contain only `trailers` values.
    InvalidTe {
        /// Index of the invalid field.
        field_index: usize,
    },
    /// A `host` field repeats an earlier Host field.
    DuplicateHost {
        /// Index of the repeated Host field.
        field_index: usize,
    },
    /// A request has neither a nonempty `:authority` nor a nonempty Host field.
    MissingAuthorityOrHost,
    /// A `:authority` value is invalid for the request form.
    InvalidAuthority {
        /// Index of the invalid `:authority` field.
        field_index: usize,
    },
    /// A Host field is empty.
    InvalidHost {
        /// Index of the invalid Host field.
        field_index: usize,
    },
    /// `:authority` and Host are both present but differ.
    AuthorityHostMismatch {
        /// Index of the `:authority` field.
        authority_field_index: usize,
        /// Index of the Host field.
        host_field_index: usize,
    },
    /// The `:method` pseudo-field is empty or not an HTTP token.
    InvalidMethod {
        /// Index of the invalid `:method` field.
        field_index: usize,
    },
    /// The `:scheme` pseudo-field is empty or malformed.
    InvalidScheme {
        /// Index of the invalid `:scheme` field.
        field_index: usize,
    },
    /// The `:path` pseudo-field is empty or invalid for an HTTP scheme.
    InvalidPath {
        /// Index of the invalid `:path` field.
        field_index: usize,
    },
    /// The `:protocol` pseudo-field is disabled, malformed, or not paired with CONNECT.
    InvalidProtocol {
        /// Index of the invalid `:protocol` field.
        field_index: usize,
    },
    /// An ordinary CONNECT request contains `:scheme` or `:path`.
    InvalidConnectPseudoFields {
        /// Index of the first forbidden pseudo-field.
        field_index: usize,
    },
    /// The `:status` pseudo-field is malformed, forbidden, or outside the accepted range.
    InvalidStatus {
        /// Index of the invalid `:status` field.
        field_index: usize,
    },
}

impl Http3HeaderSectionError {
    /// Returns the HTTP/3 application error code required by every semantic field-section error.
    pub const fn error_code(self) -> Http3ErrorCode {
        Http3ErrorCode::MESSAGE_ERROR
    }
}

impl fmt::Display for Http3HeaderSectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FieldSectionSizeOverflow { field_index } => write!(
                f,
                "HTTP/3 field {field_index} makes the field-section size overflow"
            ),
            Self::InvalidFieldName { field_index } => {
                write!(f, "HTTP/3 field {field_index} has an invalid name")
            }
            Self::UppercaseFieldName { field_index } => {
                write!(f, "HTTP/3 field {field_index} has an uppercase name")
            }
            Self::InvalidFieldValue { field_index } => {
                write!(f, "HTTP/3 field {field_index} has an invalid value")
            }
            Self::PseudoFieldAfterRegular { field_index } => write!(
                f,
                "HTTP/3 pseudo-field {field_index} follows a regular field"
            ),
            Self::PseudoFieldInTrailers { field_index } => {
                write!(f, "HTTP/3 trailer pseudo-field {field_index} is forbidden")
            }
            Self::InvalidPseudoField { field_index } => write!(
                f,
                "HTTP/3 pseudo-field {field_index} is invalid for this context"
            ),
            Self::DuplicatePseudoField { field_index } => write!(
                f,
                "HTTP/3 pseudo-field {field_index} duplicates an earlier pseudo-field"
            ),
            Self::MissingPseudoField { name } => write!(
                f,
                "HTTP/3 field section is missing required pseudo-field {name:?}"
            ),
            Self::ConnectionSpecificField { field_index } => {
                write!(f, "HTTP/3 field {field_index} is connection-specific")
            }
            Self::InvalidTe { field_index } => {
                write!(f, "HTTP/3 TE field {field_index} is invalid")
            }
            Self::DuplicateHost { field_index } => write!(
                f,
                "HTTP/3 Host field {field_index} duplicates an earlier Host field"
            ),
            Self::MissingAuthorityOrHost => {
                f.write_str("HTTP/3 request is missing :authority and Host")
            }
            Self::InvalidAuthority { field_index } => {
                write!(f, "HTTP/3 :authority field {field_index} is invalid")
            }
            Self::InvalidHost { field_index } => {
                write!(f, "HTTP/3 Host field {field_index} is invalid")
            }
            Self::AuthorityHostMismatch {
                authority_field_index,
                host_field_index,
            } => write!(
                f,
                "HTTP/3 :authority field {authority_field_index} and Host field {host_field_index} differ"
            ),
            Self::InvalidMethod { field_index } => {
                write!(f, "HTTP/3 :method field {field_index} is invalid")
            }
            Self::InvalidScheme { field_index } => {
                write!(f, "HTTP/3 :scheme field {field_index} is invalid")
            }
            Self::InvalidPath { field_index } => {
                write!(f, "HTTP/3 :path field {field_index} is invalid")
            }
            Self::InvalidProtocol { field_index } => {
                write!(f, "HTTP/3 :protocol field {field_index} is invalid")
            }
            Self::InvalidConnectPseudoFields { field_index } => write!(
                f,
                "HTTP/3 ordinary CONNECT pseudo-field {field_index} is forbidden"
            ),
            Self::InvalidStatus { field_index } => {
                write!(f, "HTTP/3 :status field {field_index} is invalid")
            }
        }
    }
}

impl core::error::Error for Http3HeaderSectionError {}
