//! HTTP/1 message-body framing.

use super::error::Http1ParseError;
use super::fields::{Http1Fields, eq_ascii_case, is_token, trim_ows};

/// HTTP/1 body framing selected by RFC 9112.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http1BodyFraming {
    /// The message has no body.
    None,
    /// The body has the encoded fixed length.
    ContentLength(usize),
    /// The body uses chunked transfer coding.
    Chunked,
    /// A response body ends when the connection closes.
    CloseDelimited,
    /// A successful CONNECT response switches to tunnel data.
    Tunnel,
}

pub(crate) fn framing(
    fields: Http1Fields<'_>,
    request: bool,
    status: Option<u16>,
    method: Option<&[u8]>,
) -> Result<Http1BodyFraming, Http1ParseError> {
    if !request
        && (method == Some(b"HEAD" as &[u8]) || matches!(status, Some(100..=199 | 204 | 304)))
    {
        return Ok(Http1BodyFraming::None);
    }
    if !request && method == Some(b"CONNECT" as &[u8]) && matches!(status, Some(200..=299)) {
        return Ok(Http1BodyFraming::Tunnel);
    }

    let has_content_length = fields.iter().any(|field| field.name_eq(b"content-length"));
    let has_transfer_encoding = fields
        .iter()
        .any(|field| field.name_eq(b"transfer-encoding"));
    if has_content_length && has_transfer_encoding {
        return Err(Http1ParseError::TransferEncodingWithContentLength);
    }

    if has_transfer_encoding {
        let final_chunked = parse_transfer_encoding(fields)?;
        if final_chunked {
            return Ok(Http1BodyFraming::Chunked);
        }
        if request {
            return Err(Http1ParseError::InvalidTransferEncoding);
        }
        return Ok(Http1BodyFraming::CloseDelimited);
    }

    if has_content_length {
        return Ok(Http1BodyFraming::ContentLength(parse_content_length(
            fields,
        )?));
    }

    Ok(if request {
        Http1BodyFraming::None
    } else {
        Http1BodyFraming::CloseDelimited
    })
}

fn parse_content_length(fields: Http1Fields<'_>) -> Result<usize, Http1ParseError> {
    let mut selected = None;
    for field in fields
        .iter()
        .filter(|field| field.name_eq(b"content-length"))
    {
        for member in field.raw_value().split(|byte| *byte == b',') {
            let member = trim_ows(member);
            if member.is_empty() || !member.iter().all(u8::is_ascii_digit) {
                return Err(Http1ParseError::InvalidContentLength);
            }
            let mut value = 0usize;
            for byte in member {
                value = value
                    .checked_mul(10)
                    .and_then(|value| value.checked_add(usize::from(*byte - b'0')))
                    .ok_or(Http1ParseError::ContentLengthOverflow)?;
            }
            match selected {
                Some(previous) if previous != value => {
                    return Err(Http1ParseError::ConflictingContentLength);
                }
                _ => selected = Some(value),
            }
        }
    }
    selected.ok_or(Http1ParseError::InvalidContentLength)
}

#[derive(Default)]
struct TransferState {
    seen: bool,
    chunked_seen: bool,
    final_chunked: bool,
}

fn parse_transfer_encoding(fields: Http1Fields<'_>) -> Result<bool, Http1ParseError> {
    let mut state = TransferState::default();
    for field in fields
        .iter()
        .filter(|field| field.name_eq(b"transfer-encoding"))
    {
        parse_transfer_value(field.raw_value(), &mut state)?;
    }
    if !state.seen {
        return Err(Http1ParseError::InvalidTransferEncoding);
    }
    Ok(state.final_chunked)
}

fn parse_transfer_value(value: &[u8], state: &mut TransferState) -> Result<(), Http1ParseError> {
    let mut offset = 0;
    loop {
        skip_ows(value, &mut offset);
        if offset == value.len() {
            return Err(Http1ParseError::InvalidTransferEncoding);
        }
        if state.chunked_seen {
            return Err(Http1ParseError::InvalidChunkedTransferEncoding);
        }

        let coding_start = offset;
        parse_token(value, &mut offset)?;
        let is_chunked = eq_ascii_case(&value[coding_start..offset], b"chunked");
        skip_ows(value, &mut offset);

        let mut has_parameters = false;
        while value.get(offset) == Some(&b';') {
            has_parameters = true;
            offset += 1;
            skip_ows(value, &mut offset);
            parse_token(value, &mut offset)?;
            skip_ows(value, &mut offset);
            if value.get(offset) != Some(&b'=') {
                return Err(Http1ParseError::InvalidTransferEncoding);
            }
            offset += 1;
            skip_ows(value, &mut offset);
            parse_token_or_quoted(value, &mut offset)?;
            skip_ows(value, &mut offset);
        }
        if is_chunked && has_parameters {
            return Err(Http1ParseError::InvalidChunkedTransferEncoding);
        }

        state.seen = true;
        state.chunked_seen |= is_chunked;
        state.final_chunked = is_chunked;
        if offset == value.len() {
            return Ok(());
        }
        if value[offset] != b',' {
            return Err(Http1ParseError::InvalidTransferEncoding);
        }
        offset += 1;
    }
}

fn parse_token(value: &[u8], offset: &mut usize) -> Result<(), Http1ParseError> {
    let start = *offset;
    while value.get(*offset).is_some_and(|byte| is_token(*byte)) {
        *offset += 1;
    }
    if *offset == start {
        return Err(Http1ParseError::InvalidTransferEncoding);
    }
    Ok(())
}

fn parse_token_or_quoted(value: &[u8], offset: &mut usize) -> Result<(), Http1ParseError> {
    if value.get(*offset) != Some(&b'"') {
        return parse_token(value, offset);
    }
    *offset += 1;
    loop {
        let byte = *value
            .get(*offset)
            .ok_or(Http1ParseError::InvalidTransferEncoding)?;
        match byte {
            b'"' => {
                *offset += 1;
                return Ok(());
            }
            b'\\' => {
                *offset += 1;
                let escaped = *value
                    .get(*offset)
                    .ok_or(Http1ParseError::InvalidTransferEncoding)?;
                if !matches!(escaped, b'\t' | b' ' | 0x21..=0x7e | 0x80..=0xff) {
                    return Err(Http1ParseError::InvalidTransferEncoding);
                }
                *offset += 1;
            }
            b'\t' | b' ' | 0x21 | 0x23..=0x5b | 0x5d..=0x7e | 0x80..=0xff => *offset += 1,
            _ => return Err(Http1ParseError::InvalidTransferEncoding),
        }
    }
}

fn skip_ows(value: &[u8], offset: &mut usize) {
    while matches!(value.get(*offset), Some(b' ' | b'\t')) {
        *offset += 1;
    }
}
