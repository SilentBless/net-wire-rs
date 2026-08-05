//! Internal IPv6 extension-header traversal.

use super::Ipv6NextHeader;
use crate::ParseError;

pub(super) struct ExtensionTraversal {
    pub(super) next_header: u8,
    pub(super) upper_offset: usize,
    pub(super) non_atomic_fragment: bool,
}

pub(super) fn traverse(
    next_header: Ipv6NextHeader,
    raw_payload_length: u16,
    payload: &[u8],
) -> Result<ExtensionTraversal, ParseError> {
    if raw_payload_length == 0 && !payload.is_empty() {
        return Err(ParseError::UnresolvedPayloadLength);
    }

    let mut next_header = next_header.raw();
    let mut offset = 0;
    let mut non_atomic_fragment = false;
    loop {
        let length = match next_header {
            0 | 43 | 60 => {
                let header = prefix(payload, offset, 2)?;
                usize::from(header[1])
                    .checked_add(1)
                    .and_then(|length| length.checked_mul(8))
                    .ok_or(ParseError::Truncated {
                        minimum: usize::MAX,
                        available: payload.len(),
                    })?
            }
            44 => {
                let header = prefix(payload, offset, 8)?;
                let fragment = u16::from_be_bytes([header[2], header[3]]);
                non_atomic_fragment |= fragment & 0xfff8 != 0 || fragment & 1 != 0;
                next_header = header[0];
                offset = end(payload, offset, 8)?;
                if non_atomic_fragment {
                    return Ok(ExtensionTraversal {
                        next_header,
                        upper_offset: offset,
                        non_atomic_fragment,
                    });
                }
                continue;
            }
            51 => {
                let header = prefix(payload, offset, 2)?;
                let length = usize::from(header[1])
                    .checked_add(2)
                    .and_then(|length| length.checked_mul(4))
                    .ok_or(ParseError::Truncated {
                        minimum: usize::MAX,
                        available: payload.len(),
                    })?;
                if length < 12 {
                    return Err(ParseError::InvalidExtensionHeaderLength {
                        next_header,
                        minimum: 12,
                        actual: length,
                    });
                }
                length
            }
            50 | 59 | 6 | 17 | 58 => {
                return Ok(ExtensionTraversal {
                    next_header,
                    upper_offset: offset,
                    non_atomic_fragment,
                });
            }
            _ => {
                return Ok(ExtensionTraversal {
                    next_header,
                    upper_offset: offset,
                    non_atomic_fragment,
                });
            }
        };

        let header = prefix(payload, offset, length)?;
        next_header = header[0];
        offset = end(payload, offset, length)?;
    }
}

#[inline]
fn prefix(payload: &[u8], offset: usize, length: usize) -> Result<&[u8], ParseError> {
    let end = end(payload, offset, length)?;
    Ok(&payload[offset..end])
}

#[inline]
fn end(payload: &[u8], offset: usize, length: usize) -> Result<usize, ParseError> {
    let end = offset.checked_add(length).ok_or(ParseError::Truncated {
        minimum: usize::MAX,
        available: payload.len(),
    })?;
    if payload.len() < end {
        return Err(ParseError::Truncated {
            minimum: end,
            available: payload.len(),
        });
    }
    Ok(end)
}
