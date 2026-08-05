//! HTTP/1 field views.

use super::Http1ParseError;

/// A caller-supplied HTTP/1 field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http1FieldRef<'a> {
    name: &'a [u8],
    value: &'a [u8],
}

impl<'a> Http1FieldRef<'a> {
    /// Creates a field reference.
    pub const fn new(name: &'a [u8], value: &'a [u8]) -> Self {
        Self { name, value }
    }

    /// Returns the field name without a colon.
    pub const fn name(self) -> &'a [u8] {
        self.name
    }

    /// Returns the field value.
    pub const fn value(self) -> &'a [u8] {
        self.value
    }
}

/// A validated HTTP/1 field line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http1Field<'a> {
    line: &'a [u8],
    colon: usize,
}

impl<'a> Http1Field<'a> {
    /// Returns the field line without its terminating CRLF.
    pub const fn raw_line(self) -> &'a [u8] {
        self.line
    }

    /// Returns the original field-name spelling.
    pub fn name(self) -> &'a [u8] {
        &self.line[..self.colon]
    }

    /// Returns the raw value immediately after the colon.
    pub fn raw_value(self) -> &'a [u8] {
        &self.line[self.colon + 1..]
    }

    /// Returns the field value with leading and trailing optional whitespace removed.
    pub fn value(self) -> &'a [u8] {
        trim_ows(self.raw_value())
    }

    /// Compares the field name using ASCII case-insensitive matching.
    pub fn name_eq(self, name: &[u8]) -> bool {
        eq_ascii_case(self.name(), name)
    }
}

/// Ordered, validated HTTP/1 fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http1Fields<'a> {
    bytes: &'a [u8],
}

impl<'a> Http1Fields<'a> {
    pub(crate) fn parse(bytes: &'a [u8], trailer: bool) -> Result<Self, Http1ParseError> {
        let error = if trailer {
            Http1ParseError::InvalidTrailer
        } else {
            Http1ParseError::InvalidField
        };
        let mut offset = 0;
        while offset < bytes.len() {
            let end = match find_line_end(bytes, offset) {
                Ok(end) => end,
                Err(LineEndError::Incomplete) => {
                    return Err(Http1ParseError::Incomplete {
                        required: bytes.len().saturating_add(1),
                        available: bytes.len(),
                    });
                }
                Err(LineEndError::Malformed) => return Err(error),
            };
            if end == offset {
                return Err(error);
            }
            let line = &bytes[offset..end];
            validate_field_line(line).map_err(|()| error)?;
            if trailer && forbidden_trailer_line(line) {
                return Err(Http1ParseError::InvalidTrailer);
            }
            offset = end + 2;
        }
        Ok(Self { bytes })
    }

    pub(crate) const fn from_validated(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Returns encoded field lines without the terminating blank line.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Iterates fields in wire order without combining duplicates.
    pub const fn iter(self) -> Http1FieldIter<'a> {
        Http1FieldIter {
            bytes: self.bytes,
            offset: 0,
        }
    }
}

impl<'a> IntoIterator for Http1Fields<'a> {
    type Item = Http1Field<'a>;
    type IntoIter = Http1FieldIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator over validated HTTP/1 fields.
#[derive(Clone, Debug)]
pub struct Http1FieldIter<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for Http1FieldIter<'a> {
    type Item = Http1Field<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset == self.bytes.len() {
            return None;
        }
        let end = find_line_end(self.bytes, self.offset).ok()?;
        let line = &self.bytes[self.offset..end];
        self.offset = end + 2;
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .expect("validated field contains a colon");
        Some(Http1Field { line, colon })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LineEndError {
    Incomplete,
    Malformed,
}

pub(crate) fn find_line_end(bytes: &[u8], start: usize) -> Result<usize, LineEndError> {
    let mut offset = start;
    while offset < bytes.len() {
        match bytes[offset] {
            b'\r' => {
                if offset + 1 == bytes.len() {
                    return Err(LineEndError::Incomplete);
                }
                if bytes[offset + 1] != b'\n' {
                    return Err(LineEndError::Malformed);
                }
                return Ok(offset);
            }
            b'\n' => return Err(LineEndError::Malformed),
            _ => offset += 1,
        }
    }
    Err(LineEndError::Incomplete)
}

pub(crate) fn trim_ows(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}

pub(crate) fn eq_ascii_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

pub(crate) const fn is_token(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^'
            | b'_' | b'`' | b'|' | b'~' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'
    )
}

pub(crate) fn validate_field_line(line: &[u8]) -> Result<(), ()> {
    let colon = line.iter().position(|byte| *byte == b':').ok_or(())?;
    if colon == 0 || !line[..colon].iter().copied().all(is_token) {
        return Err(());
    }
    if !valid_field_value(&line[colon + 1..]) {
        return Err(());
    }
    Ok(())
}

pub(crate) fn validate_field_ref(field: Http1FieldRef<'_>) -> bool {
    !field.name.is_empty()
        && field.name.iter().copied().all(is_token)
        && valid_field_value(field.value)
}

fn valid_field_value(value: &[u8]) -> bool {
    !value
        .iter()
        .any(|byte| matches!(*byte, 0..=8 | 10..=31 | 127))
}

fn forbidden_trailer_line(line: &[u8]) -> bool {
    let colon = line
        .iter()
        .position(|byte| *byte == b':')
        .expect("validated field contains a colon");
    let name = &line[..colon];
    [
        b"content-length" as &[u8],
        b"transfer-encoding",
        b"host",
        b"trailer",
        b"te",
    ]
    .iter()
    .any(|forbidden| eq_ascii_case(name, forbidden))
}
