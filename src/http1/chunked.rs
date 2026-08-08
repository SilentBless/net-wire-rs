//! Chunked HTTP/1 body views.

use super::error::Http1ParseError;
use super::fields::{Http1Fields, LineEndError, find_line_end, is_token};

/// A validated nonzero HTTP/1 chunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http1Chunk<'a> {
    size: usize,
    data: &'a [u8],
    extensions: &'a [u8],
}

impl<'a> Http1Chunk<'a> {
    /// Returns the decoded chunk size.
    pub const fn size(self) -> usize {
        self.size
    }

    /// Returns the raw chunk data.
    pub const fn data(self) -> &'a [u8] {
        self.data
    }

    /// Returns the raw extension suffix, including its first semicolon and any optional whitespace.
    pub const fn extensions(self) -> &'a [u8] {
        self.extensions
    }
}

/// A complete, exactly bounded chunked HTTP/1 body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http1ChunkedBody<'a> {
    bytes: &'a [u8],
    chunks_end: usize,
    decoded_len: usize,
    last_chunk_extensions: &'a [u8],
    trailers: Http1Fields<'a>,
}

impl<'a> Http1ChunkedBody<'a> {
    /// Parses one complete chunked body through its trailer terminator.
    ///
    /// Framing and routing fields that are unambiguously forbidden in trailers are rejected.
    /// Callers remain responsible for field-specific semantic restrictions on other trailers.
    pub fn parse(input: &'a [u8]) -> Result<Self, Http1ParseError> {
        let mut offset = 0;
        let mut decoded_len = 0usize;
        loop {
            let line_end = chunk_line_end(input, offset)?;
            let line = &input[offset..line_end];
            let parsed = parse_chunk_line(line)?;
            let after_line = line_end + 2;
            if parsed.size == 0 {
                let trailer_start = after_line;
                let mut trailer_offset = trailer_start;
                loop {
                    let trailer_end = trailer_line_end(input, trailer_offset)?;
                    if trailer_end == trailer_offset {
                        let trailers =
                            Http1Fields::parse(&input[trailer_start..trailer_offset], true)?;
                        return Ok(Self {
                            bytes: &input[..trailer_end + 2],
                            chunks_end: offset,
                            decoded_len,
                            last_chunk_extensions: parsed.extensions,
                            trailers,
                        });
                    }
                    trailer_offset = trailer_end + 2;
                }
            }

            decoded_len = decoded_len
                .checked_add(parsed.size)
                .ok_or(Http1ParseError::DecodedSizeOverflow)?;
            let data_end = after_line
                .checked_add(parsed.size)
                .ok_or(Http1ParseError::ChunkSizeOverflow)?;
            let required = data_end
                .checked_add(2)
                .ok_or(Http1ParseError::ChunkSizeOverflow)?;
            if input.len() < required {
                return Err(Http1ParseError::Incomplete {
                    required,
                    available: input.len(),
                });
            }
            if &input[data_end..required] != b"\r\n" {
                return Err(Http1ParseError::InvalidChunkTerminator);
            }
            offset = required;
        }
    }

    /// Returns the complete represented chunked-body encoding.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the sum of decoded nonzero chunk sizes.
    pub const fn decoded_len(self) -> usize {
        self.decoded_len
    }

    /// Returns raw final-chunk extension bytes, including the first semicolon and optional whitespace.
    pub const fn last_chunk_extensions(self) -> &'a [u8] {
        self.last_chunk_extensions
    }

    /// Returns ordered trailer fields that passed structural and wire-framing restrictions.
    pub const fn trailers(self) -> Http1Fields<'a> {
        self.trailers
    }

    /// Iterates validated nonzero chunks in wire order.
    pub fn chunks(self) -> Http1Chunks<'a> {
        Http1Chunks {
            bytes: &self.bytes[..self.chunks_end],
            offset: 0,
        }
    }
}

/// Iterator over validated nonzero HTTP/1 chunks.
#[derive(Clone, Debug)]
pub struct Http1Chunks<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for Http1Chunks<'a> {
    type Item = Http1Chunk<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset == self.bytes.len() {
            return None;
        }
        let line_end = find_line_end(self.bytes, self.offset).ok()?;
        let parsed = parse_chunk_line(&self.bytes[self.offset..line_end]).ok()?;
        let data_start = line_end + 2;
        let data_end = data_start + parsed.size;
        self.offset = data_end + 2;
        Some(Http1Chunk {
            size: parsed.size,
            data: &self.bytes[data_start..data_end],
            extensions: parsed.extensions,
        })
    }
}

struct ParsedChunkLine<'a> {
    size: usize,
    extensions: &'a [u8],
}

fn parse_chunk_line(line: &[u8]) -> Result<ParsedChunkLine<'_>, Http1ParseError> {
    let mut offset = 0;
    let mut size = 0usize;
    while let Some(digit) = line.get(offset).and_then(|byte| hex_value(*byte)) {
        size = size
            .checked_mul(16)
            .and_then(|size| size.checked_add(usize::from(digit)))
            .ok_or(Http1ParseError::ChunkSizeOverflow)?;
        offset += 1;
    }
    if offset == 0 {
        return Err(Http1ParseError::InvalidChunkSize);
    }
    let extension_start = offset;
    validate_chunk_extensions(&line[extension_start..])?;
    Ok(ParsedChunkLine {
        size,
        extensions: &line[extension_start..],
    })
}

fn validate_chunk_extensions(bytes: &[u8]) -> Result<(), Http1ParseError> {
    if bytes.is_empty() {
        return Ok(());
    }
    let mut offset = 0;
    skip_ows(bytes, &mut offset);
    if offset == bytes.len() {
        return Err(Http1ParseError::InvalidChunkSize);
    }
    while offset < bytes.len() {
        if bytes[offset] != b';' {
            return Err(Http1ParseError::InvalidChunkSize);
        }
        offset += 1;
        skip_ows(bytes, &mut offset);
        parse_token(bytes, &mut offset)?;
        skip_ows(bytes, &mut offset);
        if bytes.get(offset) == Some(&b'=') {
            offset += 1;
            skip_ows(bytes, &mut offset);
            parse_token_or_quoted(bytes, &mut offset)?;
            skip_ows(bytes, &mut offset);
        }
    }
    Ok(())
}

fn parse_token(bytes: &[u8], offset: &mut usize) -> Result<(), Http1ParseError> {
    let start = *offset;
    while bytes.get(*offset).is_some_and(|byte| is_token(*byte)) {
        *offset += 1;
    }
    if *offset == start {
        return Err(Http1ParseError::InvalidChunkSize);
    }
    Ok(())
}

fn parse_token_or_quoted(bytes: &[u8], offset: &mut usize) -> Result<(), Http1ParseError> {
    if bytes.get(*offset) != Some(&b'"') {
        return parse_token(bytes, offset);
    }
    *offset += 1;
    loop {
        let byte = *bytes
            .get(*offset)
            .ok_or(Http1ParseError::InvalidChunkSize)?;
        match byte {
            b'"' => {
                *offset += 1;
                return Ok(());
            }
            b'\\' => {
                *offset += 1;
                let escaped = *bytes
                    .get(*offset)
                    .ok_or(Http1ParseError::InvalidChunkSize)?;
                if !matches!(escaped, b'\t' | b' ' | 0x21..=0x7e | 0x80..=0xff) {
                    return Err(Http1ParseError::InvalidChunkSize);
                }
                *offset += 1;
            }
            b'\t' | b' ' | 0x21 | 0x23..=0x5b | 0x5d..=0x7e | 0x80..=0xff => *offset += 1,
            _ => return Err(Http1ParseError::InvalidChunkSize),
        }
    }
}

fn skip_ows(bytes: &[u8], offset: &mut usize) {
    while matches!(bytes.get(*offset), Some(b' ' | b'\t')) {
        *offset += 1;
    }
}

fn chunk_line_end(input: &[u8], offset: usize) -> Result<usize, Http1ParseError> {
    match find_line_end(input, offset) {
        Ok(end) => Ok(end),
        Err(LineEndError::Incomplete) => Err(Http1ParseError::Incomplete {
            required: input.len().saturating_add(1),
            available: input.len(),
        }),
        Err(LineEndError::Malformed) => Err(Http1ParseError::InvalidChunkSize),
    }
}

fn trailer_line_end(input: &[u8], offset: usize) -> Result<usize, Http1ParseError> {
    match find_line_end(input, offset) {
        Ok(end) => Ok(end),
        Err(LineEndError::Incomplete) => Err(Http1ParseError::Incomplete {
            required: input.len().saturating_add(1),
            available: input.len(),
        }),
        Err(LineEndError::Malformed) => Err(Http1ParseError::InvalidTrailer),
    }
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
