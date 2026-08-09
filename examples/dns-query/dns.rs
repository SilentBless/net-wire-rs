//! Small RFC 1035 query and response codec. Query names are ASCII only; no IDNA.

use core::fmt;

const HEADER_LEN: usize = 12;
const CLASS_IN: u16 = 1;
const MAX_NAME_LEN: usize = 255;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryType {
    A,
    Aaaa,
}
impl QueryType {
    pub const fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsError {
    BufferTooShort { required: usize, available: usize },
    InvalidName,
    NameTooLong,
    Truncated,
    InvalidLabel,
    InvalidPointer,
    PointerLoop,
    InvalidResponse,
    UnexpectedOpcode(u8),
    TransactionIdMismatch { expected: u16, actual: u16 },
}
impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooShort {
                required,
                available,
            } => write!(
                f,
                "DNS buffer is too short: need {required}, have {available}"
            ),
            Self::InvalidName => f.write_str("invalid DNS name"),
            Self::NameTooLong => f.write_str("DNS name exceeds 255 encoded bytes"),
            Self::Truncated => f.write_str("truncated DNS message"),
            Self::InvalidLabel => f.write_str("invalid DNS label"),
            Self::InvalidPointer => f.write_str("invalid DNS compression pointer"),
            Self::PointerLoop => f.write_str("DNS compression pointer loop"),
            Self::InvalidResponse => f.write_str("DNS message is not a response"),
            Self::UnexpectedOpcode(opcode) => write!(f, "unexpected DNS opcode {opcode}"),
            Self::TransactionIdMismatch { expected, actual } => write!(
                f,
                "DNS transaction ID mismatch: expected {expected:#06x}, got {actual:#06x}"
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub id: u16,
    pub flags: u16,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
}
impl Header {
    pub const fn is_response(self) -> bool {
        self.flags & 0x8000 != 0
    }
    pub const fn recursion_available(self) -> bool {
        self.flags & 0x0080 != 0
    }
    pub const fn response_code(self) -> u8 {
        (self.flags & 0x000f) as u8
    }
    pub const fn opcode(self) -> u8 {
        ((self.flags >> 11) & 0x0f) as u8
    }
    pub const fn truncated(self) -> bool {
        self.flags & 0x0200 != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Name<'a> {
    message: &'a [u8],
    offset: usize,
    consumed: usize,
}
impl<'a> Name<'a> {
    pub const fn consumed(self) -> usize {
        self.consumed
    }
    pub fn labels(self) -> Labels<'a> {
        Labels {
            message: self.message,
            offset: self.offset,
            steps: 0,
            expanded: 0,
            done: false,
        }
    }
}

pub struct Labels<'a> {
    message: &'a [u8],
    offset: usize,
    steps: usize,
    expanded: usize,
    done: bool,
}
impl<'a> Iterator for Labels<'a> {
    type Item = Result<&'a [u8], DnsError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        loop {
            if self.offset >= self.message.len() {
                self.done = true;
                return Some(Err(DnsError::Truncated));
            }
            if self.steps >= self.message.len() {
                self.done = true;
                return Some(Err(DnsError::PointerLoop));
            }
            self.steps += 1;
            let length = self.message[self.offset];
            if length == 0 {
                if self.expanded + 1 > MAX_NAME_LEN {
                    self.done = true;
                    return Some(Err(DnsError::NameTooLong));
                }
                self.done = true;
                return None;
            }
            if length & 0xc0 == 0xc0 {
                let next = match self.offset.checked_add(1) {
                    Some(value) => value,
                    None => {
                        self.done = true;
                        return Some(Err(DnsError::Truncated));
                    }
                };
                let tail = match self.message.get(next) {
                    Some(value) => *value,
                    None => {
                        self.done = true;
                        return Some(Err(DnsError::Truncated));
                    }
                };
                let pointer = usize::from(u16::from_be_bytes([length & 0x3f, tail]));
                if pointer >= self.message.len() {
                    self.done = true;
                    return Some(Err(DnsError::InvalidPointer));
                }
                self.offset = pointer;
                continue;
            }
            if length & 0xc0 != 0 || length > 63 {
                self.done = true;
                return Some(Err(DnsError::InvalidLabel));
            }
            let label_len = usize::from(length);
            let end = match self.offset.checked_add(label_len + 1) {
                Some(value) if value <= self.message.len() => value,
                _ => {
                    self.done = true;
                    return Some(Err(DnsError::Truncated));
                }
            };
            self.expanded += label_len + 1;
            if self.expanded + 1 > MAX_NAME_LEN {
                self.done = true;
                return Some(Err(DnsError::NameTooLong));
            }
            let label = &self.message[self.offset + 1..end];
            self.offset = end;
            return Some(Ok(label));
        }
    }
}

impl core::iter::FusedIterator for Labels<'_> {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Question<'a> {
    pub name: Name<'a>,
    pub kind: u16,
    pub class: u16,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordData<'a> {
    A([u8; 4]),
    Aaaa([u8; 16]),
    Other(&'a [u8]),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceRecord<'a> {
    pub name: Name<'a>,
    pub kind: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: RecordData<'a>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Message<'a> {
    bytes: &'a [u8],
    header: Header,
}

impl<'a> Message<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, DnsError> {
        if bytes.len() < HEADER_LEN {
            return Err(DnsError::Truncated);
        }
        let message = Self {
            bytes,
            header: Header {
                id: read_u16(bytes, 0),
                flags: read_u16(bytes, 2),
                question_count: read_u16(bytes, 4),
                answer_count: read_u16(bytes, 6),
                authority_count: read_u16(bytes, 8),
                additional_count: read_u16(bytes, 10),
            },
        };
        let mut offset = HEADER_LEN;
        for _ in 0..message.header.question_count {
            offset = parse_question(bytes, offset)?.1;
        }
        for _ in 0..message.header.answer_count {
            offset = parse_record(bytes, offset)?.1;
        }
        Ok(message)
    }
    pub const fn header(self) -> Header {
        self.header
    }
    pub fn require_response(self, transaction_id: u16) -> Result<Self, DnsError> {
        if !self.header.is_response() {
            return Err(DnsError::InvalidResponse);
        }
        if self.header.opcode() != 0 {
            return Err(DnsError::UnexpectedOpcode(self.header.opcode()));
        }
        if self.header.id != transaction_id {
            return Err(DnsError::TransactionIdMismatch {
                expected: transaction_id,
                actual: self.header.id,
            });
        }
        Ok(self)
    }
    #[cfg(test)]
    pub fn questions(self) -> Questions<'a> {
        Questions {
            message: self.bytes,
            offset: HEADER_LEN,
            remaining: self.header.question_count,
            failed: false,
        }
    }
    pub fn answers(self) -> Result<Records<'a>, DnsError> {
        Ok(Records {
            message: self.bytes,
            offset: skip_questions(self.bytes, self.header.question_count)?,
            remaining: self.header.answer_count,
            failed: false,
        })
    }
}

#[cfg(test)]
pub struct Questions<'a> {
    message: &'a [u8],
    offset: usize,
    remaining: u16,
    failed: bool,
}
#[cfg(test)]
impl<'a> Iterator for Questions<'a> {
    type Item = Result<Question<'a>, DnsError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 || self.failed {
            return None;
        }
        match parse_question(self.message, self.offset) {
            Ok((question, offset)) => {
                self.offset = offset;
                self.remaining -= 1;
                Some(Ok(question))
            }
            Err(error) => {
                self.failed = true;
                Some(Err(error))
            }
        }
    }
}
#[cfg(test)]
impl core::iter::FusedIterator for Questions<'_> {}

pub struct Records<'a> {
    message: &'a [u8],
    offset: usize,
    remaining: u16,
    failed: bool,
}
impl<'a> Iterator for Records<'a> {
    type Item = Result<ResourceRecord<'a>, DnsError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 || self.failed {
            return None;
        }
        match parse_record(self.message, self.offset) {
            Ok((record, offset)) => {
                self.offset = offset;
                self.remaining -= 1;
                Some(Ok(record))
            }
            Err(error) => {
                self.failed = true;
                Some(Err(error))
            }
        }
    }
}
impl core::iter::FusedIterator for Records<'_> {}

pub fn build_query(
    destination: &mut [u8],
    transaction_id: u16,
    qname: &str,
    query_type: QueryType,
) -> Result<usize, DnsError> {
    let name_length = encoded_name_len(qname)?;
    let required = HEADER_LEN + name_length + 4;
    if destination.len() < required {
        return Err(DnsError::BufferTooShort {
            required,
            available: destination.len(),
        });
    }
    destination[..HEADER_LEN].fill(0);
    destination[0..2].copy_from_slice(&transaction_id.to_be_bytes());
    destination[2..4].copy_from_slice(&0x0100u16.to_be_bytes());
    destination[4..6].copy_from_slice(&1u16.to_be_bytes());
    let name_end = HEADER_LEN
        + encode_name(
            &mut destination[HEADER_LEN..HEADER_LEN + name_length],
            qname,
        );
    destination[name_end..name_end + 2].copy_from_slice(&query_type.code().to_be_bytes());
    destination[name_end + 2..name_end + 4].copy_from_slice(&CLASS_IN.to_be_bytes());
    Ok(required)
}
fn encoded_name_len(name: &str) -> Result<usize, DnsError> {
    if name.is_empty() || name == "." {
        return Ok(1);
    }
    if !name.is_ascii() {
        return Err(DnsError::InvalidName);
    }
    let trimmed = match name.strip_suffix('.') {
        Some(trimmed) => trimmed,
        None => name,
    };
    if trimmed.is_empty() {
        return Err(DnsError::InvalidName);
    }
    let mut length = 1usize;
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(DnsError::InvalidName);
        }
        length = length
            .checked_add(label.len() + 1)
            .ok_or(DnsError::NameTooLong)?;
    }
    if length > MAX_NAME_LEN {
        return Err(DnsError::NameTooLong);
    }
    Ok(length)
}
fn encode_name(destination: &mut [u8], name: &str) -> usize {
    if name.is_empty() || name == "." {
        destination[0] = 0;
        return 1;
    }
    let trimmed = match name.strip_suffix('.') {
        Some(trimmed) => trimmed,
        None => name,
    };
    let mut offset = 0;
    for label in trimmed.split('.') {
        destination[offset] = label.len() as u8;
        offset += 1;
        let end = offset + label.len();
        destination[offset..end].copy_from_slice(label.as_bytes());
        offset = end;
    }
    destination[offset] = 0;
    offset + 1
}
fn skip_questions(message: &[u8], count: u16) -> Result<usize, DnsError> {
    let mut offset = HEADER_LEN;
    for _ in 0..count {
        offset = parse_question(message, offset)?.1;
    }
    Ok(offset)
}
fn parse_question<'a>(message: &'a [u8], offset: usize) -> Result<(Question<'a>, usize), DnsError> {
    let name = parse_name(message, offset)?;
    let fields = offset
        .checked_add(name.consumed())
        .ok_or(DnsError::Truncated)?;
    let end = fields.checked_add(4).ok_or(DnsError::Truncated)?;
    if end > message.len() {
        return Err(DnsError::Truncated);
    }
    Ok((
        Question {
            name,
            kind: read_u16(message, fields),
            class: read_u16(message, fields + 2),
        },
        end,
    ))
}
fn parse_record<'a>(
    message: &'a [u8],
    offset: usize,
) -> Result<(ResourceRecord<'a>, usize), DnsError> {
    let name = parse_name(message, offset)?;
    let fields = offset
        .checked_add(name.consumed())
        .ok_or(DnsError::Truncated)?;
    let data_start = fields.checked_add(10).ok_or(DnsError::Truncated)?;
    if data_start > message.len() {
        return Err(DnsError::Truncated);
    }
    let kind = read_u16(message, fields);
    let class = read_u16(message, fields + 2);
    let ttl = read_u32(message, fields + 4);
    let data_len = usize::from(read_u16(message, fields + 8));
    let end = data_start
        .checked_add(data_len)
        .ok_or(DnsError::Truncated)?;
    if end > message.len() {
        return Err(DnsError::Truncated);
    }
    let bytes = &message[data_start..end];
    let data = match (kind, class, data_len) {
        (1, CLASS_IN, 4) => RecordData::A([bytes[0], bytes[1], bytes[2], bytes[3]]),
        (28, CLASS_IN, 16) => RecordData::Aaaa(bytes.try_into().map_err(|_| DnsError::Truncated)?),
        _ => RecordData::Other(bytes),
    };
    Ok((
        ResourceRecord {
            name,
            kind,
            class,
            ttl,
            data,
        },
        end,
    ))
}
fn parse_name<'a>(message: &'a [u8], offset: usize) -> Result<Name<'a>, DnsError> {
    let labels = Name {
        message,
        offset,
        consumed: 0,
    }
    .labels();
    for label in labels {
        label?;
    }
    let mut position = offset;
    loop {
        let byte = *message.get(position).ok_or(DnsError::Truncated)?;
        if byte == 0 {
            return Ok(Name {
                message,
                offset,
                consumed: position + 1 - offset,
            });
        }
        if byte & 0xc0 == 0xc0 {
            if message.get(position + 1).is_none() {
                return Err(DnsError::Truncated);
            }
            return Ok(Name {
                message,
                offset,
                consumed: position + 2 - offset,
            });
        }
        if byte & 0xc0 != 0 || byte > 63 {
            return Err(DnsError::InvalidLabel);
        }
        position = position
            .checked_add(usize::from(byte) + 1)
            .ok_or(DnsError::Truncated)?;
    }
}
fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}
fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn query_is_atomic_and_ascii_only() {
        let mut short = [0xa5; 16];
        let before = short;
        assert!(build_query(&mut short, 1, "example.com", QueryType::A).is_err());
        assert_eq!(short, before);
        let mut bytes = [0xa5; 64];
        let before = bytes;
        assert_eq!(
            build_query(&mut bytes, 1, "éxample.com", QueryType::A),
            Err(DnsError::InvalidName)
        );
        assert_eq!(bytes, before);
    }
    #[test]
    fn query_rejects_bad_labels() {
        let mut bytes = [0; 512];
        assert!(build_query(&mut bytes, 1, ".example", QueryType::A).is_err());
        assert!(build_query(&mut bytes, 1, "a..b", QueryType::A).is_err());
        assert_eq!(build_query(&mut bytes, 1, ".", QueryType::A).unwrap(), 17);
    }
    #[test]
    fn aaaa_query_and_question_iteration_are_preserved() {
        let mut bytes = [0; 64];
        let length = build_query(&mut bytes, 7, "example.test", QueryType::Aaaa).unwrap();
        let message = Message::parse(&bytes[..length]).unwrap();
        let question = message.questions().next().unwrap().unwrap();
        assert_eq!(question.kind, QueryType::Aaaa.code());
        assert_eq!(question.class, CLASS_IN);
        assert_eq!(
            question
                .name
                .labels()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![b"example".as_slice(), b"test".as_slice()]
        );
    }
    #[test]
    fn compressed_name_consumes_pointer_only() {
        let bytes = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, b'w', b'w', b'w', 0, 0xc0, 12,
        ];
        let name = parse_name(&bytes, 17).unwrap();
        assert_eq!(name.consumed(), 2);
        assert_eq!(
            name.labels().collect::<Result<Vec<_>, _>>().unwrap(),
            vec![b"www".as_slice()]
        );
    }
    #[test]
    fn bad_compression_fails_closed() {
        let looped = [0u8; 14];
        let mut looped = looped;
        looped[12] = 0xc0;
        looped[13] = 12;
        assert_eq!(parse_name(&looped, 12), Err(DnsError::PointerLoop));
        let out = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0xff];
        assert_eq!(parse_name(&out, 12), Err(DnsError::InvalidPointer));
        let mut labels = Name {
            message: &[0xc0, 2],
            offset: 0,
            consumed: 2,
        }
        .labels();
        assert!(labels.next().unwrap().is_err());
        assert_eq!(labels.next(), None);
    }
    #[test]
    fn expanded_compressed_name_is_bounded() {
        let mut bytes = [0u8; 270];
        let mut offset = 0;
        for _ in 0..4 {
            bytes[offset] = 63;
            offset += 1;
            bytes[offset..offset + 63].fill(b'a');
            offset += 63;
        }
        bytes[offset] = 0;
        assert_eq!(
            parse_name(&bytes[..offset + 1], 0),
            Err(DnsError::NameTooLong)
        );
    }
    #[test]
    fn records_preserve_other_data() {
        let bytes = [
            0, 1, 0x81, 0x80, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4,
            0, 0, 28, 0, 1, 0, 0, 0, 1, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0,
            0, 99, 0, 3, 0, 0, 0, 1, 0, 2, 8, 9,
        ];
        let records: Vec<_> = Message::parse(&bytes)
            .unwrap()
            .answers()
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(matches!(records[0].data, RecordData::A(_)));
        assert!(matches!(records[1].data, RecordData::Aaaa(_)));
        assert_eq!(records[2].data, RecordData::Other(&[8, 9]));
    }
    #[test]
    fn response_checks_id_qr_and_opcode() {
        let mut bytes = [0; 12];
        assert_eq!(
            Message::parse(&bytes).unwrap().require_response(1),
            Err(DnsError::InvalidResponse)
        );
        bytes[2] = 0x88;
        assert!(matches!(
            Message::parse(&bytes).unwrap().require_response(1),
            Err(DnsError::UnexpectedOpcode(1))
        ));
        bytes[2] = 0x82;
        bytes[3] = 0x83;
        let header = Message::parse(&bytes).unwrap().header();
        assert!(header.truncated());
        assert!(header.recursion_available());
        assert_eq!(header.response_code(), 3);
        assert!(matches!(
            Message::parse(&bytes).unwrap().require_response(1),
            Err(DnsError::TransactionIdMismatch { .. })
        ));
    }
}
