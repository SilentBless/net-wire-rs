//! ICMPv4 caller-buffer builder.

use core::fmt;

use super::message::{HEADER_LENGTH, Icmpv4MessageMut};
use super::types::Icmpv4Type;

/// Failure to construct an ICMPv4 message in caller-provided storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Icmpv4MessageBuildError {
    /// The type was not supplied.
    MissingType,
    /// The code was not supplied.
    MissingCode,
    /// The requested common header and body length cannot be represented as a `usize`.
    MessageLengthTooLarge,
    /// The buffer cannot hold the requested message.
    BufferTooShort {
        /// Required bytes.
        required: usize,
        /// Available bytes.
        available: usize,
    },
}

impl fmt::Display for Icmpv4MessageBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingType => formatter.write_str("missing ICMPv4 type"),
            Self::MissingCode => formatter.write_str("missing ICMPv4 code"),
            Self::MessageLengthTooLarge => {
                formatter.write_str("ICMPv4 message length exceeds the platform limit")
            }
            Self::BufferTooShort {
                required,
                available,
            } => write!(
                formatter,
                "ICMPv4 buffer is too short: need {required} bytes, have {available}"
            ),
        }
    }
}

/// Builds an ICMPv4 common header in caller-owned storage.
pub struct Icmpv4MessageBuilder<'a> {
    buffer: &'a mut [u8],
    body_length: usize,
    message_type: Option<Icmpv4Type>,
    code: Option<u8>,
}

impl<'a> Icmpv4MessageBuilder<'a> {
    /// Starts a builder for `body_length` bytes, which are left untouched.
    pub fn new(buffer: &'a mut [u8], body_length: usize) -> Self {
        Self {
            buffer,
            body_length,
            message_type: None,
            code: None,
        }
    }
    /// Supplies the ICMPv4 message type.
    pub fn message_type(mut self, value: Icmpv4Type) -> Self {
        self.message_type = Some(value);
        self
    }
    /// Supplies the ICMPv4 message code.
    pub fn code(mut self, value: u8) -> Self {
        self.code = Some(value);
        self
    }
    /// Validates all inputs, writes the common header, and computes its complete checksum.
    ///
    /// Body bytes and capacity beyond the requested message are preserved. On error, the whole
    /// caller-provided buffer is unchanged.
    pub fn build(self) -> Result<Icmpv4MessageMut<'a>, Icmpv4MessageBuildError> {
        let message_type = self
            .message_type
            .ok_or(Icmpv4MessageBuildError::MissingType)?;
        let code = self.code.ok_or(Icmpv4MessageBuildError::MissingCode)?;
        let length = HEADER_LENGTH
            .checked_add(self.body_length)
            .ok_or(Icmpv4MessageBuildError::MessageLengthTooLarge)?;
        if self.buffer.len() < length {
            return Err(Icmpv4MessageBuildError::BufferTooShort {
                required: length,
                available: self.buffer.len(),
            });
        }
        let bytes = &mut self.buffer[..length];
        bytes[0] = message_type.raw();
        bytes[1] = code;
        bytes[2] = 0;
        bytes[3] = 0;
        let mut result = Icmpv4MessageMut::from_validated(bytes);
        result.update_checksum();
        Ok(result)
    }
}
