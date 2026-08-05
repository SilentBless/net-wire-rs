//! ICMPv6 caller-buffer builder.

use core::fmt;

use super::{Icmpv6MessageMut, Icmpv6Type};

const HEADER_LENGTH: usize = 4;

/// Failure to construct an ICMPv6 message in caller-provided storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Icmpv6MessageBuildError {
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

impl fmt::Display for Icmpv6MessageBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingType => formatter.write_str("missing ICMPv6 type"),
            Self::MissingCode => formatter.write_str("missing ICMPv6 code"),
            Self::MessageLengthTooLarge => {
                formatter.write_str("ICMPv6 message length exceeds the platform limit")
            }
            Self::BufferTooShort {
                required,
                available,
            } => write!(
                formatter,
                "ICMPv6 buffer is too short: need {required} bytes, have {available}"
            ),
        }
    }
}

/// Builds an ICMPv6 common header in caller-owned storage.
pub struct Icmpv6MessageBuilder<'a> {
    buffer: &'a mut [u8],
    body_length: usize,
    message_type: Option<Icmpv6Type>,
    code: Option<u8>,
    checksum: u16,
}

impl<'a> Icmpv6MessageBuilder<'a> {
    /// Starts a builder for `body_length` bytes, which are left untouched.
    #[inline]
    pub fn new(buffer: &'a mut [u8], body_length: usize) -> Self {
        Self {
            buffer,
            body_length,
            message_type: None,
            code: None,
            checksum: 0,
        }
    }

    /// Supplies the ICMPv6 message type.
    #[inline]
    pub fn message_type(mut self, value: Icmpv6Type) -> Self {
        self.message_type = Some(value);
        self
    }

    /// Supplies the ICMPv6 message code.
    #[inline]
    pub fn code(mut self, value: u8) -> Self {
        self.code = Some(value);
        self
    }

    /// Supplies the encoded checksum; it defaults to zero.
    #[inline]
    pub fn checksum(mut self, value: u16) -> Self {
        self.checksum = value;
        self
    }

    /// Validates all inputs, then writes only the common header.
    ///
    /// Body bytes and capacity beyond the requested message are preserved. On error, the whole
    /// caller-provided buffer is unchanged.
    #[inline]
    pub fn build(self) -> Result<Icmpv6MessageMut<'a>, Icmpv6MessageBuildError> {
        let message_type = self
            .message_type
            .ok_or(Icmpv6MessageBuildError::MissingType)?;
        let code = self.code.ok_or(Icmpv6MessageBuildError::MissingCode)?;
        let length = HEADER_LENGTH
            .checked_add(self.body_length)
            .ok_or(Icmpv6MessageBuildError::MessageLengthTooLarge)?;
        if self.buffer.len() < length {
            return Err(Icmpv6MessageBuildError::BufferTooShort {
                required: length,
                available: self.buffer.len(),
            });
        }

        let bytes = &mut self.buffer[..length];
        bytes[0] = message_type.raw();
        bytes[1] = code;
        bytes[2..4].copy_from_slice(&self.checksum.to_be_bytes());
        Ok(Icmpv6MessageMut::from_validated(bytes))
    }
}
