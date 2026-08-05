//! HTTP/1 head builders.

use super::fields::{is_token, validate_field_ref};
use super::head::{valid_reason, valid_request_target};
use super::{Http1BuildError, Http1FieldRef, Http1RequestHead, Http1ResponseHead, Http1Version};

/// Builds an HTTP/1 request head in caller-owned storage.
pub struct Http1RequestHeadBuilder<'output, 'input, 'fields> {
    buffer: &'output mut [u8],
    method: &'input [u8],
    target: &'input [u8],
    version: Http1Version,
    fields: &'fields [Http1FieldRef<'input>],
}

impl<'output, 'input, 'fields> Http1RequestHeadBuilder<'output, 'input, 'fields> {
    /// Creates a request-head builder.
    pub const fn new(
        buffer: &'output mut [u8],
        method: &'input [u8],
        target: &'input [u8],
        version: Http1Version,
        fields: &'fields [Http1FieldRef<'input>],
    ) -> Self {
        Self {
            buffer,
            method,
            target,
            version,
            fields,
        }
    }

    /// Validates and writes the complete request head atomically.
    pub fn build(self) -> Result<Http1RequestHead<'output>, Http1BuildError> {
        if self.method.is_empty()
            || !self.method.iter().copied().all(is_token)
            || !valid_request_target(self.target)
            || !self.fields.iter().copied().all(validate_field_ref)
        {
            return Err(Http1BuildError::InvalidValue);
        }
        let start_line_len = checked_sum(&[
            self.method.len(),
            1,
            self.target.len(),
            1,
            self.version.as_bytes().len(),
            2,
        ])?;
        let fields_len = encoded_fields_len(self.fields)?;
        let required = checked_sum(&[start_line_len, fields_len, 2])?;
        if self.buffer.len() < required {
            return Err(Http1BuildError::BufferTooShort {
                required,
                available: self.buffer.len(),
            });
        }

        let method_end = self.method.len();
        let target_end = method_end + 1 + self.target.len();
        let fields_start = start_line_len;
        let mut offset = 0;
        write_part(self.buffer, &mut offset, self.method);
        write_part(self.buffer, &mut offset, b" ");
        write_part(self.buffer, &mut offset, self.target);
        write_part(self.buffer, &mut offset, b" ");
        write_part(self.buffer, &mut offset, self.version.as_bytes());
        write_part(self.buffer, &mut offset, b"\r\n");
        write_fields(self.buffer, &mut offset, self.fields);
        write_part(self.buffer, &mut offset, b"\r\n");
        Ok(Http1RequestHead::from_validated(
            &self.buffer[..required],
            method_end,
            target_end,
            fields_start,
            self.version,
        ))
    }
}

/// Builds an HTTP/1 response head in caller-owned storage.
pub struct Http1ResponseHeadBuilder<'output, 'input, 'fields> {
    buffer: &'output mut [u8],
    version: Http1Version,
    status: u16,
    reason: &'input [u8],
    fields: &'fields [Http1FieldRef<'input>],
}

impl<'output, 'input, 'fields> Http1ResponseHeadBuilder<'output, 'input, 'fields> {
    /// Creates a response-head builder.
    pub const fn new(
        buffer: &'output mut [u8],
        version: Http1Version,
        status: u16,
        reason: &'input [u8],
        fields: &'fields [Http1FieldRef<'input>],
    ) -> Self {
        Self {
            buffer,
            version,
            status,
            reason,
            fields,
        }
    }

    /// Validates and writes the complete response head atomically.
    pub fn build(self) -> Result<Http1ResponseHead<'output>, Http1BuildError> {
        if self.status > 999
            || !valid_reason(self.reason)
            || !self.fields.iter().copied().all(validate_field_ref)
        {
            return Err(Http1BuildError::InvalidValue);
        }
        let start_line_len =
            checked_sum(&[self.version.as_bytes().len(), 1, 3, 1, self.reason.len(), 2])?;
        let fields_len = encoded_fields_len(self.fields)?;
        let required = checked_sum(&[start_line_len, fields_len, 2])?;
        if self.buffer.len() < required {
            return Err(Http1BuildError::BufferTooShort {
                required,
                available: self.buffer.len(),
            });
        }

        let reason_start = self.version.as_bytes().len() + 1 + 3 + 1;
        let fields_start = start_line_len;
        let status = [
            b'0' + ((self.status / 100) as u8),
            b'0' + (((self.status / 10) % 10) as u8),
            b'0' + ((self.status % 10) as u8),
        ];
        let mut offset = 0;
        write_part(self.buffer, &mut offset, self.version.as_bytes());
        write_part(self.buffer, &mut offset, b" ");
        write_part(self.buffer, &mut offset, &status);
        write_part(self.buffer, &mut offset, b" ");
        write_part(self.buffer, &mut offset, self.reason);
        write_part(self.buffer, &mut offset, b"\r\n");
        write_fields(self.buffer, &mut offset, self.fields);
        write_part(self.buffer, &mut offset, b"\r\n");
        Ok(Http1ResponseHead::from_validated(
            &self.buffer[..required],
            self.status,
            reason_start,
            fields_start,
            self.version,
        ))
    }
}

fn encoded_fields_len(fields: &[Http1FieldRef<'_>]) -> Result<usize, Http1BuildError> {
    let mut length = 0usize;
    for field in fields {
        length = length
            .checked_add(field.name().len())
            .and_then(|length| length.checked_add(1))
            .and_then(|length| length.checked_add(field.value().len()))
            .and_then(|length| length.checked_add(2))
            .ok_or(Http1BuildError::LengthTooLarge)?;
    }
    Ok(length)
}

fn checked_sum(parts: &[usize]) -> Result<usize, Http1BuildError> {
    parts.iter().try_fold(0usize, |total, part| {
        total
            .checked_add(*part)
            .ok_or(Http1BuildError::LengthTooLarge)
    })
}

fn write_fields(buffer: &mut [u8], offset: &mut usize, fields: &[Http1FieldRef<'_>]) {
    for field in fields {
        write_part(buffer, offset, field.name());
        write_part(buffer, offset, b":");
        write_part(buffer, offset, field.value());
        write_part(buffer, offset, b"\r\n");
    }
}

fn write_part(buffer: &mut [u8], offset: &mut usize, part: &[u8]) {
    let end = *offset + part.len();
    buffer[*offset..end].copy_from_slice(part);
    *offset = end;
}
