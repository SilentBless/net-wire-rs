//! TLS record views and caller-buffer construction.

mod layout;

use self::layout::{
    TLS_RECORD_HEADER_LEN, TlsRecordLayoutBuilder, TlsRecordLayoutError,
    TlsRecordLayoutMutationError, TlsRecordLayoutView, TlsRecordLayoutViewMut,
    TlsRecordLayoutWriteError,
};
use super::{
    error::{TlsBuildError, TlsParseError, TlsRecordMutationError},
    types::{TlsContentType, TlsProtocolVersion},
};
use core::fmt;

fn parse_error(error: TlsRecordLayoutError, input_length: usize) -> TlsParseError {
    match error {
        TlsRecordLayoutError::InputTooShort { expected, .. } => {
            match TLS_RECORD_HEADER_LEN.checked_add(expected) {
                Some(required) => TlsParseError::Incomplete {
                    required,
                    available: input_length,
                },
                None => TlsParseError::InvalidValue,
            }
        }
        TlsRecordLayoutError::TrailingBytes { .. }
        | TlsRecordLayoutError::InvalidCodecWidth { .. }
        | TlsRecordLayoutError::InvalidRangeSource { .. }
        | TlsRecordLayoutError::RangeEndBeforeStart { .. }
        | TlsRecordLayoutError::InvalidPrefixExtent { .. } => TlsParseError::InvalidValue,
    }
}

fn mutation_error(error: TlsRecordLayoutMutationError) -> TlsRecordMutationError {
    match error {
        TlsRecordLayoutMutationError::FieldContentType(error)
        | TlsRecordLayoutMutationError::FieldVersion(error) => match error {},
        TlsRecordLayoutMutationError::InvalidPlanLength {
            field,
            expected,
            actual,
        } => TlsRecordMutationError::InvalidFieldEncoding {
            field,
            expected,
            actual,
        },
    }
}

fn build_error(error: TlsRecordLayoutWriteError) -> TlsBuildError {
    match error {
        TlsRecordLayoutWriteError::FieldContentType(error)
        | TlsRecordLayoutWriteError::FieldVersion(error)
        | TlsRecordLayoutWriteError::FieldFragmentLength(error) => match error {},
        TlsRecordLayoutWriteError::InvalidPlanLength {
            field,
            expected,
            actual,
        } => TlsBuildError::InvalidFieldEncoding {
            field,
            expected,
            actual,
        },
        TlsRecordLayoutWriteError::MissingContext { .. }
        | TlsRecordLayoutWriteError::InvalidCodecWidth { .. }
        | TlsRecordLayoutWriteError::InvalidRangeSource { .. }
        | TlsRecordLayoutWriteError::ConflictingRangeSources { .. }
        | TlsRecordLayoutWriteError::InvalidPrefixPlanLength { .. }
        | TlsRecordLayoutWriteError::InvalidLayoutExtent { .. }
        | TlsRecordLayoutWriteError::OutputTooShort { .. }
        | TlsRecordLayoutWriteError::MissingField { .. } => TlsBuildError::InvalidRepresentation,
    }
}

/// A single structurally bounded TLS record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsRecord<'a> {
    layout: TlsRecordLayoutView<'a>,
}

impl<'a> TlsRecord<'a> {
    /// Parses the first complete record and excludes any coalesced suffix.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, TlsParseError> {
        if bytes.len() < TLS_RECORD_HEADER_LEN {
            return Err(TlsParseError::Incomplete {
                required: TLS_RECORD_HEADER_LEN,
                available: bytes.len(),
            });
        }
        let input_length = bytes.len();
        let (layout, _) = TlsRecordLayoutView::parse_prefix(bytes)
            .map_err(|error| parse_error(error, input_length))?;
        Ok(Self { layout })
    }

    /// Returns the content type.
    pub fn content_type(&self) -> TlsContentType {
        self.layout.content_type()
    }

    /// Returns the legacy record version.
    pub fn version(&self) -> TlsProtocolVersion {
        self.layout.version()
    }

    /// Returns the fragment.
    pub fn fragment(&self) -> &'a [u8] {
        self.layout.fragment()
    }

    /// Returns the represented record bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.layout.as_bytes()
    }
}

/// A mutable structurally bounded TLS record.
pub struct TlsRecordMut<'a> {
    layout: TlsRecordLayoutViewMut<'a>,
}

impl fmt::Debug for TlsRecordMut<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsRecordMut")
            .field("bytes", &self.as_bytes())
            .finish()
    }
}

impl PartialEq for TlsRecordMut<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for TlsRecordMut<'_> {}

impl<'a> TlsRecordMut<'a> {
    /// Parses the first complete record and excludes any coalesced suffix.
    pub fn parse(bytes: &'a mut [u8]) -> Result<Self, TlsParseError> {
        if bytes.len() < TLS_RECORD_HEADER_LEN {
            return Err(TlsParseError::Incomplete {
                required: TLS_RECORD_HEADER_LEN,
                available: bytes.len(),
            });
        }
        let input_length = bytes.len();
        let (layout, _) = TlsRecordLayoutViewMut::parse_prefix_mut(bytes)
            .map_err(|error| parse_error(error, input_length))?;
        Ok(Self { layout })
    }

    const fn from_layout(layout: TlsRecordLayoutViewMut<'a>) -> Self {
        Self { layout }
    }

    /// Returns the content type.
    pub fn content_type(&self) -> TlsContentType {
        self.layout.content_type()
    }

    /// Replaces the content type.
    pub fn set_content_type(
        &mut self,
        value: TlsContentType,
    ) -> Result<(), TlsRecordMutationError> {
        self.layout.set_content_type(value).map_err(mutation_error)
    }

    /// Returns the legacy record version.
    pub fn version(&self) -> TlsProtocolVersion {
        self.layout.version()
    }

    /// Replaces the legacy record version.
    pub fn set_version(&mut self, value: TlsProtocolVersion) -> Result<(), TlsRecordMutationError> {
        self.layout.set_version(value).map_err(mutation_error)
    }

    /// Returns the fragment.
    pub fn fragment(&self) -> &[u8] {
        self.layout.fragment()
    }

    /// Returns the fragment mutably without changing its encoded length.
    pub fn fragment_mut(&mut self) -> &mut [u8] {
        self.layout.fragment_mut()
    }

    /// Returns represented record bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.layout.as_bytes()
    }
}

/// Builds a TLS record in caller-owned storage.
pub struct TlsRecordBuilder<'a, 'b> {
    buffer: &'a mut [u8],
    content_type: TlsContentType,
    version: TlsProtocolVersion,
    fragment: &'b [u8],
}

impl<'a, 'b> TlsRecordBuilder<'a, 'b> {
    /// Starts a record builder with a copied fragment input.
    pub fn new(
        buffer: &'a mut [u8],
        content_type: TlsContentType,
        version: TlsProtocolVersion,
        fragment: &'b [u8],
    ) -> Self {
        Self {
            buffer,
            content_type,
            version,
            fragment,
        }
    }

    /// Validates all inputs before writing the record.
    pub fn build(self) -> Result<TlsRecordMut<'a>, TlsBuildError> {
        if self.fragment.len() > usize::from(u16::MAX) {
            return Err(TlsBuildError::LengthTooLarge);
        }
        let length = TLS_RECORD_HEADER_LEN
            .checked_add(self.fragment.len())
            .ok_or(TlsBuildError::LengthTooLarge)?;
        if self.buffer.len() < length {
            return Err(TlsBuildError::BufferTooShort {
                required: length,
                available: self.buffer.len(),
            });
        }
        let (layout, _) = TlsRecordLayoutBuilder::new()
            .content_type(self.content_type)
            .version(self.version)
            .fragment(self.fragment)
            .build_into(&mut self.buffer[..length])
            .map_err(build_error)?;
        Ok(TlsRecordMut::from_layout(layout))
    }
}
