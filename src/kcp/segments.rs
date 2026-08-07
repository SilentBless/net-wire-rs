//! Strict complete KCP segment-sequence validation and iteration.

use core::iter::FusedIterator;

use super::{KcpSegment, KcpSegmentsParseError};

/// A nonempty, completely validated concatenated KCP segment sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KcpSegments<'a> {
    bytes: &'a [u8],
}

impl<'a> KcpSegments<'a> {
    /// Validates and borrows a complete nonempty concatenated KCP segment sequence.
    ///
    /// Every byte must belong to a structurally complete segment; trailing bytes shorter than a
    /// KCP header are rejected rather than treated as padding.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, KcpSegmentsParseError> {
        if bytes.is_empty() {
            return Err(KcpSegmentsParseError::EmptySequence);
        }

        for segment in KcpSegmentIter::new(bytes) {
            segment?;
        }
        Ok(Self { bytes })
    }

    /// Returns the exact complete sequence bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns a fresh iterator over this sequence's validated segments.
    pub const fn iter(self) -> KcpSegmentIter<'a> {
        KcpSegmentIter::new(self.bytes)
    }
}

/// A fallible fused iterator over concatenated KCP segments.
///
/// The iterator yields every structurally valid leading segment. On the first malformed segment,
/// it yields one error with that segment's absolute offset and permanently exhausts itself.
#[derive(Clone, Debug)]
pub struct KcpSegmentIter<'a> {
    remaining: &'a [u8],
    offset: usize,
    exhausted: bool,
}

impl<'a> KcpSegmentIter<'a> {
    /// Creates an iterator over a raw concatenated KCP segment sequence without prevalidation.
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            remaining: bytes,
            offset: 0,
            exhausted: false,
        }
    }
}

impl<'a> Iterator for KcpSegmentIter<'a> {
    type Item = Result<KcpSegment<'a>, KcpSegmentsParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.exhausted || self.remaining.is_empty() {
            self.exhausted = true;
            return None;
        }

        match KcpSegment::parse(self.remaining) {
            Ok((segment, suffix)) => {
                let length = segment.as_bytes().len();
                self.offset += length;
                self.remaining = suffix;
                Some(Ok(segment))
            }
            Err(error) => self.fail(KcpSegmentsParseError::Segment {
                offset: self.offset,
                error,
            }),
        }
    }
}

impl FusedIterator for KcpSegmentIter<'_> {}

impl<'a> KcpSegmentIter<'a> {
    fn fail(
        &mut self,
        error: KcpSegmentsParseError,
    ) -> Option<Result<KcpSegment<'a>, KcpSegmentsParseError>> {
        self.remaining = &[];
        self.exhausted = true;
        Some(Err(error))
    }
}
