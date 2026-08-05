//! Bounded HTTP/2 header-block fragment sequence validation.

use core::fmt;

use super::{
    Http2Continuation, Http2Frame, Http2FrameType, Http2Headers, Http2ParseError, Http2PushPromise,
};

const END_HEADERS: u8 = 0x04;

/// Validates one bounded HTTP/2 header-block fragment sequence at a time.
///
/// This type validates only the immediate HEADERS, PUSH_PROMISE, and CONTINUATION
/// ordering rule. It does not buffer fragments, decode HPACK, or track connection state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Http2HeaderBlockSequence {
    locked_stream_id: Option<u32>,
}

impl Http2HeaderBlockSequence {
    /// Creates an idle sequence validator.
    pub const fn new() -> Self {
        Self {
            locked_stream_id: None,
        }
    }

    /// Returns whether no header block is awaiting a CONTINUATION frame.
    pub const fn is_idle(&self) -> bool {
        self.locked_stream_id.is_none()
    }

    /// Returns whether a header block is awaiting a CONTINUATION frame.
    pub const fn is_open(&self) -> bool {
        self.locked_stream_id.is_some()
    }

    /// Returns the semantic 31-bit stream ID locked by an open header block.
    pub const fn locked_stream_id(&self) -> Option<u32> {
        self.locked_stream_id
    }

    /// Observes one structurally validated frame.
    ///
    /// Unrelated frames are ignored while idle. Accepted fragment views preserve their
    /// raw frame metadata and borrow from the supplied frame.
    pub fn observe<'a>(
        &mut self,
        frame: Http2Frame<'a>,
    ) -> Result<Option<Http2HeaderBlockFragment<'a>>, Http2HeaderBlockSequenceError> {
        if let Some(expected_stream_id) = self.locked_stream_id {
            return self.observe_open(frame, expected_stream_id);
        }

        match frame.frame_type() {
            Http2FrameType::HEADERS => {
                let headers = Http2Headers::from_frame(frame)
                    .map_err(Http2HeaderBlockSequenceError::MalformedFragment)?;
                let end_headers = headers.frame().flags() & END_HEADERS != 0;
                let stream_id = headers.frame().stream_id().value();
                let fragment = Http2HeaderBlockFragment::Headers(headers);
                if !end_headers {
                    self.locked_stream_id = Some(stream_id);
                }
                Ok(Some(fragment))
            }
            Http2FrameType::PUSH_PROMISE => {
                let push_promise = Http2PushPromise::from_frame(frame)
                    .map_err(Http2HeaderBlockSequenceError::MalformedFragment)?;
                let end_headers = push_promise.frame().flags() & END_HEADERS != 0;
                let stream_id = push_promise.frame().stream_id().value();
                let fragment = Http2HeaderBlockFragment::PushPromise(push_promise);
                if !end_headers {
                    self.locked_stream_id = Some(stream_id);
                }
                Ok(Some(fragment))
            }
            Http2FrameType::CONTINUATION => {
                let continuation = Http2Continuation::from_frame(frame)
                    .map_err(Http2HeaderBlockSequenceError::MalformedFragment)?;
                Err(Http2HeaderBlockSequenceError::UnexpectedContinuation {
                    actual_stream_id: continuation.frame().stream_id().value(),
                })
            }
            _ => Ok(None),
        }
    }

    fn observe_open<'a>(
        &mut self,
        frame: Http2Frame<'a>,
        expected_stream_id: u32,
    ) -> Result<Option<Http2HeaderBlockFragment<'a>>, Http2HeaderBlockSequenceError> {
        if frame.frame_type() != Http2FrameType::CONTINUATION {
            return Err(Http2HeaderBlockSequenceError::InterleavedFrame {
                expected_stream_id,
                actual_stream_id: frame.stream_id().value(),
                actual_frame_type: frame.frame_type(),
            });
        }

        let continuation = Http2Continuation::from_frame(frame)
            .map_err(Http2HeaderBlockSequenceError::MalformedFragment)?;
        let actual_stream_id = continuation.frame().stream_id().value();
        if actual_stream_id != expected_stream_id {
            return Err(Http2HeaderBlockSequenceError::WrongContinuationStream {
                expected_stream_id,
                actual_stream_id,
            });
        }

        let end_headers = continuation.frame().flags() & END_HEADERS != 0;
        let fragment = Http2HeaderBlockFragment::Continuation(continuation);
        if end_headers {
            self.locked_stream_id = None;
        }
        Ok(Some(fragment))
    }
}

/// An accepted HTTP/2 header-block fragment with its typed frame view intact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http2HeaderBlockFragment<'a> {
    /// A HEADERS field-block fragment.
    Headers(Http2Headers<'a>),
    /// A PUSH_PROMISE field-block fragment.
    PushPromise(Http2PushPromise<'a>),
    /// A CONTINUATION field-block fragment.
    Continuation(Http2Continuation<'a>),
}

impl<'a> Http2HeaderBlockFragment<'a> {
    /// Returns the validated raw frame without erasing its original metadata.
    pub const fn frame(&self) -> Http2Frame<'a> {
        match self {
            Self::Headers(fragment) => fragment.frame(),
            Self::PushPromise(fragment) => fragment.frame(),
            Self::Continuation(fragment) => fragment.frame(),
        }
    }

    /// Returns the exact field-block bytes represented by this fragment.
    pub fn field_block_fragment(&self) -> &'a [u8] {
        match self {
            Self::Headers(fragment) => fragment.field_block_fragment(),
            Self::PushPromise(fragment) => fragment.field_block_fragment(),
            Self::Continuation(fragment) => fragment.field_block_fragment(),
        }
    }

    /// Returns whether this fragment ends its header block.
    pub fn is_end_headers(&self) -> bool {
        self.frame().flags() & END_HEADERS != 0
    }
}

/// Failure to preserve HTTP/2 header-block fragment ordering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http2HeaderBlockSequenceError {
    /// A typed header-block fragment has an invalid intrinsic layout.
    MalformedFragment(Http2ParseError),
    /// A CONTINUATION arrived while no header block was open.
    UnexpectedContinuation {
        /// Semantic 31-bit stream ID on the received frame.
        actual_stream_id: u32,
    },
    /// A CONTINUATION arrived on a stream other than the locked stream.
    WrongContinuationStream {
        /// Semantic 31-bit stream ID locked by the incomplete header block.
        expected_stream_id: u32,
        /// Semantic 31-bit stream ID on the received CONTINUATION.
        actual_stream_id: u32,
    },
    /// A non-CONTINUATION frame interrupted an incomplete header block.
    InterleavedFrame {
        /// Semantic 31-bit stream ID locked by the incomplete header block.
        expected_stream_id: u32,
        /// Semantic 31-bit stream ID on the interrupting frame.
        actual_stream_id: u32,
        /// Raw type of the interrupting frame.
        actual_frame_type: Http2FrameType,
    },
}

impl fmt::Display for Http2HeaderBlockSequenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedFragment(error) => {
                write!(f, "malformed HTTP/2 header-block fragment: {error}")
            }
            Self::UnexpectedContinuation { actual_stream_id } => write!(
                f,
                "unexpected HTTP/2 CONTINUATION on stream {actual_stream_id}"
            ),
            Self::WrongContinuationStream {
                expected_stream_id,
                actual_stream_id,
            } => write!(
                f,
                "HTTP/2 CONTINUATION stream mismatch: expected {expected_stream_id}, got {actual_stream_id}"
            ),
            Self::InterleavedFrame {
                expected_stream_id,
                actual_stream_id,
                actual_frame_type,
            } => write!(
                f,
                "HTTP/2 header block on stream {expected_stream_id} was interrupted by frame type {} on stream {actual_stream_id}",
                actual_frame_type.raw()
            ),
        }
    }
}
