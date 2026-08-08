//! RFC 9000 core frame parsing.

mod ack;
mod connection_close;
mod connection_id;
mod control;
mod crypto;
mod parse;
mod path;
mod stream;
mod token;

pub use ack::{QuicAckFrame, QuicAckRange, QuicAckRanges, QuicEcnCounts};
pub use connection_close::QuicConnectionCloseFrame;
pub use connection_id::{QuicNewConnectionIdFrame, QuicRetireConnectionIdFrame};
pub use control::{
    QuicDataBlockedFrame, QuicMaxDataFrame, QuicMaxStreamDataFrame, QuicMaxStreamsFrame,
    QuicResetStreamFrame, QuicStopSendingFrame, QuicStreamDataBlockedFrame, QuicStreamDirection,
    QuicStreamsBlockedFrame,
};
pub use crypto::QuicCryptoFrame;
pub use parse::{QuicFrameField, QuicFrameParseError};
pub use path::{QuicPathChallengeFrame, QuicPathResponseFrame};
pub use stream::QuicStreamFrame;
pub use token::QuicNewTokenFrame;

use core::iter::FusedIterator;

use super::varint::QuicVarInt;

/// A checked borrowed PADDING frame view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicPaddingFrame<'a> {
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
}

impl<'a> QuicPaddingFrame<'a> {
    /// Returns the exact encoded frame bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the exact encoded frame-type variable integer.
    pub const fn frame_type(self) -> QuicVarInt<'a> {
        self.frame_type
    }
}

/// A checked borrowed PING frame view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicPingFrame<'a> {
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
}

impl<'a> QuicPingFrame<'a> {
    /// Returns the exact encoded frame bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the exact encoded frame-type variable integer.
    pub const fn frame_type(self) -> QuicVarInt<'a> {
        self.frame_type
    }
}

/// A checked borrowed HANDSHAKE_DONE frame view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicHandshakeDoneFrame<'a> {
    bytes: &'a [u8],
    frame_type: QuicVarInt<'a>,
}

impl<'a> QuicHandshakeDoneFrame<'a> {
    /// Returns the exact encoded frame bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the exact encoded frame-type variable integer.
    pub const fn frame_type(self) -> QuicVarInt<'a> {
        self.frame_type
    }
}

/// A checked borrowed QUIC frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicFrame<'a> {
    /// An RFC 9000 PADDING frame.
    Padding(QuicPaddingFrame<'a>),
    /// An RFC 9000 PING frame.
    Ping(QuicPingFrame<'a>),
    /// An RFC 9000 ACK or ACK_ECN frame.
    Ack(QuicAckFrame<'a>),
    /// An RFC 9000 NEW_TOKEN frame.
    NewToken(QuicNewTokenFrame<'a>),
    /// An RFC 9000 CRYPTO frame.
    Crypto(QuicCryptoFrame<'a>),
    /// An RFC 9000 STREAM frame.
    Stream(QuicStreamFrame<'a>),
    /// An RFC 9000 RESET_STREAM frame.
    ResetStream(QuicResetStreamFrame<'a>),
    /// An RFC 9000 STOP_SENDING frame.
    StopSending(QuicStopSendingFrame<'a>),
    /// An RFC 9000 MAX_DATA frame.
    MaxData(QuicMaxDataFrame<'a>),
    /// An RFC 9000 MAX_STREAM_DATA frame.
    MaxStreamData(QuicMaxStreamDataFrame<'a>),
    /// An RFC 9000 MAX_STREAMS frame.
    MaxStreams(QuicMaxStreamsFrame<'a>),
    /// An RFC 9000 DATA_BLOCKED frame.
    DataBlocked(QuicDataBlockedFrame<'a>),
    /// An RFC 9000 STREAM_DATA_BLOCKED frame.
    StreamDataBlocked(QuicStreamDataBlockedFrame<'a>),
    /// An RFC 9000 STREAMS_BLOCKED frame.
    StreamsBlocked(QuicStreamsBlockedFrame<'a>),
    /// An RFC 9000 NEW_CONNECTION_ID frame.
    NewConnectionId(QuicNewConnectionIdFrame<'a>),
    /// An RFC 9000 RETIRE_CONNECTION_ID frame.
    RetireConnectionId(QuicRetireConnectionIdFrame<'a>),
    /// An RFC 9000 PATH_CHALLENGE frame.
    PathChallenge(QuicPathChallengeFrame<'a>),
    /// An RFC 9000 PATH_RESPONSE frame.
    PathResponse(QuicPathResponseFrame<'a>),
    /// An RFC 9000 CONNECTION_CLOSE frame.
    ConnectionClose(QuicConnectionCloseFrame<'a>),
    /// An RFC 9000 HANDSHAKE_DONE frame.
    HandshakeDone(QuicHandshakeDoneFrame<'a>),
}

impl<'a> QuicFrame<'a> {
    /// Parses exactly one frame, returning its unconsumed input suffix.
    pub fn parse(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), QuicFrameParseError> {
        parse_at(bytes, 0)
    }

    /// Returns the exact encoded frame bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        match self {
            Self::Padding(frame) => frame.as_bytes(),
            Self::Ping(frame) => frame.as_bytes(),
            Self::Ack(frame) => frame.as_bytes(),
            Self::NewToken(frame) => frame.as_bytes(),
            Self::Crypto(frame) => frame.as_bytes(),
            Self::Stream(frame) => frame.as_bytes(),
            Self::ResetStream(frame) => frame.as_bytes(),
            Self::StopSending(frame) => frame.as_bytes(),
            Self::MaxData(frame) => frame.as_bytes(),
            Self::MaxStreamData(frame) => frame.as_bytes(),
            Self::MaxStreams(frame) => frame.as_bytes(),
            Self::DataBlocked(frame) => frame.as_bytes(),
            Self::StreamDataBlocked(frame) => frame.as_bytes(),
            Self::StreamsBlocked(frame) => frame.as_bytes(),
            Self::NewConnectionId(frame) => frame.as_bytes(),
            Self::RetireConnectionId(frame) => frame.as_bytes(),
            Self::PathChallenge(frame) => frame.as_bytes(),
            Self::PathResponse(frame) => frame.as_bytes(),
            Self::ConnectionClose(frame) => frame.as_bytes(),
            Self::HandshakeDone(frame) => frame.as_bytes(),
        }
    }

    /// Returns the exact encoded frame-type variable integer.
    pub const fn frame_type(self) -> QuicVarInt<'a> {
        match self {
            Self::Padding(frame) => frame.frame_type(),
            Self::Ping(frame) => frame.frame_type(),
            Self::Ack(frame) => frame.frame_type(),
            Self::NewToken(frame) => frame.frame_type(),
            Self::Crypto(frame) => frame.frame_type(),
            Self::Stream(frame) => frame.frame_type(),
            Self::ResetStream(frame) => frame.frame_type(),
            Self::StopSending(frame) => frame.frame_type(),
            Self::MaxData(frame) => frame.frame_type(),
            Self::MaxStreamData(frame) => frame.frame_type(),
            Self::MaxStreams(frame) => frame.frame_type(),
            Self::DataBlocked(frame) => frame.frame_type(),
            Self::StreamDataBlocked(frame) => frame.frame_type(),
            Self::StreamsBlocked(frame) => frame.frame_type(),
            Self::NewConnectionId(frame) => frame.frame_type(),
            Self::RetireConnectionId(frame) => frame.frame_type(),
            Self::PathChallenge(frame) => frame.frame_type(),
            Self::PathResponse(frame) => frame.frame_type(),
            Self::ConnectionClose(frame) => frame.frame_type(),
            Self::HandshakeDone(frame) => frame.frame_type(),
        }
    }
}

/// A validated complete borrowed QUIC plaintext frame sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicFrames<'a> {
    bytes: &'a [u8],
}

impl<'a> QuicFrames<'a> {
    /// Parses and validates a complete nonempty plaintext frame sequence.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, QuicFrameParseError> {
        if bytes.is_empty() {
            return Err(QuicFrameParseError::EmptySequence);
        }

        for frame in QuicFrameIter::new(bytes) {
            frame?;
        }
        Ok(Self { bytes })
    }

    /// Returns the exact complete frame-sequence bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns a fresh iterator over this already validated frame sequence.
    pub const fn iter(self) -> QuicFrameIter<'a> {
        QuicFrameIter::new(self.bytes)
    }
}

/// A fallible fused iterator over a borrowed QUIC frame sequence.
#[derive(Clone, Debug)]
pub struct QuicFrameIter<'a> {
    remaining: &'a [u8],
    offset: usize,
    failed: bool,
}

impl<'a> QuicFrameIter<'a> {
    /// Creates an iterator that can expose a valid prefix before the first parse error.
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            remaining: bytes,
            offset: 0,
            failed: false,
        }
    }
}

impl<'a> Iterator for QuicFrameIter<'a> {
    type Item = Result<QuicFrame<'a>, QuicFrameParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.remaining.is_empty() {
            return None;
        }

        match parse_at(self.remaining, self.offset) {
            Ok((frame, suffix)) => {
                let consumed = frame.as_bytes().len();
                self.remaining = suffix;
                self.offset += consumed;
                Some(Ok(frame))
            }
            Err(error) => {
                self.failed = true;
                self.remaining = &[];
                Some(Err(error))
            }
        }
    }
}

impl FusedIterator for QuicFrameIter<'_> {}

fn parse_at<'a>(
    bytes: &'a [u8],
    offset: usize,
) -> Result<(QuicFrame<'a>, &'a [u8]), QuicFrameParseError> {
    let frame_type = QuicVarInt::parse(bytes)
        .map_err(|error| QuicFrameParseError::FrameType { offset, error })?;
    let frame_len = frame_type.byte_len();
    let frame_bytes = &bytes[..frame_len];
    let suffix = &bytes[frame_len..];

    match frame_type.value() {
        0 => Ok((
            QuicFrame::Padding(QuicPaddingFrame {
                bytes: frame_bytes,
                frame_type,
            }),
            suffix,
        )),
        1 => Ok((
            QuicFrame::Ping(QuicPingFrame {
                bytes: frame_bytes,
                frame_type,
            }),
            suffix,
        )),
        2 | 3 => ack::parse_ack(bytes, frame_type, offset)
            .map(|(frame, suffix)| (QuicFrame::Ack(frame), suffix)),
        7 => token::parse_new_token(bytes, frame_type, offset)
            .map(|(frame, suffix)| (QuicFrame::NewToken(frame), suffix)),
        6 => crypto::parse_crypto(bytes, frame_type, offset)
            .map(|(frame, suffix)| (QuicFrame::Crypto(frame), suffix)),
        0x08..=0x0f => stream::parse_stream(bytes, frame_type, offset)
            .map(|(frame, suffix)| (QuicFrame::Stream(frame), suffix)),
        4 => control::parse_reset_stream(bytes, frame_type, offset)
            .map(|(frame, suffix)| (QuicFrame::ResetStream(frame), suffix)),
        5 => control::parse_stop_sending(bytes, frame_type, offset)
            .map(|(frame, suffix)| (QuicFrame::StopSending(frame), suffix)),
        0x10 => control::parse_max_data(bytes, frame_type, offset)
            .map(|(frame, suffix)| (QuicFrame::MaxData(frame), suffix)),
        0x11 => control::parse_max_stream_data(bytes, frame_type, offset)
            .map(|(frame, suffix)| (QuicFrame::MaxStreamData(frame), suffix)),
        0x12 => control::parse_max_streams(
            bytes,
            frame_type,
            offset,
            QuicStreamDirection::Bidirectional,
        )
        .map(|(frame, suffix)| (QuicFrame::MaxStreams(frame), suffix)),
        0x13 => control::parse_max_streams(
            bytes,
            frame_type,
            offset,
            QuicStreamDirection::Unidirectional,
        )
        .map(|(frame, suffix)| (QuicFrame::MaxStreams(frame), suffix)),
        0x14 => control::parse_data_blocked(bytes, frame_type, offset)
            .map(|(frame, suffix)| (QuicFrame::DataBlocked(frame), suffix)),
        0x15 => control::parse_stream_data_blocked(bytes, frame_type, offset)
            .map(|(frame, suffix)| (QuicFrame::StreamDataBlocked(frame), suffix)),
        0x16 => control::parse_streams_blocked(
            bytes,
            frame_type,
            offset,
            QuicStreamDirection::Bidirectional,
        )
        .map(|(frame, suffix)| (QuicFrame::StreamsBlocked(frame), suffix)),
        0x17 => control::parse_streams_blocked(
            bytes,
            frame_type,
            offset,
            QuicStreamDirection::Unidirectional,
        )
        .map(|(frame, suffix)| (QuicFrame::StreamsBlocked(frame), suffix)),
        0x18 => connection_id::parse_new_connection_id(bytes, frame_type, offset)
            .map(|(frame, suffix)| (QuicFrame::NewConnectionId(frame), suffix)),
        0x19 => connection_id::parse_retire_connection_id(bytes, frame_type, offset)
            .map(|(frame, suffix)| (QuicFrame::RetireConnectionId(frame), suffix)),
        0x1a => path::parse_path_challenge(bytes, frame_type, offset)
            .map(|(frame, suffix)| (QuicFrame::PathChallenge(frame), suffix)),
        0x1b => path::parse_path_response(bytes, frame_type, offset)
            .map(|(frame, suffix)| (QuicFrame::PathResponse(frame), suffix)),
        0x1c | 0x1d => connection_close::parse_connection_close(bytes, frame_type, offset)
            .map(|(frame, suffix)| (QuicFrame::ConnectionClose(frame), suffix)),
        0x1e => Ok((
            QuicFrame::HandshakeDone(QuicHandshakeDoneFrame {
                bytes: frame_bytes,
                frame_type,
            }),
            suffix,
        )),
        value => Err(QuicFrameParseError::UnsupportedFrameType {
            value,
            length: frame_type.encoded_len(),
            offset,
        }),
    }
}
