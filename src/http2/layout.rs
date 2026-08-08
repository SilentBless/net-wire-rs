use super::error::Http2ParseError;
use super::frame::Http2Frame;
use super::types::Http2FrameType;

pub(super) const PADDED: u8 = 0x8;

pub(super) fn validate_frame(
    frame: Http2Frame<'_>,
    expected: Http2FrameType,
) -> Result<(), Http2ParseError> {
    validate_type(frame, expected)?;
    if frame.stream_id().value() == 0 {
        return Err(Http2ParseError::ZeroStreamId);
    }
    Ok(())
}

pub(super) fn validate_type(
    frame: Http2Frame<'_>,
    expected: Http2FrameType,
) -> Result<(), Http2ParseError> {
    if frame.frame_type() != expected {
        return Err(Http2ParseError::WrongFrameType {
            expected,
            actual: frame.frame_type(),
        });
    }
    Ok(())
}

pub(super) fn validate_zero_stream(frame: Http2Frame<'_>) -> Result<(), Http2ParseError> {
    if frame.stream_id().value() != 0 {
        return Err(Http2ParseError::ExpectedZeroStreamId);
    }
    Ok(())
}

pub(super) fn validate_exact_payload(
    frame: Http2Frame<'_>,
    expected: usize,
) -> Result<(), Http2ParseError> {
    let actual = frame.payload().len();
    if actual != expected {
        return Err(Http2ParseError::FrameSizeMismatch { expected, actual });
    }
    Ok(())
}

pub(super) fn validate_padding(payload: &[u8]) -> Result<(), Http2ParseError> {
    let Some(&padding_length) = payload.first() else {
        return Err(Http2ParseError::InvalidPadding {
            padding_length: 0,
            payload_length: 0,
        });
    };
    if usize::from(padding_length) >= payload.len() {
        return Err(Http2ParseError::InvalidPadding {
            padding_length,
            payload_length: payload.len(),
        });
    }
    Ok(())
}

pub(super) fn padding_length(frame: Http2Frame<'_>) -> usize {
    if frame.flags() & PADDED != 0 {
        usize::from(frame.payload()[0])
    } else {
        0
    }
}
