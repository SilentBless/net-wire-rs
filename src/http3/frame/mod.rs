//! Private HTTP/3 frame namespace.

mod envelope;
mod payload;

pub(crate) use envelope::Http3FrameEnvelopePlan;
pub use envelope::{
    Http3Frame, Http3FrameBuildError, Http3FrameBuilder, Http3FrameMut, Http3FrameParseError,
};
pub use payload::{
    Http3CancelPush, Http3CancelPushBuilder, Http3Data, Http3DataBuilder,
    Http3FramePayloadBuildError, Http3FramePayloadField, Http3FramePayloadParseError, Http3Goaway,
    Http3GoawayBuilder, Http3Headers, Http3HeadersBuilder, Http3MaxPushId, Http3MaxPushIdBuilder,
    Http3PushPromise, Http3PushPromiseBuilder,
};
pub(in crate::http3) use payload::{
    add_payload, encode_varint, parse_payload_varint, validate_type,
};
