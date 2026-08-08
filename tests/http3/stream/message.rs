use crate::fixtures::with_decoded_fields;
use net_wire::http3::{
    Http3ErrorCode, Http3Frame, Http3FramePayloadField, Http3FramePayloadParseError,
    Http3FrameType, Http3HeadersContext, Http3HeadersKind, Http3MessageFrame, Http3MessagePosition,
    Http3MessageStreamError, Http3MessageStreamKind, Http3MessageStreamState, Http3PendingHeaders,
    Http3PushId, analyze_decoded_header_section,
};
use net_wire::quic::QuicVarIntParseError;

#[test]
fn message_stream_initial_states_and_incomplete_errors_are_exact() {
    let mut pending_state = Http3MessageStreamState::new(Http3MessageStreamKind::Request);
    let _: Http3PendingHeaders<'_, '_> = match pending_state
        .receive(Http3Frame::parse(&[0x01, 0x00], 0).unwrap())
        .unwrap()
    {
        Http3MessageFrame::Headers(headers) => headers,
        event => panic!("expected HEADERS, got {event:?}"),
    };

    for (kind, position, error_code) in [
        (
            Http3MessageStreamKind::Request,
            Http3MessagePosition::BeforeHeaders,
            Http3ErrorCode::REQUEST_INCOMPLETE,
        ),
        (
            Http3MessageStreamKind::Response,
            Http3MessagePosition::BeforeFinalResponse,
            Http3ErrorCode::MESSAGE_ERROR,
        ),
        (
            Http3MessageStreamKind::Push,
            Http3MessagePosition::BeforeFinalResponse,
            Http3ErrorCode::MESSAGE_ERROR,
        ),
    ] {
        let state = Http3MessageStreamState::new(kind);
        assert_eq!(state.kind(), kind);
        assert_eq!(state.position(), position);
        assert_eq!(state, state);
        assert_eq!(
            state.finish(),
            Err(Http3MessageStreamError::IncompleteMessage {
                stream_kind: kind,
                position,
            })
        );
        assert_eq!(state.finish().unwrap_err().error_code(), error_code);
    }
}

#[test]
fn request_message_stream_guards_headers_and_enforces_transitions_atomically() {
    let mut state = Http3MessageStreamState::new(Http3MessageStreamKind::Request);
    let before = state;
    let error = state
        .receive(Http3Frame::parse(&[0x00, 0x01, 0xaa], 1).unwrap())
        .unwrap_err();
    assert_eq!(
        error,
        Http3MessageStreamError::UnexpectedFrame {
            frame_type: Http3FrameType::DATA,
            position: Http3MessagePosition::BeforeHeaders,
        }
    );
    assert_eq!(error.error_code(), Http3ErrorCode::FRAME_UNEXPECTED);
    assert_eq!(state, before);

    let unknown = [0x40, 0x22, 0x80, 0x00, 0x00, 0x02, 0xde, 0xad];
    match state
        .receive(Http3Frame::parse(&unknown, 2).unwrap())
        .unwrap()
    {
        Http3MessageFrame::Unknown(frame) => {
            assert_eq!(frame.as_bytes(), &unknown);
            assert_eq!(frame.frame_type_varint().as_bytes(), &unknown[..2]);
            assert_eq!(frame.payload_length_varint().as_bytes(), &unknown[2..6]);
        }
        event => panic!("expected unknown extension, got {event:?}"),
    }
    assert_eq!(state, before);

    {
        let pending = match state
            .receive(Http3Frame::parse(&[0x01, 0x02, 0xff, 0x00], 2).unwrap())
            .unwrap()
        {
            Http3MessageFrame::Headers(pending) => pending,
            event => panic!("expected HEADERS, got {event:?}"),
        };
        assert_eq!(pending.headers().encoded_field_section(), &[0xff, 0x00]);
    }
    assert_eq!(state, before);

    with_decoded_fields(&[(b":status", b"200", false)], |section| {
        let final_response =
            analyze_decoded_header_section(section, Http3HeadersContext::Response).unwrap();
        let pending = match state
            .receive(Http3Frame::parse(&[0x01, 0x00], 0).unwrap())
            .unwrap()
        {
            Http3MessageFrame::Headers(pending) => pending,
            event => panic!("expected HEADERS, got {event:?}"),
        };
        let error = pending.accept(&final_response).unwrap_err();
        assert_eq!(
            error,
            Http3MessageStreamError::InvalidHeaderSection {
                stream_kind: Http3MessageStreamKind::Request,
                position: Http3MessagePosition::BeforeHeaders,
                section_kind: Http3HeadersKind::FinalResponse,
            }
        );
        assert_eq!(error.error_code(), Http3ErrorCode::MESSAGE_ERROR);
        assert!(core::error::Error::source(&error).is_none());
    });
    assert_eq!(state, before);

    with_decoded_fields(
        &[
            (b":method", b"GET", false),
            (b":scheme", b"https", false),
            (b":authority", b"example.com", false),
            (b":path", b"/", false),
        ],
        |section| {
            let request = analyze_decoded_header_section(
                section,
                Http3HeadersContext::Request {
                    extended_connect_enabled: false,
                },
            )
            .unwrap();
            let pending = match state
                .receive(Http3Frame::parse(&[0x01, 0x02, 0xaa, 0xbb], 2).unwrap())
                .unwrap()
            {
                Http3MessageFrame::Headers(pending) => pending,
                event => panic!("expected HEADERS, got {event:?}"),
            };
            assert_eq!(
                pending.accept(&request).unwrap().encoded_field_section(),
                &[0xaa, 0xbb]
            );
        },
    );
    assert_eq!(state.position(), Http3MessagePosition::Content);
    match state
        .receive(Http3Frame::parse(&[0x00, 0x02, 0xde, 0xad], 2).unwrap())
        .unwrap()
    {
        Http3MessageFrame::Data(data) => assert_eq!(data.data(), &[0xde, 0xad]),
        event => panic!("expected DATA, got {event:?}"),
    }
    with_decoded_fields(&[(b"x", b"v", false)], |section| {
        let trailers =
            analyze_decoded_header_section(section, Http3HeadersContext::Trailers).unwrap();
        let pending = match state
            .receive(Http3Frame::parse(&[0x01, 0x01, 0xcc], 1).unwrap())
            .unwrap()
        {
            Http3MessageFrame::Headers(pending) => pending,
            event => panic!("expected HEADERS, got {event:?}"),
        };
        pending.accept(&trailers).unwrap();
    });
    assert_eq!(state.position(), Http3MessagePosition::Trailers);
    for frame_type in [Http3FrameType::DATA, Http3FrameType::HEADERS] {
        let before = state;
        let error = state
            .receive(Http3Frame::parse(&[frame_type.value() as u8, 0x00], 0).unwrap())
            .unwrap_err();
        assert_eq!(
            error,
            Http3MessageStreamError::UnexpectedFrame {
                frame_type,
                position: Http3MessagePosition::Trailers,
            }
        );
        assert_eq!(state, before);
    }
    for wire in [
        &[0x40, 0x22, 0x80, 0x00, 0x00, 0x02, 0xde, 0xad][..],
        &[0x40, 0x21, 0x80, 0x00, 0x00, 0x02, 0xbe, 0xef][..],
    ] {
        let before = state;
        match state.receive(Http3Frame::parse(wire, 2).unwrap()).unwrap() {
            Http3MessageFrame::Unknown(frame) => assert_eq!(frame.as_bytes(), wire),
            event => panic!("expected unknown extension or GREASE, got {event:?}"),
        }
        assert_eq!(state, before);
    }
    assert_eq!(state.finish(), Ok(()));
}

#[test]
fn response_and_push_message_streams_use_response_header_semantics() {
    let mut response = Http3MessageStreamState::new(Http3MessageStreamKind::Response);
    for status in [b"103" as &[u8], b"103"] {
        with_decoded_fields(&[(b":status", status, false)], |section| {
            let informational =
                analyze_decoded_header_section(section, Http3HeadersContext::Response).unwrap();
            let pending = match response
                .receive(Http3Frame::parse(&[0x01, 0x01, 0x11], 1).unwrap())
                .unwrap()
            {
                Http3MessageFrame::Headers(pending) => pending,
                event => panic!("expected HEADERS, got {event:?}"),
            };
            assert_eq!(
                pending
                    .accept(&informational)
                    .unwrap()
                    .encoded_field_section(),
                &[0x11]
            );
        });
        assert_eq!(
            response.position(),
            Http3MessagePosition::BeforeFinalResponse
        );
    }
    let before = response;
    assert_eq!(
        response.finish(),
        Err(Http3MessageStreamError::IncompleteMessage {
            stream_kind: Http3MessageStreamKind::Response,
            position: Http3MessagePosition::BeforeFinalResponse,
        })
    );
    assert_eq!(response, before);
    let error = response
        .receive(Http3Frame::parse(&[0x00, 0x00], 0).unwrap())
        .unwrap_err();
    assert_eq!(
        error,
        Http3MessageStreamError::UnexpectedFrame {
            frame_type: Http3FrameType::DATA,
            position: Http3MessagePosition::BeforeFinalResponse,
        }
    );
    assert_eq!(error.error_code(), Http3ErrorCode::FRAME_UNEXPECTED);
    assert_eq!(response, before);
    with_decoded_fields(&[(b":status", b"200", false)], |section| {
        let final_response =
            analyze_decoded_header_section(section, Http3HeadersContext::Response).unwrap();
        let pending = match response
            .receive(Http3Frame::parse(&[0x01, 0x00], 0).unwrap())
            .unwrap()
        {
            Http3MessageFrame::Headers(pending) => pending,
            event => panic!("expected HEADERS, got {event:?}"),
        };
        pending.accept(&final_response).unwrap();
    });
    assert_eq!(response.position(), Http3MessagePosition::Content);
    match response
        .receive(Http3Frame::parse(&[0x00, 0x01, 0x42], 1).unwrap())
        .unwrap()
    {
        Http3MessageFrame::Data(data) => assert_eq!(data.data(), &[0x42]),
        event => panic!("expected DATA, got {event:?}"),
    }
    let before = response;
    with_decoded_fields(&[(b":status", b"200", false)], |section| {
        let final_response =
            analyze_decoded_header_section(section, Http3HeadersContext::Response).unwrap();
        let pending = match response
            .receive(Http3Frame::parse(&[0x01, 0x00], 0).unwrap())
            .unwrap()
        {
            Http3MessageFrame::Headers(pending) => pending,
            event => panic!("expected HEADERS, got {event:?}"),
        };
        let error = pending.accept(&final_response).unwrap_err();
        assert_eq!(
            error,
            Http3MessageStreamError::InvalidHeaderSection {
                stream_kind: Http3MessageStreamKind::Response,
                position: Http3MessagePosition::Content,
                section_kind: Http3HeadersKind::FinalResponse,
            }
        );
    });
    assert_eq!(response, before);
    with_decoded_fields(&[(b"x", b"v", false)], |section| {
        let trailers =
            analyze_decoded_header_section(section, Http3HeadersContext::Trailers).unwrap();
        let pending = match response
            .receive(Http3Frame::parse(&[0x01, 0x00], 0).unwrap())
            .unwrap()
        {
            Http3MessageFrame::Headers(pending) => pending,
            event => panic!("expected HEADERS, got {event:?}"),
        };
        pending.accept(&trailers).unwrap();
    });
    assert_eq!(response.finish(), Ok(()));

    let mut empty_final = Http3MessageStreamState::new(Http3MessageStreamKind::Response);
    with_decoded_fields(&[(b":status", b"200", false)], |section| {
        let final_response =
            analyze_decoded_header_section(section, Http3HeadersContext::Response).unwrap();
        let pending = match empty_final
            .receive(Http3Frame::parse(&[0x01, 0x00], 0).unwrap())
            .unwrap()
        {
            Http3MessageFrame::Headers(pending) => pending,
            event => panic!("expected HEADERS, got {event:?}"),
        };
        pending.accept(&final_response).unwrap();
    });
    assert_eq!(empty_final.finish(), Ok(()));

    let mut push = Http3MessageStreamState::new(Http3MessageStreamKind::Push);
    for (fields, context) in [
        (
            &[(b":status" as &[u8], b"103" as &[u8], false)][..],
            Http3HeadersContext::Response,
        ),
        (
            &[(b":status" as &[u8], b"200" as &[u8], false)][..],
            Http3HeadersContext::Response,
        ),
        (
            &[(b"x" as &[u8], b"v" as &[u8], false)][..],
            Http3HeadersContext::Trailers,
        ),
    ] {
        with_decoded_fields(fields, |section| {
            let headers = analyze_decoded_header_section(section, context).unwrap();
            let pending = match push
                .receive(Http3Frame::parse(&[0x01, 0x00], 0).unwrap())
                .unwrap()
            {
                Http3MessageFrame::Headers(pending) => pending,
                event => panic!("expected HEADERS, got {event:?}"),
            };
            pending.accept(&headers).unwrap();
        });
    }
    assert_eq!(push.position(), Http3MessagePosition::Trailers);
    assert_eq!(push.finish(), Ok(()));
}

#[test]
fn message_stream_push_promises_forbidden_frames_extensions_and_errors_are_exact() {
    let malformed_promise = Http3Frame::parse(&[0x05, 0x00], 0).unwrap();
    for kind in [
        Http3MessageStreamKind::Request,
        Http3MessageStreamKind::Push,
    ] {
        let mut state = Http3MessageStreamState::new(kind);
        let before = state;
        let error = state.receive(malformed_promise).unwrap_err();
        assert_eq!(
            error,
            Http3MessageStreamError::UnexpectedFrame {
                frame_type: Http3FrameType::PUSH_PROMISE,
                position: state.position(),
            }
        );
        assert_eq!(error.error_code(), Http3ErrorCode::FRAME_UNEXPECTED);
        assert!(core::error::Error::source(&error).is_none());
        assert_eq!(state, before);
    }

    let promise_wire = [0x05, 0x03, 0x2a, 0xaa, 0xbb];
    let mut response = Http3MessageStreamState::new(Http3MessageStreamKind::Response);
    for expected_position in [
        Http3MessagePosition::BeforeFinalResponse,
        Http3MessagePosition::Content,
        Http3MessagePosition::Trailers,
    ] {
        match response
            .receive(Http3Frame::parse(&promise_wire, 3).unwrap())
            .unwrap()
        {
            Http3MessageFrame::PushPromise(promise) => {
                assert_eq!(promise.push_id(), Http3PushId::new(42));
                assert_eq!(promise.encoded_field_section(), &[0xaa, 0xbb]);
            }
            event => panic!("expected PUSH_PROMISE, got {event:?}"),
        }
        assert_eq!(response.position(), expected_position);
        if expected_position == Http3MessagePosition::BeforeFinalResponse {
            with_decoded_fields(&[(b":status", b"200", false)], |section| {
                let final_response =
                    analyze_decoded_header_section(section, Http3HeadersContext::Response).unwrap();
                let pending = match response
                    .receive(Http3Frame::parse(&[0x01, 0x00], 0).unwrap())
                    .unwrap()
                {
                    Http3MessageFrame::Headers(pending) => pending,
                    event => panic!("expected HEADERS, got {event:?}"),
                };
                pending.accept(&final_response).unwrap();
            });
        } else if expected_position == Http3MessagePosition::Content {
            with_decoded_fields(&[(b"x", b"v", false)], |section| {
                let trailers =
                    analyze_decoded_header_section(section, Http3HeadersContext::Trailers).unwrap();
                let pending = match response
                    .receive(Http3Frame::parse(&[0x01, 0x00], 0).unwrap())
                    .unwrap()
                {
                    Http3MessageFrame::Headers(pending) => pending,
                    event => panic!("expected HEADERS, got {event:?}"),
                };
                pending.accept(&trailers).unwrap();
            });
        }
    }

    let mut malformed_allowed = Http3MessageStreamState::new(Http3MessageStreamKind::Response);
    let before = malformed_allowed;
    let error = malformed_allowed
        .receive(Http3Frame::parse(&[0x05, 0x00], 0).unwrap())
        .unwrap_err();
    assert_eq!(
        error,
        Http3MessageStreamError::FramePayload {
            frame_type: Http3FrameType::PUSH_PROMISE,
            error: Http3FramePayloadParseError::PayloadVarInt {
                field: Http3FramePayloadField::PushId,
                offset: 0,
                error: QuicVarIntParseError::Incomplete {
                    required: 1,
                    available: 0,
                },
            },
        }
    );
    assert_eq!(error.error_code(), Http3ErrorCode::FRAME_ERROR);
    assert!(core::error::Error::source(&error).is_some());
    assert!(error.to_string().contains("message frame type 5 payload"));
    assert_eq!(malformed_allowed, before);

    let mut request = Http3MessageStreamState::new(Http3MessageStreamKind::Request);
    with_decoded_fields(
        &[
            (b":method", b"GET", false),
            (b":scheme", b"https", false),
            (b":authority", b"example.com", false),
            (b":path", b"/", false),
        ],
        |section| {
            let request_headers = analyze_decoded_header_section(
                section,
                Http3HeadersContext::Request {
                    extended_connect_enabled: false,
                },
            )
            .unwrap();
            let pending = match request
                .receive(Http3Frame::parse(&[0x01, 0x00], 0).unwrap())
                .unwrap()
            {
                Http3MessageFrame::Headers(pending) => pending,
                event => panic!("expected HEADERS, got {event:?}"),
            };
            pending.accept(&request_headers).unwrap();
        },
    );
    for frame_type in [
        Http3FrameType::CANCEL_PUSH,
        Http3FrameType::SETTINGS,
        Http3FrameType::GOAWAY,
        Http3FrameType::MAX_PUSH_ID,
        Http3FrameType::new(0x02),
        Http3FrameType::new(0x06),
        Http3FrameType::new(0x08),
        Http3FrameType::new(0x09),
    ] {
        let before = request;
        let error = request
            .receive(Http3Frame::parse(&[frame_type.value() as u8, 0x00], 0).unwrap())
            .unwrap_err();
        assert_eq!(
            error,
            Http3MessageStreamError::UnexpectedFrame {
                frame_type,
                position: Http3MessagePosition::Content,
            }
        );
        assert_eq!(error.error_code(), Http3ErrorCode::FRAME_UNEXPECTED);
        assert!(core::error::Error::source(&error).is_none());
        assert_eq!(request, before);
    }

    for wire in [
        &[0x40, 0x22, 0x80, 0x00, 0x00, 0x02, 0xde, 0xad][..],
        &[0x40, 0x21, 0x80, 0x00, 0x00, 0x02, 0xbe, 0xef][..],
    ] {
        let before = request;
        match request
            .receive(Http3Frame::parse(wire, 2).unwrap())
            .unwrap()
        {
            Http3MessageFrame::Unknown(frame) => assert_eq!(frame.as_bytes(), wire),
            event => panic!("expected unknown extension or GREASE, got {event:?}"),
        }
        assert_eq!(request, before);
    }

    let incomplete = Http3MessageStreamState::new(Http3MessageStreamKind::Response)
        .finish()
        .unwrap_err();
    assert!(
        incomplete
            .to_string()
            .contains("Response message is incomplete")
    );
    assert!(core::error::Error::source(&incomplete).is_none());
}
