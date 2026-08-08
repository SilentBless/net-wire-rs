use net_wire::http3::{
    Http3ControlFrame, Http3ControlStreamError, Http3ControlStreamState, Http3EndpointRole,
    Http3ErrorCode, Http3Frame, Http3FramePayloadField, Http3FramePayloadParseError,
    Http3FrameType, Http3GoawayBuilder, Http3PeerSettings, Http3PushId, Http3SettingId,
    Http3SettingsSemanticError,
};
use net_wire::quic::QuicVarIntParseError;

#[test]
fn control_stream_empty_role_specific_state_is_exposed() {
    let client = Http3ControlStreamState::new(Http3EndpointRole::Client);
    let server = Http3ControlStreamState::new(Http3EndpointRole::Server);

    for (state, role) in [
        (client, Http3EndpointRole::Client),
        (server, Http3EndpointRole::Server),
    ] {
        assert_eq!(state.role(), role);
        assert_eq!(state.settings(), None);
        assert_eq!(state.last_goaway_identifier(), None);
        assert_eq!(state.maximum_push_id(), None);
    }
}

#[test]
fn control_stream_requires_and_commits_one_valid_settings_frame_atomically() {
    let mut state = Http3ControlStreamState::new(Http3EndpointRole::Client);
    let before = state;
    let malformed_data = Http3Frame::parse(&[0x00, 0x01, 0x40], 1).unwrap();
    let error = state.receive(malformed_data).unwrap_err();
    assert_eq!(
        error,
        Http3ControlStreamError::MissingSettings {
            actual: Http3FrameType::DATA,
        }
    );
    assert_eq!(error.error_code(), Http3ErrorCode::MISSING_SETTINGS);
    assert_eq!(state, before);

    let unknown = Http3Frame::parse(&[0x21, 0x00], 0).unwrap();
    let error = state.receive(unknown).unwrap_err();
    assert_eq!(
        error,
        Http3ControlStreamError::MissingSettings {
            actual: Http3FrameType::new(0x21),
        }
    );
    assert_eq!(error.error_code(), Http3ErrorCode::MISSING_SETTINGS);
    assert_eq!(state, before);

    let settings = Http3Frame::parse(
        &[
            0x04, 0x0a, 0x01, 0x40, 0x40, 0x06, 0x00, 0x07, 0x80, 0x00, 0x40, 0x00,
        ],
        10,
    )
    .unwrap();
    match state.receive(settings).unwrap() {
        Http3ControlFrame::Settings {
            frame,
            peer_settings,
        } => {
            assert_eq!(frame.frame().frame_type(), Http3FrameType::SETTINGS);
            assert_eq!(
                frame.as_bytes(),
                &[
                    0x04, 0x0a, 0x01, 0x40, 0x40, 0x06, 0x00, 0x07, 0x80, 0x00, 0x40, 0x00
                ]
            );
            assert_eq!(peer_settings.qpack_max_table_capacity(), 64);
            assert_eq!(peer_settings.maximum_field_section_size(), Some(0));
            assert_eq!(peer_settings.qpack_blocked_streams(), 16_384);
            assert_ne!(peer_settings, Http3PeerSettings::default());
        }
        event => panic!("expected SETTINGS, got {event:?}"),
    }
    assert_eq!(state.settings().unwrap().qpack_max_table_capacity(), 64);
    assert_eq!(
        state.settings().unwrap().maximum_field_section_size(),
        Some(0)
    );
    assert_eq!(state.settings().unwrap().qpack_blocked_streams(), 16_384);

    let before = state;
    let second_malformed_settings = Http3Frame::parse(&[0x04, 0x01, 0x40], 1).unwrap();
    let error = state.receive(second_malformed_settings).unwrap_err();
    assert_eq!(
        error,
        Http3ControlStreamError::UnexpectedFrame {
            frame_type: Http3FrameType::SETTINGS,
        }
    );
    assert_eq!(error.error_code(), Http3ErrorCode::FRAME_UNEXPECTED);
    assert_eq!(state, before);
}

#[test]
fn control_stream_settings_failures_map_errors_and_leave_state_unchanged() {
    let mut state = Http3ControlStreamState::new(Http3EndpointRole::Server);
    let before = state;
    let malformed = Http3Frame::parse(&[0x04, 0x01, 0x40], 1).unwrap();
    let error = state.receive(malformed).unwrap_err();
    assert_eq!(
        error,
        Http3ControlStreamError::FramePayload {
            frame_type: Http3FrameType::SETTINGS,
            error: Http3FramePayloadParseError::PayloadVarInt {
                field: Http3FramePayloadField::SettingIdentifier,
                offset: 0,
                error: QuicVarIntParseError::Incomplete {
                    required: 2,
                    available: 1,
                },
            },
        }
    );
    assert_eq!(error.error_code(), Http3ErrorCode::FRAME_ERROR);
    assert_eq!(state, before);

    let duplicate = Http3Frame::parse(&[0x04, 0x04, 0x21, 0x00, 0x21, 0x00], 4).unwrap();
    let error = state.receive(duplicate).unwrap_err();
    assert_eq!(
        error,
        Http3ControlStreamError::Settings(Http3SettingsSemanticError::DuplicateSetting {
            id: Http3SettingId::new(0x21),
            offset: 2,
        })
    );
    assert_eq!(error.error_code(), Http3ErrorCode::SETTINGS_ERROR);
    assert_eq!(state, before);

    let prohibited = Http3Frame::parse(&[0x04, 0x02, 0x00, 0x00], 2).unwrap();
    let error = state.receive(prohibited).unwrap_err();
    assert_eq!(
        error,
        Http3ControlStreamError::Settings(Http3SettingsSemanticError::ProhibitedSetting {
            id: Http3SettingId::new(0),
            offset: 0,
        })
    );
    assert_eq!(error.error_code(), Http3ErrorCode::SETTINGS_ERROR);
    assert_eq!(state, before);
}

#[test]
fn control_stream_rejects_forbidden_frames_and_preserves_unknown_wire_bytes() {
    let mut state = Http3ControlStreamState::new(Http3EndpointRole::Client);
    state
        .receive(Http3Frame::parse(&[0x04, 0x00], 0).unwrap())
        .unwrap();

    for (wire, frame_type) in [
        (&[0x00, 0x00][..], Http3FrameType::DATA),
        (&[0x01, 0x00][..], Http3FrameType::HEADERS),
        (&[0x05, 0x00][..], Http3FrameType::PUSH_PROMISE),
        (&[0x02, 0x00][..], Http3FrameType::new(0x02)),
        (&[0x06, 0x00][..], Http3FrameType::new(0x06)),
        (&[0x08, 0x00][..], Http3FrameType::new(0x08)),
        (&[0x09, 0x00][..], Http3FrameType::new(0x09)),
    ] {
        let before = state;
        let error = state
            .receive(Http3Frame::parse(wire, 0).unwrap())
            .unwrap_err();
        assert_eq!(
            error,
            Http3ControlStreamError::UnexpectedFrame { frame_type }
        );
        assert_eq!(error.error_code(), Http3ErrorCode::FRAME_UNEXPECTED);
        assert_eq!(state, before);
    }

    for wire in [
        &[0x40, 0x40, 0x80, 0x00, 0x00, 0x02, 0xde, 0xad][..],
        &[0x40, 0x21, 0x80, 0x00, 0x00, 0x02, 0xbe, 0xef][..],
    ] {
        let before = state;
        match state.receive(Http3Frame::parse(wire, 2).unwrap()).unwrap() {
            Http3ControlFrame::Unknown(frame) => {
                assert_eq!(frame.as_bytes(), wire);
                assert_eq!(frame.frame_type_varint().as_bytes(), &wire[..2]);
                assert_eq!(frame.payload_length_varint().as_bytes(), &wire[2..6]);
            }
            event => panic!("expected unknown control frame, got {event:?}"),
        }
        assert_eq!(state, before);
    }
}

#[test]
fn control_stream_enforces_push_role_and_maximum_monotonicity_atomically() {
    let mut client = Http3ControlStreamState::new(Http3EndpointRole::Client);
    client
        .receive(Http3Frame::parse(&[0x04, 0x00], 0).unwrap())
        .unwrap();
    for (wire, frame_type) in [
        (&[0x03, 0x01, 0x40][..], Http3FrameType::CANCEL_PUSH),
        (&[0x0d, 0x01, 0x40][..], Http3FrameType::MAX_PUSH_ID),
    ] {
        let before = client;
        let error = client
            .receive(Http3Frame::parse(wire, 1).unwrap())
            .unwrap_err();
        assert_eq!(
            error,
            Http3ControlStreamError::UnexpectedFrame { frame_type }
        );
        assert_eq!(error.error_code(), Http3ErrorCode::FRAME_UNEXPECTED);
        assert_eq!(client, before);
    }

    let mut server = Http3ControlStreamState::new(Http3EndpointRole::Server);
    server
        .receive(Http3Frame::parse(&[0x04, 0x00], 0).unwrap())
        .unwrap();
    let before_cancel = server;
    match server
        .receive(Http3Frame::parse(&[0x03, 0x01, 0x2a], 1).unwrap())
        .unwrap()
    {
        Http3ControlFrame::CancelPush(cancel) => assert_eq!(cancel.push_id(), Http3PushId::new(42)),
        event => panic!("expected CANCEL_PUSH, got {event:?}"),
    }
    assert_eq!(server, before_cancel);

    for wire in [&[0x0d, 0x02, 0x40, 0x40][..], &[0x0d, 0x02, 0x40, 0x40][..]] {
        match server.receive(Http3Frame::parse(wire, 2).unwrap()).unwrap() {
            Http3ControlFrame::MaxPushId(maximum) => {
                assert_eq!(maximum.push_id(), Http3PushId::new(64));
            }
            event => panic!("expected MAX_PUSH_ID, got {event:?}"),
        }
    }
    match server
        .receive(Http3Frame::parse(&[0x0d, 0x04, 0x80, 0x00, 0x40, 0x00], 4).unwrap())
        .unwrap()
    {
        Http3ControlFrame::MaxPushId(maximum) => {
            assert_eq!(maximum.push_id(), Http3PushId::new(16_384));
        }
        event => panic!("expected MAX_PUSH_ID, got {event:?}"),
    }
    assert_eq!(server.maximum_push_id(), Some(Http3PushId::new(16_384)));

    let before = server;
    let error = server
        .receive(Http3Frame::parse(&[0x0d, 0x02, 0x40, 0x40], 2).unwrap())
        .unwrap_err();
    assert_eq!(
        error,
        Http3ControlStreamError::ReducedMaximumPushId {
            previous: Http3PushId::new(16_384),
            current: Http3PushId::new(64),
        }
    );
    assert_eq!(error.error_code(), Http3ErrorCode::ID_ERROR);
    assert_eq!(server, before);
}

#[test]
fn control_stream_goaway_role_semantics_are_monotonic_and_atomic() {
    let mut client = Http3ControlStreamState::new(Http3EndpointRole::Client);
    client
        .receive(Http3Frame::parse(&[0x04, 0x00], 0).unwrap())
        .unwrap();
    for identifier in [8, 8, 4] {
        let mut destination = [0; 10];
        let frame = Http3GoawayBuilder::new(&mut destination, identifier)
            .build()
            .unwrap();
        match client
            .receive(Http3Frame::parse(frame.as_bytes(), 8).unwrap())
            .unwrap()
        {
            Http3ControlFrame::Goaway(goaway) => assert_eq!(goaway.identifier(), identifier),
            event => panic!("expected GOAWAY, got {event:?}"),
        }
    }
    assert_eq!(client.last_goaway_identifier(), Some(4));
    let before = client;
    let error = client
        .receive(Http3Frame::parse(&[0x07, 0x01, 0x05], 1).unwrap())
        .unwrap_err();
    assert_eq!(
        error,
        Http3ControlStreamError::InvalidGoawayStreamId { identifier: 5 }
    );
    assert_eq!(error.error_code(), Http3ErrorCode::ID_ERROR);
    assert_eq!(client, before);
    let error = client
        .receive(Http3Frame::parse(&[0x07, 0x01, 0x08], 1).unwrap())
        .unwrap_err();
    assert_eq!(
        error,
        Http3ControlStreamError::IncreasedGoawayIdentifier {
            previous: 4,
            current: 8,
        }
    );
    assert_eq!(error.error_code(), Http3ErrorCode::ID_ERROR);
    assert_eq!(client, before);

    let mut server = Http3ControlStreamState::new(Http3EndpointRole::Server);
    server
        .receive(Http3Frame::parse(&[0x04, 0x00], 0).unwrap())
        .unwrap();
    let maximum = 0x3fff_ffff_ffff_ffff;
    match server
        .receive(
            Http3Frame::parse(
                &[0x07, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                8,
            )
            .unwrap(),
        )
        .unwrap()
    {
        Http3ControlFrame::Goaway(goaway) => assert_eq!(goaway.identifier(), maximum),
        event => panic!("expected GOAWAY, got {event:?}"),
    }
    match server
        .receive(Http3Frame::parse(&[0x07, 0x01, 0x2a], 1).unwrap())
        .unwrap()
    {
        Http3ControlFrame::Goaway(goaway) => assert_eq!(goaway.identifier(), 42),
        event => panic!("expected GOAWAY, got {event:?}"),
    }
    let before = server;
    let error = server
        .receive(Http3Frame::parse(&[0x07, 0x01, 0x2b], 1).unwrap())
        .unwrap_err();
    assert_eq!(
        error,
        Http3ControlStreamError::IncreasedGoawayIdentifier {
            previous: 42,
            current: 43,
        }
    );
    assert_eq!(error.error_code(), Http3ErrorCode::ID_ERROR);
    assert_eq!(server, before);
    let error = server
        .receive(Http3Frame::parse(&[0x07, 0x03, 0x40, 0x2a, 0xff], 3).unwrap())
        .unwrap_err();
    assert_eq!(
        error,
        Http3ControlStreamError::FramePayload {
            frame_type: Http3FrameType::GOAWAY,
            error: Http3FramePayloadParseError::TrailingPayload {
                consumed: 2,
                actual: 3,
            },
        }
    );
    assert_eq!(error.error_code(), Http3ErrorCode::FRAME_ERROR);
    assert_eq!(server, before);
}

#[test]
fn control_stream_errors_describe_the_failure_and_expose_only_nested_sources() {
    let mut state = Http3ControlStreamState::new(Http3EndpointRole::Server);
    let missing = state
        .receive(Http3Frame::parse(&[0x00, 0x00], 0).unwrap())
        .unwrap_err();
    assert!(missing.to_string().contains("starts with frame type 0"));
    assert!(core::error::Error::source(&missing).is_none());

    let payload = state
        .receive(Http3Frame::parse(&[0x04, 0x01, 0x40], 1).unwrap())
        .unwrap_err();
    assert!(payload.to_string().contains("SETTINGS identifier"));
    assert!(core::error::Error::source(&payload).is_some());

    let semantic = state
        .receive(Http3Frame::parse(&[0x04, 0x04, 0x21, 0x00, 0x21, 0x00], 4).unwrap())
        .unwrap_err();
    assert!(
        semantic
            .to_string()
            .contains("duplicates an earlier identifier")
    );
    assert!(core::error::Error::source(&semantic).is_some());

    let mut ready = Http3ControlStreamState::new(Http3EndpointRole::Client);
    ready
        .receive(Http3Frame::parse(&[0x04, 0x00], 0).unwrap())
        .unwrap();
    let unexpected = ready
        .receive(Http3Frame::parse(&[0x00, 0x00], 0).unwrap())
        .unwrap_err();
    assert!(
        unexpected
            .to_string()
            .contains("unexpected on the control stream")
    );
    assert!(core::error::Error::source(&unexpected).is_none());
}
