use net_wire::http3::{
    Http3CriticalUniStreamKind, Http3EndpointRole, Http3ErrorCode, Http3PeerUniStreamError,
    Http3PeerUniStreamEvent, Http3PeerUniStreamState, Http3PushId, Http3StreamId, Http3StreamType,
    Http3UniStreamHeader,
};

#[test]
fn peer_unidirectional_stream_state_starts_empty() {
    let client = Http3PeerUniStreamState::new(Http3EndpointRole::Client);
    let server = Http3PeerUniStreamState::new(Http3EndpointRole::Server);

    for (state, role) in [
        (client, Http3EndpointRole::Client),
        (server, Http3EndpointRole::Server),
    ] {
        assert_eq!(state.role(), role);
        assert_eq!(state.control_stream_id(), None);
        assert_eq!(state.qpack_encoder_stream_id(), None);
        assert_eq!(state.qpack_decoder_stream_id(), None);
    }
}

#[test]
fn peer_unidirectional_stream_state_registers_critical_streams_for_each_role() {
    for (role, stream_ids) in [
        (Http3EndpointRole::Client, [3, 7, 11]),
        (Http3EndpointRole::Server, [2, 6, 10]),
    ] {
        let mut state = Http3PeerUniStreamState::new(role);
        let cases = [
            (
                Http3CriticalUniStreamKind::Control,
                stream_ids[0],
                &[0x00][..],
                Http3PeerUniStreamEvent::Control {
                    stream_id: Http3StreamId::new(stream_ids[0]),
                },
            ),
            (
                Http3CriticalUniStreamKind::QpackEncoder,
                stream_ids[1],
                &[0x02][..],
                Http3PeerUniStreamEvent::QpackEncoder {
                    stream_id: Http3StreamId::new(stream_ids[1]),
                },
            ),
            (
                Http3CriticalUniStreamKind::QpackDecoder,
                stream_ids[2],
                &[0x03][..],
                Http3PeerUniStreamEvent::QpackDecoder {
                    stream_id: Http3StreamId::new(stream_ids[2]),
                },
            ),
        ];

        for (kind, raw_stream_id, wire, event) in cases {
            let stream_id = Http3StreamId::new(raw_stream_id);
            assert_eq!(
                state.receive_header(stream_id, Http3UniStreamHeader::parse(wire).unwrap()),
                Ok(event)
            );
            match kind {
                Http3CriticalUniStreamKind::Control => {
                    assert_eq!(state.control_stream_id(), Some(stream_id));
                }
                Http3CriticalUniStreamKind::QpackEncoder => {
                    assert_eq!(state.qpack_encoder_stream_id(), Some(stream_id));
                }
                Http3CriticalUniStreamKind::QpackDecoder => {
                    assert_eq!(state.qpack_decoder_stream_id(), Some(stream_id));
                }
            }
        }
    }
}

#[test]
fn peer_unidirectional_stream_state_rejections_are_exact_and_transactional() {
    let mut state = Http3PeerUniStreamState::new(Http3EndpointRole::Client);
    for (kind, existing, received, wire) in [
        (Http3CriticalUniStreamKind::Control, 3, 15, &[0x00][..]),
        (Http3CriticalUniStreamKind::QpackEncoder, 7, 19, &[0x02][..]),
        (
            Http3CriticalUniStreamKind::QpackDecoder,
            11,
            23,
            &[0x03][..],
        ),
    ] {
        let existing = Http3StreamId::new(existing);
        state
            .receive_header(existing, Http3UniStreamHeader::parse(wire).unwrap())
            .unwrap();
        let before = state;
        let error = state
            .receive_header(
                Http3StreamId::new(received),
                Http3UniStreamHeader::parse(wire).unwrap(),
            )
            .unwrap_err();
        assert_eq!(
            error,
            Http3PeerUniStreamError::DuplicateCriticalStream {
                kind,
                existing,
                received: Http3StreamId::new(received),
            }
        );
        assert_eq!(
            error.error_code(),
            Some(Http3ErrorCode::STREAM_CREATION_ERROR)
        );
        assert!(
            error.to_string().contains("Control")
                || error.to_string().contains("QpackEncoder")
                || error.to_string().contains("QpackDecoder")
        );
        assert!(error.to_string().contains("duplicates stream"));
        assert!(core::error::Error::source(&error).is_none());
        assert_eq!(state, before);
    }

    for (role, invalid_ids) in [
        (Http3EndpointRole::Client, [0, 1, 2, 0x4000_0000_0000_0003]),
        (Http3EndpointRole::Server, [0, 1, 3, 0x4000_0000_0000_0002]),
    ] {
        for raw_stream_id in invalid_ids {
            let mut state = Http3PeerUniStreamState::new(role);
            let before = state;
            let stream_id = Http3StreamId::new(raw_stream_id);
            let error = state
                .receive_header(stream_id, Http3UniStreamHeader::parse(&[0x00]).unwrap())
                .unwrap_err();
            assert_eq!(
                error,
                Http3PeerUniStreamError::InvalidPeerUnidirectionalStream { stream_id }
            );
            assert_eq!(error.error_code(), None);
            assert_eq!(state, before);
        }
    }
}

#[test]
fn peer_unidirectional_stream_state_handles_push_extensions_and_closures() {
    let mut client = Http3PeerUniStreamState::new(Http3EndpointRole::Client);
    client
        .receive_header(
            Http3StreamId::new(3),
            Http3UniStreamHeader::parse(&[0x00]).unwrap(),
        )
        .unwrap();
    let before_push = client;
    assert_eq!(
        client.receive_header(
            Http3StreamId::new(7),
            Http3UniStreamHeader::parse(&[0x01, 0x2a]).unwrap(),
        ),
        Ok(Http3PeerUniStreamEvent::Push {
            stream_id: Http3StreamId::new(7),
            push_id: Http3PushId::new(42),
        })
    );
    assert_eq!(client, before_push);

    for (stream_id, wire, stream_type) in [
        (11, &[0x22][..], Http3StreamType::new(0x22)),
        (15, &[0x21][..], Http3StreamType::new(0x21)),
    ] {
        let before = client;
        assert_eq!(
            client.receive_header(
                Http3StreamId::new(stream_id),
                Http3UniStreamHeader::parse(wire).unwrap(),
            ),
            Ok(Http3PeerUniStreamEvent::Unknown {
                stream_id: Http3StreamId::new(stream_id),
                stream_type,
            })
        );
        assert_eq!(client, before);
    }

    let mut server = Http3PeerUniStreamState::new(Http3EndpointRole::Server);
    let before = server;
    let error = server
        .receive_header(
            Http3StreamId::new(2),
            Http3UniStreamHeader::parse(&[0x01, 0x2a]).unwrap(),
        )
        .unwrap_err();
    assert_eq!(
        error,
        Http3PeerUniStreamError::ClientInitiatedPushStream {
            stream_id: Http3StreamId::new(2),
            push_id: Http3PushId::new(42),
        }
    );
    assert_eq!(
        error.error_code(),
        Some(Http3ErrorCode::STREAM_CREATION_ERROR)
    );
    assert_eq!(server, before);

    assert_eq!(
        Http3PeerUniStreamState::new(Http3EndpointRole::Client)
            .receive_closed(Http3StreamId::new(3)),
        Ok(())
    );
    assert_eq!(client.receive_closed(Http3StreamId::new(7)), Ok(()));
    assert_eq!(client.receive_closed(Http3StreamId::new(11)), Ok(()));

    for (kind, stream_id, wire) in [
        (Http3CriticalUniStreamKind::Control, 3, &[0x00][..]),
        (Http3CriticalUniStreamKind::QpackEncoder, 7, &[0x02][..]),
        (Http3CriticalUniStreamKind::QpackDecoder, 11, &[0x03][..]),
    ] {
        let stream_id = Http3StreamId::new(stream_id);
        let mut state = Http3PeerUniStreamState::new(Http3EndpointRole::Client);
        state
            .receive_header(stream_id, Http3UniStreamHeader::parse(wire).unwrap())
            .unwrap();
        let error = state.receive_closed(stream_id).unwrap_err();
        assert_eq!(
            error,
            Http3PeerUniStreamError::ClosedCriticalStream { kind, stream_id }
        );
        assert_eq!(
            error.error_code(),
            Some(Http3ErrorCode::CLOSED_CRITICAL_STREAM)
        );
    }
}
