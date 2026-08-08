use crate::fixtures::with_decoded_fields;
use net_wire::http3::{
    Http3ContentDisposition, Http3ContentKind, Http3ContentOperation, Http3Data, Http3DataBuilder,
    Http3ErrorCode, Http3HeadersContext, Http3MessageContentError, Http3MessageContentState,
    Http3ResponseContext, analyze_decoded_header_section,
};

#[test]
fn message_content_defaults_and_local_errors_are_exact() {
    let mut state = Http3MessageContentState::new(Http3ContentKind::Request);
    assert_eq!(state.kind(), Http3ContentKind::Request);
    assert_eq!(state.declared_length(), None);
    assert_eq!(state.received_length(), 0);
    assert_eq!(
        state.finish(),
        Err(Http3MessageContentError::IncompleteMessage)
    );
    assert_eq!(
        state.finish().unwrap_err().error_code(),
        Some(Http3ErrorCode::MESSAGE_ERROR)
    );

    let before = state;
    assert_eq!(
        state.receive_data(Http3Data::parse(&[0, 0], 0).unwrap()),
        Err(Http3MessageContentError::OperationNotReady {
            operation: Http3ContentOperation::Data,
        })
    );
    let error = state
        .receive_data(Http3Data::parse(&[0, 0], 0).unwrap())
        .unwrap_err();
    assert_eq!(error.error_code(), None);
    assert!(error.to_string().contains("Data operation is not ready"));
    assert!(core::error::Error::source(&error).is_none());
    assert_eq!(state, before);

    with_decoded_fields(&[(b"x", b"v", false)], |section| {
        let trailers =
            analyze_decoded_header_section(section, Http3HeadersContext::Trailers).unwrap();
        let error = state.accept_trailers(trailers).unwrap_err();
        assert_eq!(
            error,
            Http3MessageContentError::OperationNotReady {
                operation: Http3ContentOperation::Trailers,
            }
        );
        assert_eq!(error.error_code(), None);
        assert_eq!(state, before);
    });

    let peer = Http3MessageContentError::InvalidContentLength {
        field_index: 4,
        member_index: 1,
    };
    assert!(peer.to_string().contains("field 4 member 1 is invalid"));
    assert_eq!(peer.error_code(), Some(Http3ErrorCode::MESSAGE_ERROR));
    assert!(core::error::Error::source(&peer).is_none());
}

#[test]
fn message_content_request_normalizes_and_accounts_real_data_frames() {
    let fields = [
        (b":method" as &[u8], b"POST" as &[u8], false),
        (b":scheme", b"https", false),
        (b":authority", b"x", false),
        (b":path", b"/", false),
        (b"content-length", b"004, 4", false),
        (b"content-length", b"4", false),
    ];
    with_decoded_fields(&fields, |section| {
        let headers = analyze_decoded_header_section(
            section,
            Http3HeadersContext::Request {
                extended_connect_enabled: false,
            },
        )
        .unwrap();
        let mut state = Http3MessageContentState::new(Http3ContentKind::Request);
        assert_eq!(
            state.accept_initial_headers(headers),
            Ok(Http3ContentDisposition::HttpMessage)
        );
        assert_eq!(state.declared_length(), Some(4));
        assert_eq!(state.received_length(), 0);

        let mut first_destination = [0; 4];
        let first = Http3DataBuilder::new(&mut first_destination, &[0xaa, 0xbb])
            .build()
            .unwrap();
        let first = Http3Data::parse(first.as_bytes(), 2).unwrap();
        state.receive_data(first).unwrap();
        assert_eq!(state.received_length(), 2);

        let mut second_destination = [0; 4];
        let second = Http3DataBuilder::new(&mut second_destination, &[0xcc, 0xdd])
            .build()
            .unwrap();
        let second = Http3Data::parse(second.as_bytes(), 2).unwrap();
        state.receive_data(second).unwrap();
        assert_eq!(state.received_length(), 4);
        state
            .receive_data(Http3Data::parse(&[0, 0], 0).unwrap())
            .unwrap();
        assert_eq!(state.received_length(), 4);
        assert_eq!(state.finish(), Ok(()));
    });
}

#[test]
fn message_content_length_parse_failures_are_exact_and_atomic() {
    for (value, extra, expected) in [
        (
            b"4," as &[u8],
            None,
            Http3MessageContentError::InvalidContentLength {
                field_index: 4,
                member_index: 1,
            },
        ),
        (
            b"4, x",
            None,
            Http3MessageContentError::InvalidContentLength {
                field_index: 4,
                member_index: 1,
            },
        ),
        (
            b"18446744073709551616",
            None,
            Http3MessageContentError::ContentLengthOverflow {
                field_index: 4,
                member_index: 0,
            },
        ),
        (
            b"4, 4",
            Some(b"5" as &[u8]),
            Http3MessageContentError::ConflictingContentLength {
                field_index: 5,
                member_index: 0,
                expected: 4,
                actual: 5,
            },
        ),
    ] {
        let fields = [
            (b":method" as &[u8], b"POST" as &[u8], false),
            (b":scheme", b"https", false),
            (b":authority", b"x", false),
            (b":path", b"/", false),
            (b"content-length", value, false),
        ];
        with_decoded_fields(&fields, |section| {
            let headers = analyze_decoded_header_section(
                section,
                Http3HeadersContext::Request {
                    extended_connect_enabled: false,
                },
            )
            .unwrap();
            let mut state = Http3MessageContentState::new(Http3ContentKind::Request);
            let before = state;
            let error = if let Some(extra) = extra {
                with_decoded_fields(
                    &[
                        (b":method" as &[u8], b"POST" as &[u8], false),
                        (b":scheme", b"https", false),
                        (b":authority", b"x", false),
                        (b":path", b"/", false),
                        (b"content-length", value, false),
                        (b"content-length", extra, false),
                    ],
                    |section| {
                        state
                            .accept_initial_headers(
                                analyze_decoded_header_section(
                                    section,
                                    Http3HeadersContext::Request {
                                        extended_connect_enabled: false,
                                    },
                                )
                                .unwrap(),
                            )
                            .unwrap_err()
                    },
                )
            } else {
                state.accept_initial_headers(headers).unwrap_err()
            };
            assert_eq!(error, expected);
            assert_eq!(error.error_code(), Some(Http3ErrorCode::MESSAGE_ERROR));
            assert_eq!(state, before);
        });
    }
}

#[test]
fn message_content_mismatch_and_trailers_preserve_atomicity() {
    with_decoded_fields(
        &[
            (b":method" as &[u8], b"POST" as &[u8], false),
            (b":scheme", b"https", false),
            (b":authority", b"x", false),
            (b":path", b"/", false),
            (b"content-length", b"3", false),
        ],
        |section| {
            let mut state = Http3MessageContentState::new(Http3ContentKind::Request);
            state
                .accept_initial_headers(
                    analyze_decoded_header_section(
                        section,
                        Http3HeadersContext::Request {
                            extended_connect_enabled: false,
                        },
                    )
                    .unwrap(),
                )
                .unwrap();
            state
                .receive_data(Http3Data::parse(&[0, 2, 1, 2], 2).unwrap())
                .unwrap();
            let before = state;
            assert_eq!(
                state.receive_data(Http3Data::parse(&[0, 2, 3, 4], 2).unwrap()),
                Err(Http3MessageContentError::ContentLengthMismatch {
                    declared: 3,
                    received: 4
                })
            );
            assert_eq!(state, before);
            assert_eq!(
                state.finish(),
                Err(Http3MessageContentError::ContentLengthMismatch {
                    declared: 3,
                    received: 2
                })
            );
            with_decoded_fields(&[(b"x", b"v", false)], |trailers| {
                let error = state
                    .accept_trailers(
                        analyze_decoded_header_section(trailers, Http3HeadersContext::Trailers)
                            .unwrap(),
                    )
                    .unwrap_err();
                assert_eq!(
                    error,
                    Http3MessageContentError::ContentLengthMismatch {
                        declared: 3,
                        received: 2
                    }
                );
                assert_eq!(error.error_code(), Some(Http3ErrorCode::MESSAGE_ERROR));
                assert_eq!(state, before);
            });
        },
    );

    with_decoded_fields(
        &[
            (b":method" as &[u8], b"POST" as &[u8], false),
            (b":scheme", b"https", false),
            (b":authority", b"x", false),
            (b":path", b"/", false),
            (b"content-length", b"2", false),
        ],
        |section| {
            let mut state = Http3MessageContentState::new(Http3ContentKind::Request);
            state
                .accept_initial_headers(
                    analyze_decoded_header_section(
                        section,
                        Http3HeadersContext::Request {
                            extended_connect_enabled: false,
                        },
                    )
                    .unwrap(),
                )
                .unwrap();
            state
                .receive_data(Http3Data::parse(&[0, 2, 1, 2], 2).unwrap())
                .unwrap();
            with_decoded_fields(&[(b"content-length", b"2", false)], |trailers| {
                let before = state;
                let error = state
                    .accept_trailers(
                        analyze_decoded_header_section(trailers, Http3HeadersContext::Trailers)
                            .unwrap(),
                    )
                    .unwrap_err();
                assert_eq!(
                    error,
                    Http3MessageContentError::ContentLengthInTrailers { field_index: 0 }
                );
                assert_eq!(state, before);
            });
            with_decoded_fields(&[(b"x", b"v", false)], |trailers| {
                state
                    .accept_trailers(
                        analyze_decoded_header_section(trailers, Http3HeadersContext::Trailers)
                            .unwrap(),
                    )
                    .unwrap();
            });
            assert_eq!(state.finish(), Ok(()));
        },
    );
}

#[test]
fn message_content_response_status_matrix_keeps_no_content_rules_separate() {
    let mut ordinary =
        Http3MessageContentState::new(Http3ContentKind::Response(Http3ResponseContext::Ordinary));
    let before_information = ordinary;
    for _ in 0..2 {
        with_decoded_fields(&[(b":status", b"100", false)], |section| {
            assert_eq!(
                ordinary.accept_initial_headers(
                    analyze_decoded_header_section(section, Http3HeadersContext::Response).unwrap()
                ),
                Ok(Http3ContentDisposition::AwaitingFinalResponse)
            );
            assert_eq!(ordinary, before_information);
        });
    }
    with_decoded_fields(
        &[
            (b":status", b"103", false),
            (b"content-length", b"1", false),
        ],
        |section| {
            let before = ordinary;
            let error = ordinary
                .accept_initial_headers(
                    analyze_decoded_header_section(section, Http3HeadersContext::Response).unwrap(),
                )
                .unwrap_err();
            assert_eq!(
                error,
                Http3MessageContentError::ProhibitedContentLength { field_index: 1 }
            );
            assert_eq!(error.error_code(), Some(Http3ErrorCode::MESSAGE_ERROR));
            assert_eq!(ordinary, before);
        },
    );
    with_decoded_fields(
        &[
            (b":status", b"200", false),
            (b"content-length", b"2", false),
        ],
        |section| {
            assert_eq!(
                ordinary.accept_initial_headers(
                    analyze_decoded_header_section(section, Http3HeadersContext::Response).unwrap()
                ),
                Ok(Http3ContentDisposition::HttpMessage)
            );
        },
    );
    assert_eq!(ordinary.declared_length(), Some(2));

    for (kind, status) in [
        (
            Http3ContentKind::Response(Http3ResponseContext::Head),
            b"200" as &[u8],
        ),
        (
            Http3ContentKind::Response(Http3ResponseContext::Head),
            b"304",
        ),
        (
            Http3ContentKind::Response(Http3ResponseContext::Ordinary),
            b"304",
        ),
        (
            Http3ContentKind::Response(Http3ResponseContext::Ordinary),
            b"205",
        ),
    ] {
        with_decoded_fields(
            &[
                (b":status", status, false),
                (b"content-length", b"7", false),
            ],
            |section| {
                let mut state = Http3MessageContentState::new(kind);
                state
                    .accept_initial_headers(
                        analyze_decoded_header_section(section, Http3HeadersContext::Response)
                            .unwrap(),
                    )
                    .unwrap();
                assert_eq!(state.declared_length(), Some(7));
                let before = state;
                state
                    .receive_data(Http3Data::parse(&[0, 0], 0).unwrap())
                    .unwrap();
                assert_eq!(state, before);
                let error = state
                    .receive_data(Http3Data::parse(&[0, 1, 1], 1).unwrap())
                    .unwrap_err();
                assert_eq!(
                    error,
                    Http3MessageContentError::ContentNotAllowed { data_length: 1 }
                );
                assert_eq!(error.error_code(), Some(Http3ErrorCode::MESSAGE_ERROR));
                assert_eq!(state, before);
                with_decoded_fields(&[(b"x", b"v", false)], |trailers| {
                    state
                        .accept_trailers(
                            analyze_decoded_header_section(trailers, Http3HeadersContext::Trailers)
                                .unwrap(),
                        )
                        .unwrap();
                });
                assert_eq!(state.finish(), Ok(()));
            },
        );
    }

    for kind in [
        Http3ContentKind::Response(Http3ResponseContext::Ordinary),
        Http3ContentKind::Response(Http3ResponseContext::Head),
        Http3ContentKind::Push,
    ] {
        with_decoded_fields(
            &[
                (b":status", b"204", false),
                (b"content-length", b"0", false),
            ],
            |section| {
                let mut state = Http3MessageContentState::new(kind);
                let before = state;
                assert_eq!(
                    state.accept_initial_headers(
                        analyze_decoded_header_section(section, Http3HeadersContext::Response)
                            .unwrap()
                    ),
                    Err(Http3MessageContentError::ProhibitedContentLength { field_index: 1 })
                );
                assert_eq!(state, before);
            },
        );
        with_decoded_fields(&[(b":status", b"204", false)], |section| {
            let mut state = Http3MessageContentState::new(kind);
            state
                .accept_initial_headers(
                    analyze_decoded_header_section(section, Http3HeadersContext::Response).unwrap(),
                )
                .unwrap();
            let before = state;
            state
                .receive_data(Http3Data::parse(&[0, 0], 0).unwrap())
                .unwrap();
            assert_eq!(state, before);
            assert_eq!(
                state.receive_data(Http3Data::parse(&[0, 1, 1], 1).unwrap()),
                Err(Http3MessageContentError::ContentNotAllowed { data_length: 1 })
            );
            assert_eq!(state, before);
            with_decoded_fields(&[(b"x", b"v", false)], |trailers| {
                assert_eq!(
                    state.accept_trailers(
                        analyze_decoded_header_section(trailers, Http3HeadersContext::Trailers)
                            .unwrap()
                    ),
                    Err(Http3MessageContentError::OperationNotReady {
                        operation: Http3ContentOperation::Trailers
                    })
                );
            });
            assert_eq!(state, before);
        });
    }
}

#[test]
fn message_content_connect_tunnels_do_not_account_http_bytes() {
    for (fields, enabled) in [
        (
            &[
                (b":method" as &[u8], b"CONNECT" as &[u8], false),
                (b":authority", b"x:443", false),
                (b"content-length", b"9", false),
            ][..],
            false,
        ),
        (
            &[
                (b":method" as &[u8], b"CONNECT" as &[u8], false),
                (b":protocol", b"websocket", false),
                (b":scheme", b"https", false),
                (b":authority", b"x", false),
                (b":path", b"/", false),
                (b"content-length", b"9", false),
            ][..],
            true,
        ),
    ] {
        with_decoded_fields(fields, |section| {
            let mut state = Http3MessageContentState::new(Http3ContentKind::Request);
            assert_eq!(
                state.accept_initial_headers(
                    analyze_decoded_header_section(
                        section,
                        Http3HeadersContext::Request {
                            extended_connect_enabled: enabled
                        }
                    )
                    .unwrap()
                ),
                Ok(Http3ContentDisposition::ConnectTunnel)
            );
            assert_eq!(state.declared_length(), Some(9));
            let before = state;
            let error = state
                .receive_data(Http3Data::parse(&[0, 1, 1], 1).unwrap())
                .unwrap_err();
            assert_eq!(error, Http3MessageContentError::NotHttpMessageContent);
            assert_eq!(error.error_code(), None);
            assert_eq!(state, before);
            with_decoded_fields(&[(b"x", b"v", false)], |trailers| {
                assert_eq!(
                    state.accept_trailers(
                        analyze_decoded_header_section(trailers, Http3HeadersContext::Trailers)
                            .unwrap()
                    ),
                    Err(Http3MessageContentError::NotHttpMessageContent)
                );
                assert_eq!(state, before);
            });
            assert_eq!(state.finish(), Ok(()));
        });
    }

    with_decoded_fields(
        &[
            (b":status", b"205", false),
            (b"content-length", b"1", false),
        ],
        |section| {
            let mut state = Http3MessageContentState::new(Http3ContentKind::Response(
                Http3ResponseContext::Connect,
            ));
            assert_eq!(
                state.accept_initial_headers(
                    analyze_decoded_header_section(section, Http3HeadersContext::Response).unwrap()
                ),
                Err(Http3MessageContentError::ProhibitedContentLength { field_index: 1 })
            );
        },
    );
    with_decoded_fields(&[(b":status", b"205", false)], |section| {
        let mut state = Http3MessageContentState::new(Http3ContentKind::Response(
            Http3ResponseContext::Connect,
        ));
        assert_eq!(
            state.accept_initial_headers(
                analyze_decoded_header_section(section, Http3HeadersContext::Response).unwrap()
            ),
            Ok(Http3ContentDisposition::ConnectTunnel)
        );
        let before = state;
        assert_eq!(
            state.receive_data(Http3Data::parse(&[0, 1, 1], 1).unwrap()),
            Err(Http3MessageContentError::NotHttpMessageContent)
        );
        assert_eq!(state, before);
    });
    with_decoded_fields(
        &[
            (b":status", b"404", false),
            (b"content-length", b"2", false),
        ],
        |section| {
            let mut state = Http3MessageContentState::new(Http3ContentKind::Response(
                Http3ResponseContext::Connect,
            ));
            assert_eq!(
                state.accept_initial_headers(
                    analyze_decoded_header_section(section, Http3HeadersContext::Response).unwrap()
                ),
                Ok(Http3ContentDisposition::HttpMessage)
            );
            state
                .receive_data(Http3Data::parse(&[0, 2, 1, 2], 2).unwrap())
                .unwrap();
            assert_eq!(state.finish(), Ok(()));
        },
    );
}
