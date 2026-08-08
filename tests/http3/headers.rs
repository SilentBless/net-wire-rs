use crate::fixtures::{DecodedFieldSpec, with_decoded_fields};
use net_wire::http3::{
    Http3DecodedPushPromise, Http3ErrorCode, Http3Frame, Http3HeaderSectionError,
    Http3HeadersContext, Http3HeadersKind, Http3MessageFrame, Http3MessagePosition,
    Http3MessageStreamKind, Http3MessageStreamState, analyze_decoded_header_section,
    analyze_decoded_push_promise,
};

type HeaderSectionErrorCase<'a> = (&'a [DecodedFieldSpec<'a>], Http3HeaderSectionError);

#[test]
fn decoded_header_analysis_preserves_qpack_and_handoff() {
    let fields = [
        (b":method" as &[u8], b"GET" as &[u8], false),
        (b":scheme", b"https", false),
        (b":authority", b"example.com", true),
        (b":path", b"/", false),
        (b"host", b"example.com", false),
    ];
    with_decoded_fields(&fields, |section| {
        let analyzed = analyze_decoded_header_section(
            section,
            Http3HeadersContext::Request {
                extended_connect_enabled: false,
            },
        )
        .unwrap();

        assert_eq!(analyzed.section(), section);
        assert_eq!(analyzed.kind(), Http3HeadersKind::Request);
        assert_eq!(analyzed.field_section_size(), 224);
        assert!(analyzed.section().get(2).unwrap().never_indexed());
        assert_eq!(
            analyzed.section().iter().collect::<Vec<_>>(),
            section.iter().collect::<Vec<_>>()
        );

        let mut state = Http3MessageStreamState::new(Http3MessageStreamKind::Request);
        let pending = match state
            .receive(Http3Frame::parse(&[0x01, 0x00], 0).unwrap())
            .unwrap()
        {
            Http3MessageFrame::Headers(pending) => pending,
            event => panic!("expected HEADERS, got {event:?}"),
        };
        pending.accept(&analyzed).unwrap();
        assert_eq!(state.position(), Http3MessagePosition::Content);
    });
    with_decoded_fields(
        &[
            (b":method", b"GET", false),
            (b":scheme", b"custom", false),
            (b":path", b"opaque", false),
        ],
        |section| {
            assert!(
                analyze_decoded_header_section(
                    section,
                    Http3HeadersContext::Request {
                        extended_connect_enabled: false
                    }
                )
                .is_ok()
            )
        },
    );
}

#[test]
fn decoded_request_analysis_reports_exact_errors_and_te_rules() {
    let cases: &[HeaderSectionErrorCase<'_>] = &[
        (
            &[
                (b":scheme", b"https", false),
                (b":path", b"/", false),
                (b":authority", b"x", false),
            ],
            Http3HeaderSectionError::MissingPseudoField { name: b":method" },
        ),
        (
            &[
                (b":method", b"GET", false),
                (b":scheme", b"https", false),
                (b":authority", b"x", false),
                (b":authority", b"x", false),
                (b":path", b"/", false),
            ],
            Http3HeaderSectionError::DuplicatePseudoField { field_index: 3 },
        ),
        (
            &[(b"x", b"v", false), (b":method", b"GET", false)],
            Http3HeaderSectionError::PseudoFieldAfterRegular { field_index: 1 },
        ),
        (
            &[
                (b":method", b"GET", false),
                (b":scheme", b"https", false),
                (b":authority", b"x", false),
                (b":path", b"/", false),
                (b"Host", b"x", false),
            ],
            Http3HeaderSectionError::UppercaseFieldName { field_index: 4 },
        ),
        (
            &[
                (b":method", b"GET", false),
                (b":scheme", b"https", false),
                (b":authority", b"x", false),
                (b":path", b"/", false),
                (b"bad name", b"x", false),
            ],
            Http3HeaderSectionError::InvalidFieldName { field_index: 4 },
        ),
        (
            &[
                (b":method", b"GET", false),
                (b":scheme", b"https", false),
                (b":authority", b"x", false),
                (b":path", b"/", false),
                (b"x", b"bad ", false),
            ],
            Http3HeaderSectionError::InvalidFieldValue { field_index: 4 },
        ),
        (
            &[
                (b":method", b"GET", false),
                (b":scheme", b"https", false),
                (b":authority", b"x", false),
                (b":path", b"/", false),
                (b"x", b"bad\n", false),
            ],
            Http3HeaderSectionError::InvalidFieldValue { field_index: 4 },
        ),
        (
            &[
                (b":method", b"GET", false),
                (b":scheme", b"https", false),
                (b":authority", b"x", false),
                (b":path", b"/", false),
                (b"connection", b"close", false),
            ],
            Http3HeaderSectionError::ConnectionSpecificField { field_index: 4 },
        ),
        (
            &[
                (b":method", b"GET", false),
                (b":scheme", b"https", false),
                (b":authority", b"x", false),
                (b":path", b"/", false),
                (b"host", b"x", false),
                (b"host", b"x", false),
            ],
            Http3HeaderSectionError::DuplicateHost { field_index: 5 },
        ),
        (
            &[
                (b":method", b"GET", false),
                (b":scheme", b"https", false),
                (b":authority", b"x", false),
                (b":path", b"/", false),
                (b"host", b"", false),
            ],
            Http3HeaderSectionError::InvalidHost { field_index: 4 },
        ),
        (
            &[
                (b":method", b"GET", false),
                (b":scheme", b"https", false),
                (b":authority", b"x", false),
                (b":path", b"/", false),
                (b"host", b"y", false),
            ],
            Http3HeaderSectionError::AuthorityHostMismatch {
                authority_field_index: 2,
                host_field_index: 4,
            },
        ),
    ];
    for &(fields, expected) in cases {
        with_decoded_fields(fields, |section| {
            let error = analyze_decoded_header_section(
                section,
                Http3HeadersContext::Request {
                    extended_connect_enabled: false,
                },
            )
            .unwrap_err();
            assert_eq!(error, expected);
            assert_eq!(error.error_code(), Http3ErrorCode::MESSAGE_ERROR);
            assert!(core::error::Error::source(&error).is_none());
        });
    }
    for value in [b"trailers" as &[u8], b"Trailers ,\tTRAILERS"] {
        with_decoded_fields(
            &[
                (b":method", b"GET", false),
                (b":scheme", b"https", false),
                (b":authority", b"x", false),
                (b":path", b"/", false),
                (b"te", value, false),
            ],
            |section| {
                assert!(
                    analyze_decoded_header_section(
                        section,
                        Http3HeadersContext::Request {
                            extended_connect_enabled: false
                        }
                    )
                    .is_ok()
                )
            },
        );
    }
    for value in [b"gzip" as &[u8], b","] {
        with_decoded_fields(
            &[
                (b":method", b"GET", false),
                (b":scheme", b"https", false),
                (b":authority", b"x", false),
                (b":path", b"/", false),
                (b"te", value, false),
            ],
            |section| {
                assert_eq!(
                    analyze_decoded_header_section(
                        section,
                        Http3HeadersContext::Request {
                            extended_connect_enabled: false
                        }
                    ),
                    Err(Http3HeaderSectionError::InvalidTe { field_index: 4 })
                )
            },
        );
    }
}

#[test]
fn decoded_response_and_trailer_analysis_cover_status_and_forbidden_fields() {
    for (status, kind) in [
        (b"100" as &[u8], Http3HeadersKind::InformationalResponse),
        (b"199", Http3HeadersKind::InformationalResponse),
        (b"200", Http3HeadersKind::FinalResponse),
        (b"599", Http3HeadersKind::FinalResponse),
    ] {
        with_decoded_fields(&[(b":status", status, false)], |section| {
            assert_eq!(
                analyze_decoded_header_section(section, Http3HeadersContext::Response)
                    .unwrap()
                    .kind(),
                kind
            )
        });
    }
    for status in [b"101" as &[u8], b"099", b"600", b"20", b"2x0"] {
        with_decoded_fields(&[(b":status", status, false)], |section| {
            assert_eq!(
                analyze_decoded_header_section(section, Http3HeadersContext::Response),
                Err(Http3HeaderSectionError::InvalidStatus { field_index: 0 })
            )
        });
    }
    for (context, fields, error) in [
        (
            Http3HeadersContext::Response,
            &[
                (b":status" as &[u8], b"200" as &[u8], false),
                (b"te", b"trailers", false),
            ][..],
            Http3HeaderSectionError::InvalidTe { field_index: 1 },
        ),
        (
            Http3HeadersContext::Trailers,
            &[(b":status" as &[u8], b"200" as &[u8], false)][..],
            Http3HeaderSectionError::PseudoFieldInTrailers { field_index: 0 },
        ),
        (
            Http3HeadersContext::Trailers,
            &[(b"connection" as &[u8], b"close" as &[u8], false)][..],
            Http3HeaderSectionError::ConnectionSpecificField { field_index: 0 },
        ),
    ] {
        with_decoded_fields(fields, |section| {
            assert_eq!(analyze_decoded_header_section(section, context), Err(error))
        });
    }
    with_decoded_fields(&[(b"x", b"v", false)], |section| {
        assert_eq!(
            analyze_decoded_header_section(section, Http3HeadersContext::Trailers)
                .unwrap()
                .kind(),
            Http3HeadersKind::Trailers
        )
    });
}

#[test]
fn decoded_connect_analysis_covers_ordinary_and_extended_forms() {
    for authority in [b"example.com:443" as &[u8], b"[::1]:443"] {
        with_decoded_fields(
            &[
                (b":method", b"CONNECT", false),
                (b":authority", authority, false),
                (b"host", authority, false),
            ],
            |section| {
                assert!(
                    analyze_decoded_header_section(
                        section,
                        Http3HeadersContext::Request {
                            extended_connect_enabled: false
                        }
                    )
                    .is_ok()
                )
            },
        );
    }
    for authority in [
        b"example.com" as &[u8],
        b"::1:443",
        b"example.com:x",
        b"example.com:65536",
    ] {
        with_decoded_fields(
            &[
                (b":method", b"CONNECT", false),
                (b":authority", authority, false),
            ],
            |section| {
                assert_eq!(
                    analyze_decoded_header_section(
                        section,
                        Http3HeadersContext::Request {
                            extended_connect_enabled: false
                        }
                    ),
                    Err(Http3HeaderSectionError::InvalidAuthority { field_index: 1 })
                )
            },
        );
    }
    for name in [b":scheme" as &[u8], b":path"] {
        with_decoded_fields(
            &[
                (b":method", b"CONNECT", false),
                (b":authority", b"x:443", false),
                (name, b"x", false),
            ],
            |section| {
                assert_eq!(
                    analyze_decoded_header_section(
                        section,
                        Http3HeadersContext::Request {
                            extended_connect_enabled: false
                        }
                    ),
                    Err(Http3HeaderSectionError::InvalidConnectPseudoFields { field_index: 2 })
                )
            },
        );
    }
    let extended = &[
        (b":method" as &[u8], b"CONNECT" as &[u8], false),
        (b":protocol", b"websocket", false),
        (b":scheme", b"https", false),
        (b":authority", b"x", false),
        (b":path", b"/", false),
    ];
    with_decoded_fields(extended, |section| {
        assert!(
            analyze_decoded_header_section(
                section,
                Http3HeadersContext::Request {
                    extended_connect_enabled: true
                }
            )
            .is_ok()
        )
    });
    with_decoded_fields(extended, |section| {
        assert_eq!(
            analyze_decoded_header_section(
                section,
                Http3HeadersContext::Request {
                    extended_connect_enabled: false
                }
            ),
            Err(Http3HeaderSectionError::InvalidProtocol { field_index: 1 })
        )
    });
    for fields in [
        &[
            (b":method" as &[u8], b"CONNECT" as &[u8], false),
            (b":protocol", b"bad protocol", false),
            (b":scheme", b"https", false),
            (b":authority", b"x", false),
            (b":path", b"/", false),
        ][..],
        &[
            (b":method" as &[u8], b"GET" as &[u8], false),
            (b":protocol", b"websocket", false),
            (b":scheme", b"https", false),
            (b":authority", b"x", false),
            (b":path", b"/", false),
        ][..],
    ] {
        with_decoded_fields(fields, |section| {
            assert_eq!(
                analyze_decoded_header_section(
                    section,
                    Http3HeadersContext::Request {
                        extended_connect_enabled: true
                    }
                ),
                Err(Http3HeaderSectionError::InvalidProtocol { field_index: 1 })
            )
        });
    }
}

#[test]
fn decoded_push_promise_reuses_request_syntax_without_headers_kind() {
    let fields = [
        (b":method" as &[u8], b"GET" as &[u8], false),
        (b":scheme", b"https", false),
        (b":authority", b"x", false),
        (b":path", b"/", false),
    ];
    with_decoded_fields(&fields, |section| {
        let promise: Http3DecodedPushPromise<'_> =
            analyze_decoded_push_promise(section, false).unwrap();
        assert_eq!(promise.section(), section);
        assert_eq!(promise.field_section_size(), 167);
    });
    with_decoded_fields(
        &[
            (b":method", b"GET", false),
            (b":scheme", b"https", false),
            (b":path", b"/", false),
        ],
        |section| {
            let error = analyze_decoded_push_promise(section, false).unwrap_err();
            assert_eq!(error, Http3HeaderSectionError::MissingAuthorityOrHost);
            assert_eq!(error.error_code(), Http3ErrorCode::MESSAGE_ERROR);
            assert!(error.to_string().contains("missing :authority and Host"));
            assert!(core::error::Error::source(&error).is_none());
        },
    );
}
