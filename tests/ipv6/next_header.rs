use net_wire::ipv6::Ipv6NextHeader;

#[test]
fn next_header_constants_are_public_protocol_numbers() {
    assert_eq!(
        [
            Ipv6NextHeader::HOPOPT.raw(),
            Ipv6NextHeader::ROUTING.raw(),
            Ipv6NextHeader::FRAGMENT.raw(),
            Ipv6NextHeader::ESP.raw(),
            Ipv6NextHeader::AUTHENTICATION.raw(),
            Ipv6NextHeader::DESTINATION_OPTIONS.raw(),
            Ipv6NextHeader::TCP.raw(),
            Ipv6NextHeader::UDP.raw(),
            Ipv6NextHeader::ICMPV6.raw(),
            Ipv6NextHeader::NO_NEXT_HEADER.raw(),
        ],
        [0, 43, 44, 50, 51, 60, 6, 17, 58, 59]
    );
}
