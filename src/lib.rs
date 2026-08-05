#![no_std]
#![deny(missing_docs)]

//! Borrowed, allocation-free views of network wire layouts.
//!
//! This crate performs no I/O or allocation. The default feature set is empty; protocol
//! features are independent and can be enabled in any supported combination.

#[cfg(any(
    feature = "ipv4",
    feature = "icmpv4",
    all(feature = "ipv4", any(feature = "udp", feature = "tcp")),
    all(
        feature = "ipv6",
        any(feature = "icmpv6", feature = "udp", feature = "tcp")
    )
))]
mod checksum;
#[cfg(any(
    all(feature = "ipv4", feature = "tcp"),
    all(feature = "ipv6", any(feature = "icmpv6", feature = "tcp"))
))]
mod pseudoheader;

#[cfg(feature = "arp")]
/// ARP packet views, semantic fields, and caller-buffer construction.
pub mod arp;
/// Allocation-free parsing errors.
pub mod error;
#[cfg(feature = "ethernet")]
/// Ethernet II frame views, semantic fields, and caller-buffer construction.
pub mod ethernet;
#[cfg(feature = "http1")]
/// Standalone HTTP/1 head and chunked-body views and caller-buffer construction.
pub mod http1;
#[cfg(feature = "http2")]
/// Standalone raw HTTP/2 preface and frame views and caller-buffer construction.
pub mod http2;
#[cfg(feature = "icmpv4")]
/// ICMPv4 message views and caller-buffer construction.
pub mod icmpv4;
#[cfg(feature = "icmpv6")]
/// ICMPv6 message views and caller-buffer construction.
pub mod icmpv6;
#[cfg(feature = "ipv4")]
/// IPv4 packet views, semantic fields, and caller-buffer construction.
pub mod ipv4;
#[cfg(feature = "ipv6")]
/// IPv6 packet views, semantic fields, and caller-buffer construction.
pub mod ipv6;
#[cfg(feature = "tcp")]
/// TCP segment views and caller-buffer construction.
pub mod tcp;
#[cfg(feature = "tls")]
/// TLS record and handshake views and caller-buffer construction.
pub mod tls;
#[cfg(feature = "udp")]
/// UDP datagram views and caller-buffer construction.
pub mod udp;

#[cfg(feature = "arp")]
pub use arp::{
    ArpHardwareType, ArpOperation, ArpPacket, ArpPacketBuildError, ArpPacketBuilder, ArpPacketMut,
    ArpProtocolType,
};
pub use error::ParseError;
#[cfg(feature = "ethernet")]
pub use ethernet::{
    EtherType, EthernetFrame, EthernetFrameBuildError, EthernetFrameBuilder, EthernetFrameMut,
    MacAddress,
};
#[cfg(feature = "http1")]
pub use http1::{
    Http1BodyFraming, Http1BuildError, Http1Chunk, Http1ChunkedBody, Http1Chunks, Http1Field,
    Http1FieldIter, Http1FieldRef, Http1Fields, Http1ParseError, Http1RequestHead,
    Http1RequestHeadBuilder, Http1ResponseHead, Http1ResponseHeadBuilder, Http1Version,
};
#[cfg(feature = "http2")]
pub use http2::{
    HPACK_STATIC_TABLE_LEN, HTTP2_CLIENT_PREFACE, HpackBlockDecoder, HpackBlockEncoder,
    HpackDecodeError, HpackDecodeStep, HpackDecodedField, HpackDecodedFieldMode,
    HpackDecoderContext, HpackDynamicTable, HpackDynamicTableEntry, HpackDynamicTableError,
    HpackDynamicTableInsertResult, HpackDynamicTableSizeUpdate, HpackDynamicTableSizeUpdateBuilder,
    HpackEncodeError, HpackEncodeLiteralName, HpackEncoderContext, HpackHeaderFieldRef,
    HpackHuffmanDecodeError, HpackHuffmanDecoder, HpackHuffmanEncodeError, HpackHuffmanEncoder,
    HpackIndexedField, HpackIndexedFieldBuilder, HpackInteger, HpackIntegerBuildError,
    HpackIntegerBuilder, HpackIntegerParseError, HpackLiteralField, HpackLiteralFieldBuilder,
    HpackLiteralHuffman, HpackLiteralMode, HpackLiteralName, HpackLiteralValue,
    HpackRepresentation, HpackRepresentationBuildError, HpackRepresentationParseError,
    HpackStaticTable, HpackStringLiteral, HpackStringLiteralBuildError, HpackStringLiteralBuilder,
    HpackStringLiteralParseError, Http2BuildError, Http2ClientPreface, Http2Continuation,
    Http2ContinuationBuilder, Http2Data, Http2DataBuilder, Http2ErrorCode, Http2Frame,
    Http2FrameBuilder, Http2FrameMut, Http2FrameType, Http2Goaway, Http2GoawayBuilder,
    Http2HeaderBlockFragment, Http2HeaderBlockSequence, Http2HeaderBlockSequenceError,
    Http2Headers, Http2HeadersBuilder, Http2ParseError, Http2Ping, Http2PingBuilder, Http2Priority,
    Http2PriorityFrame, Http2PriorityFrameBuilder, Http2PushPromise, Http2PushPromiseBuilder,
    Http2RstStream, Http2RstStreamBuilder, Http2Setting, Http2SettingId, Http2Settings,
    Http2SettingsBuilder, Http2SettingsIter, Http2StreamId, Http2StreamIdError,
    Http2WindowIncrement, Http2WindowUpdate, Http2WindowUpdateBuilder,
};
#[cfg(feature = "icmpv4")]
pub use icmpv4::{
    Icmpv4Message, Icmpv4MessageBuildError, Icmpv4MessageBuilder, Icmpv4MessageMut, Icmpv4Type,
};
#[cfg(feature = "icmpv6")]
pub use icmpv6::{
    Icmpv6Message, Icmpv6MessageBuildError, Icmpv6MessageBuilder, Icmpv6MessageMut, Icmpv6Type,
};
#[cfg(feature = "ipv4")]
pub use ipv4::{
    Ipv4Address, Ipv4Packet, Ipv4PacketBuildError, Ipv4PacketBuilder, Ipv4PacketMut, Ipv4Protocol,
};
#[cfg(feature = "ipv6")]
pub use ipv6::{
    Ipv6Address, Ipv6NextHeader, Ipv6Packet, Ipv6PacketBuildError, Ipv6PacketBuilder,
    Ipv6PacketMut, Ipv6PayloadLength,
};
#[cfg(any(
    all(feature = "ipv4", feature = "tcp"),
    all(feature = "ipv6", any(feature = "icmpv6", feature = "tcp"))
))]
pub use pseudoheader::PseudoHeaderChecksumError;
#[cfg(feature = "tcp")]
pub use tcp::{TcpFlags, TcpSegment, TcpSegmentBuildError, TcpSegmentBuilder, TcpSegmentMut};
#[cfg(feature = "tls")]
pub use tls::{
    AlpnProtocol, AlpnProtocolIter, AlpnProtocolList, CertificateCompressionAlgorithms,
    ClientHello, ClientHelloBuilder, ClientKeyShare, ClientPreSharedKey, ClientServerNameList,
    ClientSupportedVersions, Cookie, EcPointFormats, HELLO_RETRY_REQUEST_RANDOM, HrrKeyShare,
    KeyShareEntry, KeyShareIter, PskBinderIter, PskIdentity, PskIdentityIter, PskKeyExchangeModes,
    ServerHello, ServerHelloBuilder, ServerKeyShare, ServerName, ServerNameIter,
    ServerPreSharedKey, ServerSelectedAlpn, ServerSupportedVersion, SignatureAlgorithms,
    SupportedGroups, SupportedVersions, TlsBuildError, TlsCertificateCompressionAlgorithm,
    TlsCipherSuite, TlsCompressionMethod, TlsContentType, TlsExtension, TlsExtensionBuilder,
    TlsExtensionType, TlsExtensions, TlsHandshake, TlsHandshakeBuilder, TlsHandshakeType,
    TlsNamedGroup, TlsParseError, TlsProtocolVersion, TlsPskKeyExchangeMode, TlsRecord,
    TlsRecordBuilder, TlsRecordMut, TlsServerNameType, TlsSignatureScheme,
};
#[cfg(feature = "udp")]
pub use udp::{
    UdpChecksumStatus, UdpDatagram, UdpDatagramBuildError, UdpDatagramBuilder, UdpDatagramMut,
};
