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
#[cfg(any(feature = "http2", feature = "qpack"))]
mod header_huffman;
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
#[cfg(feature = "http3")]
/// Standalone raw HTTP/3 frame views and caller-buffer construction.
pub mod http3;
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
#[cfg(feature = "qpack")]
/// Standalone QPACK prefixed integers, Huffman payloads, and string-literal views.
pub mod qpack;
#[cfg(feature = "quic")]
/// Standalone QUIC wire primitives and borrowed packet-header views.
pub mod quic;
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
#[cfg(feature = "http3")]
pub use http3::{
    Http3CancelPush, Http3CancelPushBuilder, Http3ControlFrame, Http3ControlStreamError,
    Http3ControlStreamState, Http3CriticalUniStreamKind, Http3Data, Http3DataBuilder,
    Http3DecodedHeaderSection, Http3DecodedPushPromise, Http3EndpointRole, Http3ErrorCode,
    Http3Frame, Http3FrameBuildError, Http3FrameBuilder, Http3FrameMut, Http3FrameParseError,
    Http3FramePayloadBuildError, Http3FramePayloadField, Http3FramePayloadParseError,
    Http3FrameType, Http3Goaway, Http3GoawayBuilder, Http3HeaderSectionContext,
    Http3HeaderSectionError, Http3HeaderSectionKind, Http3Headers, Http3HeadersBuilder,
    Http3MaxPushId, Http3MaxPushIdBuilder, Http3MessageContentDisposition,
    Http3MessageContentError, Http3MessageContentKind, Http3MessageContentOperation,
    Http3MessageContentState, Http3MessageFrame, Http3MessagePosition, Http3MessageStreamError,
    Http3MessageStreamKind, Http3MessageStreamState, Http3PeerSettings, Http3PeerUniStreamError,
    Http3PeerUniStreamEvent, Http3PeerUniStreamState, Http3PendingHeaders, Http3PushId,
    Http3PushPromise, Http3PushPromiseBuilder, Http3QpackFieldSectionError,
    Http3ResponseRequestContext, Http3Setting, Http3SettingId, Http3SettingValue, Http3Settings,
    Http3SettingsBuilder, Http3SettingsIter, Http3SettingsSemanticError, Http3StreamId,
    Http3StreamType, Http3UniStreamBuildError, Http3UniStreamField, Http3UniStreamHeader,
    Http3UniStreamHeaderBuilder, Http3UniStreamKind, Http3UniStreamParseError,
    analyze_decoded_header_section, analyze_decoded_push_promise,
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
#[cfg(feature = "qpack")]
pub use qpack::{
    QPACK_INTEGER_MAX, QPACK_STATIC_TABLE_LEN, QpackBlockedStream, QpackBlockedStreams,
    QpackBlockedStreamsError, QpackDecodedFieldEntry, QpackDecodedFieldIter, QpackDecodedFieldRef,
    QpackDecodedFieldSection, QpackDecoderFeedbackError, QpackDecoderInstruction,
    QpackDecoderInstructionApplyError, QpackDecoderInstructionBuildError,
    QpackDecoderInstructionIter, QpackDecoderInstructionParseError, QpackDecoderInstructions,
    QpackDecoderInstructionsApplyError, QpackDecoderInstructionsParseError, QpackDecoderState,
    QpackDuplicate, QpackDuplicateBuilder, QpackDynamicTable, QpackDynamicTableEntry,
    QpackDynamicTableError, QpackEncodedFieldSection, QpackEncoderInstruction,
    QpackEncoderInstructionApplier, QpackEncoderInstructionApplyError,
    QpackEncoderInstructionApplyOutcome, QpackEncoderInstructionBuildError,
    QpackEncoderInstructionIter, QpackEncoderInstructionParseError, QpackEncoderInstructions,
    QpackEncoderInstructionsApplyError, QpackEncoderInstructionsParseError,
    QpackEncoderOutstandingSection, QpackEncoderState, QpackEncoderStateError, QpackFieldLine,
    QpackFieldLineBuildError, QpackFieldLineIter, QpackFieldLineParseError, QpackFieldLines,
    QpackFieldLinesParseError, QpackFieldPlan, QpackFieldSectionBase, QpackFieldSectionBlocked,
    QpackFieldSectionContext, QpackFieldSectionContextError, QpackFieldSectionDecodeError,
    QpackFieldSectionDecodeOutcome, QpackFieldSectionDecoder, QpackFieldSectionEncodeBuffers,
    QpackFieldSectionEncodeError, QpackFieldSectionEncoder, QpackFieldSectionOutput,
    QpackFieldSectionPlanError, QpackFieldSectionPlanSlot, QpackFieldSectionPrefix,
    QpackFieldSectionPrefixBuildError, QpackFieldSectionPrefixBuilder,
    QpackFieldSectionPrefixParseError, QpackHeaderFieldRef, QpackHuffmanDecodeError,
    QpackHuffmanDecoder, QpackHuffmanEncodeError, QpackHuffmanEncoder, QpackIndexedFieldLine,
    QpackIndexedFieldLineBuilder, QpackIndexedPostBaseFieldLine,
    QpackIndexedPostBaseFieldLineBuilder, QpackInsertCountIncrement,
    QpackInsertCountIncrementBuilder, QpackInsertWithLiteralName,
    QpackInsertWithLiteralNameBuilder, QpackInsertWithNameReference,
    QpackInsertWithNameReferenceBuilder, QpackInteger, QpackIntegerBuildError, QpackIntegerBuilder,
    QpackIntegerParseError, QpackLiteralNameFieldLine, QpackLiteralNameFieldLineBuilder,
    QpackLiteralNameReferenceFieldLine, QpackLiteralNameReferenceFieldLineBuilder,
    QpackLiteralPostBaseNameReferenceFieldLine, QpackLiteralPostBaseNameReferenceFieldLineBuilder,
    QpackReadyBlockedStreamIter, QpackSectionAcknowledgment, QpackSectionAcknowledgmentBuilder,
    QpackSetDynamicTableCapacity, QpackSetDynamicTableCapacityBuilder, QpackStaticTable,
    QpackStreamCancellation, QpackStreamCancellationBuilder, QpackStringLiteral,
    QpackStringLiteralBuildError, QpackStringLiteralBuilder, QpackStringLiteralParseError,
};
#[cfg(all(feature = "quic", feature = "tls"))]
pub use quic::QuicTransportParametersTlsExtensionError;
#[cfg(feature = "quic")]
pub use quic::{
    QuicAckFrame, QuicAckRange, QuicAckRanges, QuicConnectionCloseFrame, QuicConnectionId,
    QuicConnectionIdField, QuicCryptoFrame, QuicDataBlockedFrame, QuicDatagram, QuicEcnCounts,
    QuicFrame, QuicFrameField, QuicFrameIter, QuicFrameParseError, QuicFrames,
    QuicHandshakeDoneFrame, QuicHandshakePacketBuilder, QuicInitialPacketBuilder, QuicLongHeader,
    QuicLongPacketType, QuicMaxDataFrame, QuicMaxStreamDataFrame, QuicMaxStreamsFrame,
    QuicNewConnectionIdFrame, QuicNewTokenFrame, QuicPacket, QuicPacketBuildError,
    QuicPacketBuildField, QuicPacketNumberLen, QuicPacketParseError, QuicPackets, QuicPaddingFrame,
    QuicPathChallengeFrame, QuicPathResponseFrame, QuicPingFrame, QuicPreferredAddress,
    QuicProtectedLongPacket, QuicResetStreamFrame, QuicRetireConnectionIdFrame, QuicRetryPacket,
    QuicRetryPacketBuilder, QuicShortHeader, QuicShortHeaderContext, QuicShortPacketBuilder,
    QuicStopSendingFrame, QuicStreamDataBlockedFrame, QuicStreamDirection, QuicStreamFrame,
    QuicStreamsBlockedFrame, QuicTransportParameter, QuicTransportParameterField,
    QuicTransportParameterHandshakeContext, QuicTransportParameterHandshakeError,
    QuicTransportParameterId, QuicTransportParameterIter, QuicTransportParameterParseError,
    QuicTransportParameterSemanticError, QuicTransportParameterSender,
    QuicTransportParameterValueError, QuicTransportParameterValueKind, QuicTransportParameters,
    QuicTransportParametersV1, QuicTruncatedPacketNumber, QuicUnknownLongPacket,
    QuicUnprotectedHeaderError, QuicUnprotectedLongHeader, QuicUnprotectedShortHeader, QuicVarInt,
    QuicVarIntBuildError, QuicVarIntBuilder, QuicVarIntLen, QuicVarIntParseError, QuicVersion,
    QuicVersionIter, QuicVersionNegotiationPacket, QuicVersionNegotiationPacketBuilder,
    QuicZeroRttPacketBuilder,
};
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
