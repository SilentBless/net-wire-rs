#![no_std]
#![deny(missing_docs)]

//! Borrowed, allocation-free views of network wire layouts.
//!
//! This crate performs no I/O or allocation. The default feature set is empty. Protocols are
//! selected explicitly; intrinsic lower-protocol requirements are enabled transitively, while
//! optional adapters remain orthogonal.

mod error;
#[cfg(any(
    feature = "ipv4",
    feature = "icmpv4",
    all(feature = "ipv4", any(feature = "udp", feature = "tcp")),
    all(
        feature = "ipv6",
        any(feature = "icmpv6", feature = "udp", feature = "tcp")
    )
))]
mod internet_checksum;
#[cfg(any(feature = "http2", feature = "qpack"))]
mod rfc7541_huffman;

#[cfg(feature = "arp")]
/// ARP packet views, semantic fields, and caller-buffer construction.
pub mod arp;
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
#[cfg(feature = "kcp")]
/// KCP wire segment views and stateless scalar helpers.
pub mod kcp;
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

pub use error::ParseError;
#[cfg(any(
    all(feature = "ipv4", feature = "tcp"),
    all(feature = "ipv6", any(feature = "icmpv6", feature = "tcp"))
))]
pub use internet_checksum::PseudoHeaderChecksumError;
