//! User Datagram Protocol views and caller-buffer construction (RFC 768).

mod builder;
#[cfg(any(
    all(feature = "udp", feature = "ipv4"),
    all(feature = "udp", feature = "ipv6")
))]
mod checksum;
pub(crate) mod datagram;

pub use builder::{UdpDatagramBuildError, UdpDatagramBuilder};
#[cfg(all(feature = "udp", feature = "ipv4"))]
pub use checksum::UdpChecksumStatus;
pub use datagram::{UdpDatagram, UdpDatagramMut};
