//! Transmission Control Protocol views and caller-buffer construction (RFC 9293).

mod builder;
#[cfg(any(
    all(feature = "tcp", feature = "ipv4"),
    all(feature = "tcp", feature = "ipv6")
))]
mod checksum;
mod flags;
pub(crate) mod segment;

pub use builder::{TcpSegmentBuildError, TcpSegmentBuilder};
#[cfg(any(
    all(feature = "tcp", feature = "ipv4"),
    all(feature = "tcp", feature = "ipv6")
))]
pub use checksum::TcpChecksumError;
pub use flags::TcpFlags;
pub use segment::{TcpSegment, TcpSegmentMut};
