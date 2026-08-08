//! Transmission Control Protocol views and caller-buffer construction (RFC 9293).

mod builder;
mod flags;
pub(crate) mod segment;

pub use builder::{TcpSegmentBuildError, TcpSegmentBuilder};
pub use flags::TcpFlags;
pub use segment::{TcpSegment, TcpSegmentMut};
