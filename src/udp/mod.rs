//! User Datagram Protocol views and caller-buffer construction (RFC 768).

mod builder;
mod datagram;

pub use builder::{UdpDatagramBuildError, UdpDatagramBuilder};
pub use datagram::{UdpDatagram, UdpDatagramMut};
