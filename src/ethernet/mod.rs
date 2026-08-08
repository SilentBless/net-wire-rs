//! Ethernet II semantic fields and borrowed frame views.
//!
//! The represented header order follows
//! [RFC 894](https://www.rfc-editor.org/rfc/rfc894). Callers must remove any frame check
//! sequence (FCS) before parsing; every supplied byte after the fixed header is payload.

pub(crate) mod address;
mod builder;
pub(crate) mod ether_type;
pub(crate) mod frame;

/// Ethernet hardware addresses.
pub use address::MacAddress;
/// Ethernet II frame construction.
pub use builder::{EthernetFrameBuildError, EthernetFrameBuilder};
/// Ethernet protocol type values.
pub use ether_type::EtherType;
/// Ethernet II frame views.
pub use frame::{EthernetFrame, EthernetFrameMut};
