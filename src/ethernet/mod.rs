//! Ethernet II semantic fields and borrowed frame views.
//!
//! The represented header order follows
//! [RFC 894](https://www.rfc-editor.org/rfc/rfc894). Callers must remove any frame check
//! sequence (FCS) before parsing; every supplied byte after the fixed header is payload.

mod address;
mod ether_type;
mod frame;

/// Ethernet hardware addresses.
pub use address::MacAddress;
/// Ethernet protocol type values.
pub use ether_type::EtherType;
/// Ethernet II frame views and caller-buffer construction.
pub use frame::{EthernetFrame, EthernetFrameBuildError, EthernetFrameBuilder, EthernetFrameMut};
