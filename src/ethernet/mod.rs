//! Ethernet II semantic fields and caller-bounded frame views.
//!
//! The represented header order follows [RFC 894](https://www.rfc-editor.org/rfc/rfc894).
//! Every supplied byte after the fixed 14-octet header is payload; callers must bound input
//! before parsing to exclude an FCS or capture padding when those bytes are not payload.

pub(crate) mod address;
pub(crate) mod ether_type;
pub(crate) mod layout;

/// Ethernet hardware addresses.
pub use address::MacAddress;
/// Ethernet protocol type values.
pub use ether_type::EtherType;
/// Generated Ethernet II frame views and caller-buffer construction.
pub use layout::{
    EthernetFrameBuilder, EthernetFrameError, EthernetFrameMutationError, EthernetFrameView,
    EthernetFrameViewMut, EthernetFrameWriteError,
};
