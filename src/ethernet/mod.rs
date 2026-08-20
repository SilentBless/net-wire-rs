//! Ethernet II semantic fields and caller-bounded frame views.
//!
//! The represented header order follows [RFC 894](https://www.rfc-editor.org/rfc/rfc894).
//! Ethernet on the medium may add minimum-frame padding and a four-octet frame check sequence
//! (FCS) after the protocol payload. This API deliberately does not model either as an implicit
//! trailer: Ethernet II carries no payload length that could distinguish payload, padding, and
//! FCS from bytes alone, and receive APIs commonly remove the FCS before exposing a frame.
//!
//! Consequently, every supplied byte after the fixed 14-octet header is the frame view's
//! payload. Callers with capture metadata must use it to establish the intended frame boundary.
//! A nested protocol can impose a narrower boundary—for example, IPv4 `total_length` excludes
//! trailing Ethernet bytes from the returned IPv4 packet—but such a tail is not thereby proven
//! to be padding or a valid FCS.

pub(crate) mod layout;
pub(crate) mod types;

/// Generated Ethernet II frame views and caller-buffer construction.
pub use layout::{
    EthernetFrame, EthernetFrameBuilder, EthernetFrameError, EthernetFrameMutationError,
    EthernetFrameViewMut, EthernetFrameWriteError,
};
/// Ethernet semantic field types.
pub use types::{EtherType, MacAddress};
