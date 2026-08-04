#![no_std]
#![deny(missing_docs)]

//! Borrowed, allocation-free views of network wire layouts.
//!
//! This crate parses and writes protocol headers in caller-owned byte slices. It is a
//! wire-layout toolkit, not a networking stack: it performs no I/O, allocation, packet
//! storage ownership, or nested-protocol dispatch.
//!
//! The default feature set is intentionally empty. Enable the `ethernet` feature for
//! Ethernet II frame views and builders.

/// Allocation-free parsing errors shared by wire-format views.
pub mod error;
#[cfg(feature = "ethernet")]
/// Ethernet II frame views, semantic fields, and a caller-buffer builder.
pub mod ethernet;

/// Allocation-free parsing errors.
pub use error::ParseError;
#[cfg(feature = "ethernet")]
/// Ethernet II frame views, builder, and semantic Ethernet field types.
pub use ethernet::{
    EtherType, EthernetFrame, EthernetFrameBuildError, EthernetFrameBuilder, EthernetFrameMut,
    MacAddress,
};
