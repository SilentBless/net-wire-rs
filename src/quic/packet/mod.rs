//! QUIC packet borrowed views.

mod datagram;
pub(super) mod header;
pub(in crate::quic) mod layout;
pub(super) mod long;
mod parse;
pub(super) mod terminal;
mod unprotected;

pub use datagram::{QuicDatagram, QuicPacket, QuicPackets, QuicUnknownLongPacket};
pub use header::{
    QuicConnectionId, QuicConnectionIdField, QuicLongHeader, QuicLongPacketType, QuicShortHeader,
    QuicShortHeaderContext, QuicVersion,
};
pub use long::QuicProtectedLongPacket;
pub use parse::QuicPacketParseError;
pub use terminal::{QuicRetryPacket, QuicVersionIter, QuicVersionNegotiationPacket};
pub use unprotected::{
    QuicPacketNumberLen, QuicTruncatedPacketNumber, QuicUnprotectedHeaderError,
    QuicUnprotectedLongHeader, QuicUnprotectedShortHeader,
};
