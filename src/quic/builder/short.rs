//! Protected QUIC v1 and v2 short-packet builder.

use super::super::{
    QuicConnectionId, QuicConnectionIdField, QuicPacketBuildError, QuicShortHeader,
};

/// Builds a complete protected QUIC short-header packet in caller-owned storage.
///
/// The protected low five bits and protected remainder are copied exactly without
/// interpreting header-protection, packet-number, or payload semantics.
pub struct QuicShortPacketBuilder<'buffer, 'input> {
    destination: &'buffer mut [u8],
    spin: bool,
    protected_low_bits: u8,
    destination_connection_id: QuicConnectionId<'input>,
    protected_remainder: &'input [u8],
}

impl<'buffer, 'input> QuicShortPacketBuilder<'buffer, 'input> {
    /// Creates a builder with exact opaque short-header protected bytes.
    pub fn new(
        destination: &'buffer mut [u8],
        spin: bool,
        protected_low_bits: u8,
        destination_connection_id: QuicConnectionId<'input>,
        protected_remainder: &'input [u8],
    ) -> Self {
        Self {
            destination,
            spin,
            protected_low_bits,
            destination_connection_id,
            protected_remainder,
        }
    }

    /// Validates all inputs and capacity before writing a complete protected short packet.
    pub fn build(self) -> Result<QuicShortHeader<'buffer>, QuicPacketBuildError> {
        if self.protected_low_bits > 0x1f {
            return Err(QuicPacketBuildError::ProtectedLowBitsOutOfRange {
                maximum: 0x1f,
                actual: self.protected_low_bits,
            });
        }
        if self.destination_connection_id.len() > 20 {
            return Err(QuicPacketBuildError::ConnectionIdTooLong {
                field: QuicConnectionIdField::Destination,
                maximum: 20,
                actual: self.destination_connection_id.len(),
            });
        }
        if self.protected_remainder.len() < 2 {
            return Err(QuicPacketBuildError::ProtectedRemainderTooShort {
                minimum: 2,
                actual: self.protected_remainder.len(),
            });
        }

        let destination_end = checked_add(
            1,
            self.destination_connection_id.len(),
            "destination connection ID",
        )?;
        let required = checked_add(
            destination_end,
            self.protected_remainder.len(),
            "protected remainder",
        )?;
        if self.destination.len() < required {
            return Err(QuicPacketBuildError::BufferTooShort {
                required,
                available: self.destination.len(),
            });
        }

        let destination = self.destination;
        destination[0] = 0x40 | (u8::from(self.spin) << 5) | self.protected_low_bits;
        destination[1..destination_end].copy_from_slice(self.destination_connection_id.as_bytes());
        destination[destination_end..required].copy_from_slice(self.protected_remainder);

        let bytes = &destination[..required];
        Ok(QuicShortHeader::from_validated(
            bytes,
            bytes[0],
            QuicConnectionId::new(&bytes[1..destination_end]),
            &bytes[destination_end..],
        ))
    }
}

fn checked_add(
    offset: usize,
    length: usize,
    component: &'static str,
) -> Result<usize, QuicPacketBuildError> {
    offset
        .checked_add(length)
        .ok_or(QuicPacketBuildError::LengthOverflow {
            component,
            offset,
            length,
        })
}
