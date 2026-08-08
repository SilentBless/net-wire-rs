use core::fmt;

use super::packet::{ArpPacketMut, PREFIX_LENGTH};
use super::types::{ArpHardwareType, ArpOperation, ArpProtocolType};

/// Failure while validating an ARP builder request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArpPacketBuildError {
    /// No hardware type was supplied.
    MissingHardwareType,
    /// No protocol type was supplied.
    MissingProtocolType,
    /// No operation was supplied.
    MissingOperation,
    /// The four address inputs were not supplied together.
    MissingAddresses,
    /// Sender and target address sizes differ for one address category.
    AddressLengthMismatch,
    /// A hardware or protocol address exceeds RFC 826's one-octet length field.
    AddressLengthTooLarge,
    /// The caller buffer cannot hold the complete RFC 826 packet.
    BufferTooShort {
        /// Required packet length.
        required: usize,
        /// Available buffer length.
        available: usize,
    },
}

impl fmt::Display for ArpPacketBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingHardwareType => f.write_str("missing ARP hardware type"),
            Self::MissingProtocolType => f.write_str("missing ARP protocol type"),
            Self::MissingOperation => f.write_str("missing ARP operation"),
            Self::MissingAddresses => f.write_str("missing ARP addresses"),
            Self::AddressLengthMismatch => {
                f.write_str("ARP sender and target address lengths differ")
            }
            Self::AddressLengthTooLarge => f.write_str("ARP address length exceeds 255 octets"),
            Self::BufferTooShort {
                required,
                available,
            } => write!(
                f,
                "ARP buffer is too short: need {required} bytes, have {available}"
            ),
        }
    }
}

/// Builds one RFC 826 packet in a caller-provided buffer.
pub struct ArpPacketBuilder<'buffer, 'input> {
    buffer: &'buffer mut [u8],
    hardware_type: Option<ArpHardwareType>,
    protocol_type: Option<ArpProtocolType>,
    operation: Option<ArpOperation>,
    sender_hardware: Option<&'input [u8]>,
    sender_protocol: Option<&'input [u8]>,
    target_hardware: Option<&'input [u8]>,
    target_protocol: Option<&'input [u8]>,
}

impl<'buffer, 'input> ArpPacketBuilder<'buffer, 'input> {
    /// Starts a builder whose result borrows only `buffer`.
    #[inline]
    pub fn new(buffer: &'buffer mut [u8]) -> Self {
        Self {
            buffer,
            hardware_type: None,
            protocol_type: None,
            operation: None,
            sender_hardware: None,
            sender_protocol: None,
            target_hardware: None,
            target_protocol: None,
        }
    }
    /// Supplies the RFC 826 hardware type.
    #[inline]
    pub fn hardware_type(mut self, value: ArpHardwareType) -> Self {
        self.hardware_type = Some(value);
        self
    }
    /// Supplies the RFC 826 protocol type.
    #[inline]
    pub fn protocol_type(mut self, value: ArpProtocolType) -> Self {
        self.protocol_type = Some(value);
        self
    }
    /// Supplies the RFC 826 operation.
    #[inline]
    pub fn operation(mut self, value: ArpOperation) -> Self {
        self.operation = Some(value);
        self
    }
    /// Supplies sender-hardware, sender-protocol, target-hardware, and target-protocol addresses.
    #[inline]
    pub fn addresses(
        mut self,
        sender_hardware: &'input [u8],
        sender_protocol: &'input [u8],
        target_hardware: &'input [u8],
        target_protocol: &'input [u8],
    ) -> Self {
        self.sender_hardware = Some(sender_hardware);
        self.sender_protocol = Some(sender_protocol);
        self.target_hardware = Some(target_hardware);
        self.target_protocol = Some(target_protocol);
        self
    }
    /// Validates every field and capacity before writing; trailing buffer bytes remain unchanged.
    #[inline]
    pub fn build(self) -> Result<ArpPacketMut<'buffer>, ArpPacketBuildError> {
        let hardware_type = self
            .hardware_type
            .ok_or(ArpPacketBuildError::MissingHardwareType)?;
        let protocol_type = self
            .protocol_type
            .ok_or(ArpPacketBuildError::MissingProtocolType)?;
        let operation = self
            .operation
            .ok_or(ArpPacketBuildError::MissingOperation)?;
        let sender_hardware = self
            .sender_hardware
            .ok_or(ArpPacketBuildError::MissingAddresses)?;
        let sender_protocol = self
            .sender_protocol
            .ok_or(ArpPacketBuildError::MissingAddresses)?;
        let target_hardware = self
            .target_hardware
            .ok_or(ArpPacketBuildError::MissingAddresses)?;
        let target_protocol = self
            .target_protocol
            .ok_or(ArpPacketBuildError::MissingAddresses)?;
        if sender_hardware.len() != target_hardware.len()
            || sender_protocol.len() != target_protocol.len()
        {
            return Err(ArpPacketBuildError::AddressLengthMismatch);
        }
        if sender_hardware.len() > u8::MAX as usize || sender_protocol.len() > u8::MAX as usize {
            return Err(ArpPacketBuildError::AddressLengthTooLarge);
        }
        let length = PREFIX_LENGTH + 2 * sender_hardware.len() + 2 * sender_protocol.len();
        if self.buffer.len() < length {
            return Err(ArpPacketBuildError::BufferTooShort {
                required: length,
                available: self.buffer.len(),
            });
        }
        let bytes = &mut self.buffer[..length];
        bytes[0..2].copy_from_slice(&hardware_type.raw().to_be_bytes());
        bytes[2..4].copy_from_slice(&protocol_type.raw().to_be_bytes());
        bytes[4] = sender_hardware.len() as u8;
        bytes[5] = sender_protocol.len() as u8;
        bytes[6..8].copy_from_slice(&operation.raw().to_be_bytes());
        let mut offset = PREFIX_LENGTH;
        bytes[offset..offset + sender_hardware.len()].copy_from_slice(sender_hardware);
        offset += sender_hardware.len();
        bytes[offset..offset + sender_protocol.len()].copy_from_slice(sender_protocol);
        offset += sender_protocol.len();
        bytes[offset..offset + target_hardware.len()].copy_from_slice(target_hardware);
        offset += target_hardware.len();
        bytes[offset..].copy_from_slice(target_protocol);
        Ok(ArpPacketMut::from_validated(
            bytes,
            sender_hardware.len(),
            sender_protocol.len(),
        ))
    }
}
