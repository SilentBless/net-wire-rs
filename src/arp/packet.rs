use crate::ParseError;
#[cfg(feature = "ethernet")]
use crate::{EtherType, EthernetFrame, EthernetFrameMut, MacAddress};

use super::{ArpHardwareType, ArpOperation, ArpProtocolType};

const PREFIX_LENGTH: usize = 8;

/// A structurally validated immutable ARP packet view.
///
/// RFC 826 uses independent one-octet hardware and protocol address lengths. Parsing
/// validates that layout and restricts the view to it, excluding supplied trailing bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArpPacket<'a> {
    bytes: &'a [u8],
    hardware_length: usize,
    protocol_length: usize,
}

impl<'a> ArpPacket<'a> {
    /// Validates the generic RFC 826 layout without interpreting address semantics.
    #[inline]
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let (hardware_length, protocol_length, length) = validate(bytes)?;
        Ok(Self {
            bytes: &bytes[..length],
            hardware_length,
            protocol_length,
        })
    }
    /// Returns the RFC 826 hardware type, preserving unknown values.
    #[inline]
    pub fn hardware_type(&self) -> ArpHardwareType {
        ArpHardwareType::new(u16::from_be_bytes(
            self.bytes[0..2].try_into().expect("validated ARP prefix"),
        ))
    }
    /// Returns the RFC 826 protocol type, preserving unknown values.
    #[inline]
    pub fn protocol_type(&self) -> ArpProtocolType {
        ArpProtocolType::new(u16::from_be_bytes(
            self.bytes[2..4].try_into().expect("validated ARP prefix"),
        ))
    }
    /// Returns the encoded hardware address length.
    #[inline]
    pub fn hardware_address_length(&self) -> u8 {
        self.hardware_length as u8
    }
    /// Returns the encoded protocol address length.
    #[inline]
    pub fn protocol_address_length(&self) -> u8 {
        self.protocol_length as u8
    }
    /// Returns the encoded hardware address length.
    #[inline]
    pub fn hlen(&self) -> u8 {
        self.hardware_address_length()
    }
    /// Returns the encoded protocol address length.
    #[inline]
    pub fn plen(&self) -> u8 {
        self.protocol_address_length()
    }
    /// Returns the RFC 826 operation, preserving unknown values.
    #[inline]
    pub fn operation(&self) -> ArpOperation {
        ArpOperation::new(u16::from_be_bytes(
            self.bytes[6..8].try_into().expect("validated ARP prefix"),
        ))
    }
    /// Returns the sender hardware address bytes.
    #[inline]
    pub fn sender_hardware_address(&self) -> &'a [u8] {
        &self.bytes[PREFIX_LENGTH..PREFIX_LENGTH + self.hardware_length]
    }
    /// Returns the sender protocol address bytes.
    #[inline]
    pub fn sender_protocol_address(&self) -> &'a [u8] {
        let start = PREFIX_LENGTH + self.hardware_length;
        &self.bytes[start..start + self.protocol_length]
    }
    /// Returns the target hardware address bytes.
    #[inline]
    pub fn target_hardware_address(&self) -> &'a [u8] {
        let start = PREFIX_LENGTH + self.hardware_length + self.protocol_length;
        &self.bytes[start..start + self.hardware_length]
    }
    /// Returns the target protocol address bytes.
    #[inline]
    pub fn target_protocol_address(&self) -> &'a [u8] {
        let start = PREFIX_LENGTH + 2 * self.hardware_length + self.protocol_length;
        &self.bytes[start..]
    }
    /// Returns all RFC 826 bytes represented by this view.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

/// A structurally validated mutable ARP packet view.
#[derive(Debug, Eq, PartialEq)]
pub struct ArpPacketMut<'a> {
    bytes: &'a mut [u8],
    hardware_length: usize,
    protocol_length: usize,
}

impl<'a> ArpPacketMut<'a> {
    /// Validates the generic RFC 826 layout and excludes supplied trailing bytes.
    #[inline]
    pub fn parse(bytes: &'a mut [u8]) -> Result<Self, ParseError> {
        let (hardware_length, protocol_length, length) = validate(bytes)?;
        Ok(Self::from_validated(
            &mut bytes[..length],
            hardware_length,
            protocol_length,
        ))
    }
    pub(super) fn from_validated(
        bytes: &'a mut [u8],
        hardware_length: usize,
        protocol_length: usize,
    ) -> Self {
        Self {
            bytes,
            hardware_length,
            protocol_length,
        }
    }
    /// Returns the RFC 826 hardware type, preserving unknown values.
    #[inline]
    pub fn hardware_type(&self) -> ArpHardwareType {
        ArpHardwareType::new(u16::from_be_bytes(
            self.bytes[0..2].try_into().expect("validated ARP prefix"),
        ))
    }
    /// Returns the RFC 826 protocol type, preserving unknown values.
    #[inline]
    pub fn protocol_type(&self) -> ArpProtocolType {
        ArpProtocolType::new(u16::from_be_bytes(
            self.bytes[2..4].try_into().expect("validated ARP prefix"),
        ))
    }
    /// Returns the encoded hardware address length, which this view cannot change.
    #[inline]
    pub fn hardware_address_length(&self) -> u8 {
        self.hardware_length as u8
    }
    /// Returns the encoded protocol address length, which this view cannot change.
    #[inline]
    pub fn protocol_address_length(&self) -> u8 {
        self.protocol_length as u8
    }
    /// Returns the encoded hardware address length.
    #[inline]
    pub fn hlen(&self) -> u8 {
        self.hardware_address_length()
    }
    /// Returns the encoded protocol address length.
    #[inline]
    pub fn plen(&self) -> u8 {
        self.protocol_address_length()
    }
    /// Returns the RFC 826 operation, preserving unknown values.
    #[inline]
    pub fn operation(&self) -> ArpOperation {
        ArpOperation::new(u16::from_be_bytes(
            self.bytes[6..8].try_into().expect("validated ARP prefix"),
        ))
    }
    /// Replaces the RFC 826 hardware type without changing address lengths.
    #[inline]
    pub fn set_hardware_type(&mut self, value: ArpHardwareType) {
        self.bytes[0..2].copy_from_slice(&value.raw().to_be_bytes());
    }
    /// Replaces the RFC 826 protocol type without changing address lengths.
    #[inline]
    pub fn set_protocol_type(&mut self, value: ArpProtocolType) {
        self.bytes[2..4].copy_from_slice(&value.raw().to_be_bytes());
    }
    /// Replaces the RFC 826 operation.
    #[inline]
    pub fn set_operation(&mut self, value: ArpOperation) {
        self.bytes[6..8].copy_from_slice(&value.raw().to_be_bytes());
    }
    /// Returns the sender hardware address bytes.
    #[inline]
    pub fn sender_hardware_address(&self) -> &[u8] {
        &self.bytes[PREFIX_LENGTH..PREFIX_LENGTH + self.hardware_length]
    }
    /// Returns mutable sender hardware address bytes.
    #[inline]
    pub fn sender_hardware_address_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[PREFIX_LENGTH..PREFIX_LENGTH + self.hardware_length]
    }
    /// Returns the sender protocol address bytes.
    #[inline]
    pub fn sender_protocol_address(&self) -> &[u8] {
        let start = PREFIX_LENGTH + self.hardware_length;
        &self.bytes[start..start + self.protocol_length]
    }
    /// Returns mutable sender protocol address bytes.
    #[inline]
    pub fn sender_protocol_address_mut(&mut self) -> &mut [u8] {
        let start = PREFIX_LENGTH + self.hardware_length;
        &mut self.bytes[start..start + self.protocol_length]
    }
    /// Returns the target hardware address bytes.
    #[inline]
    pub fn target_hardware_address(&self) -> &[u8] {
        let start = PREFIX_LENGTH + self.hardware_length + self.protocol_length;
        &self.bytes[start..start + self.hardware_length]
    }
    /// Returns mutable target hardware address bytes.
    #[inline]
    pub fn target_hardware_address_mut(&mut self) -> &mut [u8] {
        let start = PREFIX_LENGTH + self.hardware_length + self.protocol_length;
        &mut self.bytes[start..start + self.hardware_length]
    }
    /// Returns the target protocol address bytes.
    #[inline]
    pub fn target_protocol_address(&self) -> &[u8] {
        let start = PREFIX_LENGTH + 2 * self.hardware_length + self.protocol_length;
        &self.bytes[start..]
    }
    /// Returns mutable target protocol address bytes.
    #[inline]
    pub fn target_protocol_address_mut(&mut self) -> &mut [u8] {
        let start = PREFIX_LENGTH + 2 * self.hardware_length + self.protocol_length;
        &mut self.bytes[start..]
    }
    /// Returns all RFC 826 bytes represented by this view.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
    }
    /// Returns all represented ARP bytes mutably.
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        self.bytes
    }
}

#[inline]
fn validate(bytes: &[u8]) -> Result<(usize, usize, usize), ParseError> {
    if bytes.len() < PREFIX_LENGTH {
        return Err(ParseError::Truncated {
            minimum: PREFIX_LENGTH,
            available: bytes.len(),
        });
    }
    let hardware_length = bytes[4] as usize;
    let protocol_length = bytes[5] as usize;
    let length = PREFIX_LENGTH + 2 * hardware_length + 2 * protocol_length;
    if bytes.len() < length {
        return Err(ParseError::Truncated {
            minimum: length,
            available: bytes.len(),
        });
    }
    Ok((hardware_length, protocol_length, length))
}

#[cfg(feature = "ethernet")]
impl<'a> EthernetFrame<'a> {
    /// Parses an ARP payload only when this frame's EtherType is ARP.
    #[inline]
    pub fn arp(&self) -> Result<Option<ArpPacket<'a>>, ParseError> {
        if self.ether_type() != EtherType::ARP {
            return Ok(None);
        }
        ArpPacket::parse(self.payload()).map(Some)
    }
}
#[cfg(feature = "ethernet")]
impl<'a> EthernetFrameMut<'a> {
    /// Parses a mutable ARP payload only when this frame's EtherType is ARP.
    #[inline]
    pub fn arp_mut(&mut self) -> Result<Option<ArpPacketMut<'_>>, ParseError> {
        if self.ether_type() != EtherType::ARP {
            return Ok(None);
        }
        ArpPacketMut::parse(self.payload_mut()).map(Some)
    }
}
#[cfg(feature = "ethernet")]
impl<'a> ArpPacket<'a> {
    /// Returns the sender MAC address only for Ethernet hardware with a six-octet address.
    #[inline]
    pub fn sender_mac_address(&self) -> Option<MacAddress> {
        if self.hardware_type() != ArpHardwareType::ETHERNET
            || self.sender_hardware_address().len() != 6
        {
            return None;
        }
        Some(MacAddress::new(
            self.sender_hardware_address()
                .try_into()
                .expect("checked address length"),
        ))
    }
    /// Returns the target MAC address only for Ethernet hardware with a six-octet address.
    #[inline]
    pub fn target_mac_address(&self) -> Option<MacAddress> {
        if self.hardware_type() != ArpHardwareType::ETHERNET
            || self.target_hardware_address().len() != 6
        {
            return None;
        }
        Some(MacAddress::new(
            self.target_hardware_address()
                .try_into()
                .expect("checked address length"),
        ))
    }
}
