use crate::error::ParseError;
use crate::ethernet::{
    address::MacAddress,
    ether_type::EtherType,
    frame::{EthernetFrame, EthernetFrameMut},
};

use super::packet::{ArpPacket, ArpPacketMut};
use super::types::ArpHardwareType;

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
