use crate::ethernet::{
    layout::{EthernetFrame, EthernetFrameViewMut},
    types::{EtherType, MacAddress},
};

use super::{ArpHardwareType, ArpPacket, ArpPacketError, ArpPacketViewMut};

impl<'a> EthernetFrame<'a> {
    /// Parses an ARP payload only when this frame's EtherType is ARP.
    #[inline]
    pub fn arp(&self) -> Result<Option<ArpPacket<'a>>, ArpPacketError> {
        if self.ether_type() != EtherType::ARP {
            return Ok(None);
        }
        ArpPacket::view(self.payload())
            .with_remainder()
            .map(|(packet, _)| Some(packet))
    }
}

impl<'a> EthernetFrameViewMut<'a> {
    /// Parses a mutable ARP payload only when this frame's EtherType is ARP.
    #[inline]
    pub fn arp_mut(&mut self) -> Result<Option<ArpPacketViewMut<'_>>, ArpPacketError> {
        if self.ether_type() != EtherType::ARP {
            return Ok(None);
        }
        ArpPacketViewMut::parse_prefix_mut(self.payload_mut()).map(|(packet, _)| Some(packet))
    }
}

impl ArpPacket<'_> {
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
