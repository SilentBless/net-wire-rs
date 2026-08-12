use crate::ethernet::{
    address::MacAddress,
    ether_type::EtherType,
    frame::{EthernetFrame, EthernetFrameMut},
};

use super::{ArpHardwareType, ArpPacketError, ArpPacketView, ArpPacketViewMut};

impl<'a> EthernetFrame<'a> {
    /// Parses an ARP payload only when this frame's EtherType is ARP.
    #[inline]
    pub fn arp(&self) -> Result<Option<ArpPacketView<'a>>, ArpPacketError> {
        if self.ether_type() != EtherType::ARP {
            return Ok(None);
        }
        ArpPacketView::parse_prefix(self.payload()).map(|(packet, _)| Some(packet))
    }
}

impl<'a> EthernetFrameMut<'a> {
    /// Parses a mutable ARP payload only when this frame's EtherType is ARP.
    #[inline]
    pub fn arp_mut(&mut self) -> Result<Option<ArpPacketViewMut<'_>>, ArpPacketError> {
        if self.ether_type() != EtherType::ARP {
            return Ok(None);
        }
        ArpPacketViewMut::parse_prefix_mut(self.payload_mut()).map(|(packet, _)| Some(packet))
    }
}

impl ArpPacketView<'_> {
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
