//! ARP type-field wrappers from RFC 826 and IANA registries.

/// An ARP hardware type from the IANA ARP Parameters registry.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ArpHardwareType(u16);

impl ArpHardwareType {
    /// Ethernet hardware type (`1`) defined by RFC 826.
    pub const ETHERNET: Self = Self(1);

    /// Preserves an encoded hardware-type value, including unassigned values.
    #[inline]
    pub const fn new(raw: u16) -> Self {
        Self(raw)
    }

    /// Returns the host-order value encoded in the hardware-type field.
    #[inline]
    pub const fn raw(self) -> u16 {
        self.0
    }
}

/// An ARP protocol type, conventionally an EtherType, from RFC 826.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ArpProtocolType(u16);

impl ArpProtocolType {
    /// Internet Protocol version 4 protocol type (`0x0800`).
    pub const IPV4: Self = Self(0x0800);

    /// Preserves an encoded protocol-type value, including unassigned values.
    #[inline]
    pub const fn new(raw: u16) -> Self {
        Self(raw)
    }

    /// Returns the host-order value encoded in the protocol-type field.
    #[inline]
    pub const fn raw(self) -> u16 {
        self.0
    }
}

/// An ARP operation value from RFC 826.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ArpOperation(u16);

impl ArpOperation {
    /// ARP request operation (`1`).
    pub const REQUEST: Self = Self(1);
    /// ARP reply operation (`2`).
    pub const REPLY: Self = Self(2);

    /// Preserves an encoded operation value, including unassigned values.
    #[inline]
    pub const fn new(raw: u16) -> Self {
        Self(raw)
    }

    /// Returns the host-order value encoded in the operation field.
    #[inline]
    pub const fn raw(self) -> u16 {
        self.0
    }
}
