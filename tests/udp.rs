#[path = "udp/datagram.rs"]
mod datagram;

#[cfg(any(feature = "ipv4", feature = "ipv6"))]
#[path = "udp/fixtures.rs"]
mod fixtures;

#[cfg(feature = "ipv4")]
#[path = "udp/integrations/ipv4.rs"]
mod ipv4;

#[cfg(feature = "ipv6")]
#[path = "udp/integrations/ipv6.rs"]
mod ipv6;
