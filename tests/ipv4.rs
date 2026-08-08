#[path = "ipv4/builder.rs"]
mod builder;
#[cfg(feature = "ethernet")]
#[path = "ipv4/integrations/ethernet.rs"]
mod ethernet;
#[path = "ipv4/fixtures.rs"]
mod fixtures;
#[cfg(feature = "icmpv4")]
#[path = "ipv4/integrations/icmpv4.rs"]
mod icmpv4;
#[path = "ipv4/packet.rs"]
mod packet;
#[cfg(feature = "tcp")]
#[path = "ipv4/integrations/tcp.rs"]
mod tcp;
#[cfg(feature = "udp")]
#[path = "ipv4/integrations/udp.rs"]
mod udp;
