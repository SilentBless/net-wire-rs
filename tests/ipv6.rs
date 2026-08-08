#[path = "ipv6/builder.rs"]
mod builder;
#[cfg(feature = "ethernet")]
#[path = "ipv6/integrations/ethernet.rs"]
mod ethernet;
#[cfg(all(feature = "icmpv6", feature = "udp", feature = "tcp"))]
#[path = "ipv6/integrations/extensions.rs"]
mod extensions;
#[path = "ipv6/fixtures.rs"]
mod fixtures;
#[cfg(feature = "icmpv6")]
#[path = "ipv6/integrations/icmpv6.rs"]
mod icmpv6;
#[path = "ipv6/next_header.rs"]
mod next_header;
#[path = "ipv6/packet.rs"]
mod packet;
#[cfg(feature = "tcp")]
#[path = "ipv6/integrations/tcp.rs"]
mod tcp;
#[cfg(feature = "udp")]
#[path = "ipv6/integrations/udp.rs"]
mod udp;
