#[path = "ipv6/builder.rs"]
mod builder;
#[cfg(all(feature = "icmpv6", feature = "udp", feature = "tcp"))]
#[path = "ipv6/integrations/dispatch.rs"]
mod dispatch;
#[cfg(feature = "ethernet")]
#[path = "ipv6/integrations/ethernet.rs"]
mod ethernet;
#[path = "ipv6/fixtures.rs"]
mod fixtures;
#[path = "ipv6/next_header.rs"]
mod next_header;
#[path = "ipv6/packet.rs"]
mod packet;
