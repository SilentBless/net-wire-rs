#[path = "arp/builder.rs"]
mod builder;
#[cfg(feature = "ethernet")]
#[path = "arp/integrations/ethernet.rs"]
mod ethernet;
#[path = "arp/fixtures.rs"]
mod fixtures;
#[cfg(feature = "ipv4")]
#[path = "arp/integrations/ipv4.rs"]
mod ipv4;
#[path = "arp/packet.rs"]
mod packet;
