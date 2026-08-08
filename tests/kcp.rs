#[path = "kcp/builder.rs"]
mod builder;
#[path = "kcp/fixtures.rs"]
mod fixtures;
#[path = "kcp/segment.rs"]
mod segment;
#[path = "kcp/segments.rs"]
mod segments;
#[path = "kcp/types.rs"]
mod types;

#[cfg(feature = "udp")]
#[path = "kcp/integrations/udp.rs"]
mod udp;
