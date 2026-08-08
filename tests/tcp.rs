#[path = "tcp/segment.rs"]
mod segment;

#[cfg(any(feature = "ipv4", feature = "ipv6"))]
#[path = "tcp/fixtures.rs"]
mod fixtures;

#[cfg(feature = "ipv4")]
#[path = "tcp/integrations/ipv4.rs"]
mod ipv4;

#[cfg(feature = "ipv6")]
#[path = "tcp/integrations/ipv6.rs"]
mod ipv6;
