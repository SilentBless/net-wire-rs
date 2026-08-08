#[path = "icmpv6/message.rs"]
mod message;

#[cfg(feature = "ipv6")]
#[path = "icmpv6/integrations/ipv6.rs"]
mod ipv6;
