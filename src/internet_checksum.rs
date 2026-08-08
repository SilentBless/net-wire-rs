//! Internal one's-complement checksum primitives.

/// Adds wire-order octets to a running one's-complement accumulator.
#[inline]
pub(crate) fn add_bytes(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut index = 0;
    while index < bytes.len() {
        let low = bytes.get(index + 1).copied().unwrap_or(0);
        sum += u32::from((u16::from(bytes[index]) << 8) | u16::from(low));
        sum = u32::from(fold(sum));
        index += 2;
    }
    sum
}

/// Folds an accumulator to a sixteen-bit one's-complement sum.
#[inline]
pub(crate) fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// Returns the one's-complement sum of wire-order bytes.
#[cfg(any(feature = "ipv4", feature = "icmpv4"))]
#[inline]
pub(crate) fn sum(bytes: &[u8]) -> u16 {
    fold(add_bytes(0, bytes))
}

/// Returns the checksum to encode for the supplied accumulator.
#[cfg(any(
    feature = "icmpv4",
    all(feature = "ipv4", any(feature = "udp", feature = "tcp")),
    all(
        feature = "ipv6",
        any(feature = "icmpv6", feature = "udp", feature = "tcp")
    )
))]
#[inline]
pub(crate) fn checksum(sum: u32) -> u16 {
    !fold(sum)
}

/// Adds an IPv4 pseudoheader to an accumulator.
#[cfg(all(feature = "ipv4", any(feature = "udp", feature = "tcp")))]
#[inline]
pub(crate) fn add_ipv4_pseudoheader(
    sum: u32,
    source: [u8; 4],
    destination: [u8; 4],
    protocol: u8,
    length: u16,
) -> u32 {
    let sum = add_bytes(sum, &source);
    let sum = add_bytes(sum, &destination);
    let sum = add_bytes(sum, &[0, protocol]);
    add_bytes(sum, &length.to_be_bytes())
}

/// Adds an IPv6 pseudoheader to an accumulator.
#[cfg(all(
    feature = "ipv6",
    any(feature = "icmpv6", feature = "udp", feature = "tcp")
))]
#[inline]
pub(crate) fn add_ipv6_pseudoheader(
    sum: u32,
    source: [u8; 16],
    destination: [u8; 16],
    next_header: u8,
    length: u32,
) -> u32 {
    let sum = add_bytes(sum, &source);
    let sum = add_bytes(sum, &destination);
    let sum = add_bytes(sum, &length.to_be_bytes());
    add_bytes(sum, &[0, 0, 0, next_header])
}
