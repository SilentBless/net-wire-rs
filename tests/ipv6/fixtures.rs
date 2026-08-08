pub(super) const WIRE: [u8; 44] = [
    0x6a, 0xbc, 0xde, 0xef, 0, 3, 0xfd, 64, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 2, 3, 0xee,
];

#[cfg(any(feature = "icmpv6", feature = "udp", feature = "tcp"))]
pub(super) fn packet(next_header: net_wire::ipv6::Ipv6NextHeader, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 40 + payload.len()];
    bytes[0] = 0x60;
    bytes[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    bytes[6] = next_header.raw();
    bytes[7] = 64;
    bytes[8..24].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    bytes[24..40].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    bytes[40..].copy_from_slice(payload);
    bytes
}
