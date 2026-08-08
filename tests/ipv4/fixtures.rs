pub(super) const BASIC: [u8; 21] = [
    0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0xf6, 0xe0, 192, 0, 2, 1, 192, 0, 2, 2, 0xee,
];
pub(super) const OPTIONS: [u8; 29] = [
    0x46, 0xab, 0, 28, 0x12, 0x34, 0x20, 5, 60, 0xfd, 0x59, 0xc4, 192, 0, 2, 1, 198, 51, 100, 2, 1,
    2, 3, 4, 9, 8, 7, 6, 0xee,
];

#[cfg(any(feature = "icmpv4", feature = "udp", feature = "tcp"))]
pub(super) fn packet(protocol: u8, fragment: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![
        0x45,
        0,
        0,
        (20 + payload.len()) as u8,
        0,
        0,
        (fragment >> 8) as u8,
        fragment as u8,
        64,
        protocol,
        0,
        0,
        192,
        0,
        2,
        1,
        192,
        0,
        2,
        2,
    ];
    bytes.extend_from_slice(payload);
    bytes
}
