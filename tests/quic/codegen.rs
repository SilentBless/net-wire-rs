//! Release-codegen probes for the public QUIC variable-integer API.
//!
//! The Python gate compares these probes with the handwritten equivalents below.

use core::hint::black_box;

use net_wire::quic::{
    QuicVarInt, QuicVarIntBuildError, QuicVarIntBuilder, QuicVarIntLen, QuicVarIntParseError,
};

type ParseResult = Result<(u64, usize, bool), (usize, usize)>;
type BuildResult = Result<(u64, usize), (u64, usize, usize)>;

#[inline(never)]
pub fn quic_varint_public_parse(bytes: &[u8]) -> ParseResult {
    match QuicVarInt::parse(bytes) {
        Ok(value) => Ok((value.value(), value.byte_len(), value.is_canonical())),
        Err(QuicVarIntParseError::Incomplete {
            required,
            available,
        }) => Err((required, available)),
    }
}

#[inline(never)]
pub fn quic_varint_handwritten_parse(bytes: &[u8]) -> ParseResult {
    let Some(&first) = bytes.first() else {
        return Err((1, 0));
    };
    let length = match first >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    if bytes.len() < length {
        return Err((length, bytes.len()));
    }

    let exact = bytes.get(..length).ok_or((length, bytes.len()))?;
    let mut value = u64::from(first & 0x3f);
    for &byte in &exact[1..] {
        value = (value << 8) | u64::from(byte);
    }
    let canonical_length = if value <= 63 {
        1
    } else if value <= 16_383 {
        2
    } else if value <= 1_073_741_823 {
        4
    } else {
        8
    };
    Ok((value, length, length == canonical_length))
}

#[inline(never)]
pub fn quic_varint_public_canonical_build(output: &mut [u8], value: u64) -> BuildResult {
    match QuicVarIntBuilder::new(output, value).build() {
        Ok(built) => Ok((built.value(), built.byte_len())),
        Err(QuicVarIntBuildError::ValueTooLarge { value }) => Err((value, 0, 0)),
        Err(QuicVarIntBuildError::WidthTooSmall { length, value }) => {
            Err((value, length.byte_len(), 0))
        }
        Err(QuicVarIntBuildError::BufferTooShort {
            required,
            available,
        }) => Err((0, required, available)),
    }
}

#[inline(never)]
pub fn quic_varint_handwritten_canonical_build(output: &mut [u8], value: u64) -> BuildResult {
    if value > (1 << 62) - 1 {
        return Err((value, 0, 0));
    }
    let length = if value <= 63 {
        1
    } else if value <= 16_383 {
        2
    } else if value <= 1_073_741_823 {
        4
    } else {
        8
    };
    if output.len() < length {
        return Err((0, length, output.len()));
    }

    let value_bytes = value.to_be_bytes();
    output[..length].copy_from_slice(&value_bytes[8 - length..]);
    output[0] |= match length {
        1 => 0,
        2 => 0x40,
        4 => 0x80,
        _ => 0xc0,
    };
    Ok((value, length))
}

#[inline(never)]
pub fn quic_varint_public_two_build(output: &mut [u8], value: u64) -> BuildResult {
    match QuicVarIntBuilder::new(output, value)
        .with_len(QuicVarIntLen::Two)
        .build()
    {
        Ok(built) => Ok((built.value(), built.byte_len())),
        Err(QuicVarIntBuildError::ValueTooLarge { value }) => Err((value, 0, 0)),
        Err(QuicVarIntBuildError::WidthTooSmall { length, value }) => {
            Err((value, length.byte_len(), 0))
        }
        Err(QuicVarIntBuildError::BufferTooShort {
            required,
            available,
        }) => Err((0, required, available)),
    }
}

#[inline(never)]
pub fn quic_varint_handwritten_two_build(output: &mut [u8], value: u64) -> BuildResult {
    if value > (1 << 62) - 1 {
        return Err((value, 0, 0));
    }
    if value > 16_383 {
        return Err((value, 2, 0));
    }
    if output.len() < 2 {
        return Err((0, 2, output.len()));
    }

    let value_bytes = value.to_be_bytes();
    output[..2].copy_from_slice(&value_bytes[6..]);
    output[0] |= 0x40;
    Ok((value, 2))
}

#[test]
fn retains_release_codegen_probes() {
    let input = black_box([0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c, 0xee]);
    let _ = black_box(quic_varint_public_parse(black_box(&input)));
    let _ = black_box(quic_varint_handwritten_parse(black_box(&input)));

    let mut canonical_public = black_box([0xa5; 8]);
    let _ = black_box(quic_varint_public_canonical_build(
        black_box(&mut canonical_public),
        black_box(16_384),
    ));
    black_box(canonical_public);
    let mut canonical_handwritten = black_box([0xa5; 8]);
    let _ = black_box(quic_varint_handwritten_canonical_build(
        black_box(&mut canonical_handwritten),
        black_box(16_384),
    ));
    black_box(canonical_handwritten);

    let mut two_public = black_box([0xa5; 2]);
    let _ = black_box(quic_varint_public_two_build(
        black_box(&mut two_public),
        black_box(37),
    ));
    black_box(two_public);
    let mut two_handwritten = black_box([0xa5; 2]);
    let _ = black_box(quic_varint_handwritten_two_build(
        black_box(&mut two_handwritten),
        black_box(37),
    ));
    black_box(two_handwritten);
}
