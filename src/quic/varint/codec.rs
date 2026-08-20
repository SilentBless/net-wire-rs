//! Physical RFC 9000 variable-integer prefix codec.

use core::num::NonZeroUsize;

use wire_repr::{EncodePlan, PrefixCodec, PrefixExtent};

use super::{MAX_VALUE, QuicVarIntBuildError, QuicVarIntLen, QuicVarIntParseError};

/// Private scalar value shared by decoded and requested encodings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct QuicVarIntCodecValue {
    value: u64,
    length: QuicVarIntLen,
    requested_length: bool,
}

impl QuicVarIntCodecValue {
    /// Requests canonical encoding unless an explicit width is supplied.
    pub(crate) const fn encoding(value: u64, requested: Option<QuicVarIntLen>) -> Self {
        Self {
            value,
            length: match requested {
                Some(length) => length,
                None => canonical_len(value),
            },
            requested_length: requested.is_some(),
        }
    }

    pub(super) const fn value(self) -> u64 {
        self.value
    }

    pub(super) const fn length(self) -> QuicVarIntLen {
        self.length
    }
}

/// Infallible prepared RFC 9000 variable-integer encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct QuicVarIntEncodePlan {
    encoded: u64,
    length: QuicVarIntLen,
}

impl QuicVarIntEncodePlan {
    pub(super) const fn length(self) -> QuicVarIntLen {
        self.length
    }
}

impl EncodePlan for QuicVarIntEncodePlan {
    #[inline]
    fn encoded_len(&self) -> usize {
        self.length.byte_len()
    }

    #[inline]
    fn write_into(&self, output: &mut [u8]) {
        let encoded_len = self.length.byte_len();
        if output.len() != encoded_len {
            return;
        }
        let bytes = self.encoded.to_be_bytes();
        output.copy_from_slice(&bytes[bytes.len() - encoded_len..]);
    }
}

/// RFC 9000 variable-integer physical representation owner.
pub(crate) struct QuicVarIntCodec;

impl PrefixCodec for QuicVarIntCodec {
    type Value<'wire>
        = QuicVarIntCodecValue
    where
        Self: 'wire;
    type DecodeError = QuicVarIntParseError;
    type EncodeError = QuicVarIntBuildError;
    type Plan<'value>
        = QuicVarIntEncodePlan
    where
        Self: 'value;

    #[inline]
    fn validate_prefix(bytes: &[u8]) -> Result<PrefixExtent, Self::DecodeError> {
        let first = *bytes.first().ok_or(QuicVarIntParseError::Incomplete {
            required: 1,
            available: 0,
        })?;
        let length = length_from_first_byte(first);
        let required = length.byte_len();
        if bytes.len() < required {
            return Err(QuicVarIntParseError::Incomplete {
                required,
                available: bytes.len(),
            });
        }
        let encoded_len =
            NonZeroUsize::new(required).expect("QUIC variable-integer width is nonzero");
        Ok(PrefixExtent::new(encoded_len))
    }

    #[inline]
    fn decode<'wire>(bytes: &'wire [u8]) -> Self::Value<'wire> {
        let Some((&first, tail)) = bytes.split_first() else {
            return QuicVarIntCodecValue {
                value: 0,
                length: QuicVarIntLen::One,
                requested_length: false,
            };
        };
        let length = length_from_first_byte(first);
        let mut value = u64::from(first & 0x3f);
        for &byte in tail {
            value = (value << 8) | u64::from(byte);
        }
        QuicVarIntCodecValue {
            value,
            length,
            requested_length: false,
        }
    }

    #[inline]
    fn plan<'value>(value: Self::Value<'value>) -> Result<Self::Plan<'value>, Self::EncodeError> {
        let length = if value.requested_length {
            value.length
        } else {
            canonical_len(value.value)
        };
        let value = value.value;
        if value > MAX_VALUE {
            return Err(QuicVarIntBuildError::ValueTooLarge { value });
        }
        if value > length.max_value() {
            return Err(QuicVarIntBuildError::WidthTooSmall { length, value });
        }

        Ok(QuicVarIntEncodePlan {
            encoded: value | prefix_value(length),
            length,
        })
    }
}

pub(super) const fn canonical_len(value: u64) -> QuicVarIntLen {
    if value <= QuicVarIntLen::One.max_value() {
        QuicVarIntLen::One
    } else if value <= QuicVarIntLen::Two.max_value() {
        QuicVarIntLen::Two
    } else if value <= QuicVarIntLen::Four.max_value() {
        QuicVarIntLen::Four
    } else {
        QuicVarIntLen::Eight
    }
}

const fn length_from_first_byte(first: u8) -> QuicVarIntLen {
    match first >> 6 {
        0 => QuicVarIntLen::One,
        1 => QuicVarIntLen::Two,
        2 => QuicVarIntLen::Four,
        _ => QuicVarIntLen::Eight,
    }
}

const fn prefix_value(length: QuicVarIntLen) -> u64 {
    match length {
        QuicVarIntLen::One => 0,
        QuicVarIntLen::Two => 1 << 14,
        QuicVarIntLen::Four => 2 << 30,
        QuicVarIntLen::Eight => 3 << 62,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_reports_each_prefix_extent_and_truncation() {
        assert_eq!(
            QuicVarIntCodec::validate_prefix(&[]),
            Err(QuicVarIntParseError::Incomplete {
                required: 1,
                available: 0,
            })
        );
        for (first, required) in [(0x00, 1), (0x40, 2), (0x80, 4), (0xc0, 8)] {
            let bytes = [first; 8];
            let extent = QuicVarIntCodec::validate_prefix(&bytes).unwrap();
            assert_eq!(extent.encoded_len().get(), required);
            for available in 1..required {
                assert_eq!(
                    QuicVarIntCodec::validate_prefix(&bytes[..available]),
                    Err(QuicVarIntParseError::Incomplete {
                        required,
                        available,
                    })
                );
            }
        }
    }

    #[test]
    fn decode_preserves_the_exact_noncanonical_span() {
        let bytes = [0x40, 0x25, 0xee];
        let extent = QuicVarIntCodec::validate_prefix(&bytes).unwrap();
        let (exact, suffix) = extent.split_input(&bytes).unwrap();
        assert_eq!(suffix, &[0xee]);
        assert_eq!(
            QuicVarIntCodec::decode(exact),
            QuicVarIntCodecValue {
                value: 37,
                length: QuicVarIntLen::Two,
                requested_length: false,
            }
        );
    }

    #[test]
    fn plans_exact_bytes_that_validate_and_decode_to_the_request() {
        for (value, requested, expected) in [
            (37, None, &[0x25][..]),
            (37, Some(QuicVarIntLen::Two), &[0x40, 0x25][..]),
            (16_384, None, &[0x80, 0x00, 0x40, 0x00][..]),
            (
                MAX_VALUE,
                None,
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff][..],
            ),
        ] {
            let plan =
                QuicVarIntCodec::plan(QuicVarIntCodecValue::encoding(value, requested)).unwrap();
            let mut encoded = [0; 8];
            let output = &mut encoded[..plan.encoded_len()];
            plan.write_into(output);
            assert_eq!(output, expected);

            let extent = QuicVarIntCodec::validate_prefix(output).unwrap();
            assert_eq!(extent.encoded_len().get(), plan.encoded_len());
            assert_eq!(
                QuicVarIntCodec::decode(output),
                QuicVarIntCodecValue {
                    value,
                    length: plan.length(),
                    requested_length: false,
                }
            );
        }
    }

    #[test]
    fn planning_a_decoded_noncanonical_value_uses_the_canonical_width() {
        let decoded = QuicVarIntCodec::decode(&[0x40, 0x25]);
        let plan = QuicVarIntCodec::plan(decoded).unwrap();
        let mut output = [0; 1];
        plan.write_into(&mut output);
        assert_eq!(output, [0x25]);
    }
}
