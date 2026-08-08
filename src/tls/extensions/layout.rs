use crate::tls::error::TlsParseError;

pub(super) fn len(r: usize, a: usize) -> TlsParseError {
    if a < r {
        TlsParseError::Incomplete {
            required: r,
            available: a,
        }
    } else {
        TlsParseError::TrailingBytes
    }
}

pub(super) fn empty(b: &[u8]) -> Result<(), TlsParseError> {
    if b.is_empty() {
        Ok(())
    } else {
        Err(TlsParseError::TrailingBytes)
    }
}

pub(super) fn v16(b: &[u8], min: usize, even: bool) -> Result<&[u8], TlsParseError> {
    if b.len() < 2 {
        return Err(TlsParseError::Incomplete {
            required: 2,
            available: b.len(),
        });
    }
    let n = usize::from(u16::from_be_bytes([b[0], b[1]]));
    if n < min || (even && !n.is_multiple_of(2)) {
        return Err(TlsParseError::InvalidValue);
    }
    if b.len() != n + 2 {
        return Err(len(n + 2, b.len()));
    }
    Ok(&b[2..])
}

pub(super) fn v8(b: &[u8], min: usize) -> Result<&[u8], TlsParseError> {
    if b.is_empty() {
        return Err(TlsParseError::Incomplete {
            required: 1,
            available: 0,
        });
    }
    let n = usize::from(b[0]);
    if n < min {
        return Err(TlsParseError::InvalidValue);
    }
    if b.len() != n + 1 {
        return Err(len(n + 1, b.len()));
    }
    Ok(&b[1..])
}

pub(super) fn take_v16(b: &[u8], minimum: usize) -> Result<(&[u8], &[u8]), TlsParseError> {
    if b.len() < 2 {
        return Err(TlsParseError::Incomplete {
            required: 2,
            available: b.len(),
        });
    }
    let length = usize::from(u16::from_be_bytes([b[0], b[1]]));
    if length < minimum {
        return Err(TlsParseError::InvalidValue);
    }
    let total = 2usize
        .checked_add(length)
        .ok_or(TlsParseError::InvalidValue)?;
    if b.len() < total {
        return Err(TlsParseError::Incomplete {
            required: total,
            available: b.len(),
        });
    }
    Ok((&b[2..total], &b[total..]))
}
