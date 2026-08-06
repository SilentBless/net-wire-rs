//! RFC 9204 Appendix A static header table.

/// A borrowed QPACK header field with byte-oriented name and value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackHeaderFieldRef<'a> {
    name: &'a [u8],
    value: &'a [u8],
}

impl<'a> QpackHeaderFieldRef<'a> {
    /// Creates a borrowed header field from opaque name and value bytes.
    pub const fn new(name: &'a [u8], value: &'a [u8]) -> Self {
        Self { name, value }
    }

    /// Returns the opaque header name bytes.
    pub const fn name(self) -> &'a [u8] {
        self.name
    }

    /// Returns the opaque header value bytes.
    pub const fn value(self) -> &'a [u8] {
        self.value
    }
}

/// Number of entries in the RFC 9204 Appendix A static table.
pub const QPACK_STATIC_TABLE_LEN: usize = 99;

/// RFC 9204 Appendix A's immutable, zero-based static header table.
pub struct QpackStaticTable;

impl QpackStaticTable {
    /// Returns the number of entries in the static table.
    pub const fn len() -> usize {
        QPACK_STATIC_TABLE_LEN
    }

    /// Returns whether the static table has no entries.
    pub const fn is_empty() -> bool {
        false
    }

    /// Returns the field at a zero-based RFC 9204 Appendix A index.
    pub fn get(index: usize) -> Option<QpackHeaderFieldRef<'static>> {
        STATIC_TABLE.get(index).copied()
    }
}

const STATIC_TABLE: [QpackHeaderFieldRef<'static>; QPACK_STATIC_TABLE_LEN] = [
    QpackHeaderFieldRef::new(b":authority", b""),
    QpackHeaderFieldRef::new(b":path", b"/"),
    QpackHeaderFieldRef::new(b"age", b"0"),
    QpackHeaderFieldRef::new(b"content-disposition", b""),
    QpackHeaderFieldRef::new(b"content-length", b"0"),
    QpackHeaderFieldRef::new(b"cookie", b""),
    QpackHeaderFieldRef::new(b"date", b""),
    QpackHeaderFieldRef::new(b"etag", b""),
    QpackHeaderFieldRef::new(b"if-modified-since", b""),
    QpackHeaderFieldRef::new(b"if-none-match", b""),
    QpackHeaderFieldRef::new(b"last-modified", b""),
    QpackHeaderFieldRef::new(b"link", b""),
    QpackHeaderFieldRef::new(b"location", b""),
    QpackHeaderFieldRef::new(b"referer", b""),
    QpackHeaderFieldRef::new(b"set-cookie", b""),
    QpackHeaderFieldRef::new(b":method", b"CONNECT"),
    QpackHeaderFieldRef::new(b":method", b"DELETE"),
    QpackHeaderFieldRef::new(b":method", b"GET"),
    QpackHeaderFieldRef::new(b":method", b"HEAD"),
    QpackHeaderFieldRef::new(b":method", b"OPTIONS"),
    QpackHeaderFieldRef::new(b":method", b"POST"),
    QpackHeaderFieldRef::new(b":method", b"PUT"),
    QpackHeaderFieldRef::new(b":scheme", b"http"),
    QpackHeaderFieldRef::new(b":scheme", b"https"),
    QpackHeaderFieldRef::new(b":status", b"103"),
    QpackHeaderFieldRef::new(b":status", b"200"),
    QpackHeaderFieldRef::new(b":status", b"304"),
    QpackHeaderFieldRef::new(b":status", b"404"),
    QpackHeaderFieldRef::new(b":status", b"503"),
    QpackHeaderFieldRef::new(b"accept", b"*/*"),
    QpackHeaderFieldRef::new(b"accept", b"application/dns-message"),
    QpackHeaderFieldRef::new(b"accept-encoding", b"gzip, deflate, br"),
    QpackHeaderFieldRef::new(b"accept-ranges", b"bytes"),
    QpackHeaderFieldRef::new(b"access-control-allow-headers", b"cache-control"),
    QpackHeaderFieldRef::new(b"access-control-allow-headers", b"content-type"),
    QpackHeaderFieldRef::new(b"access-control-allow-origin", b"*"),
    QpackHeaderFieldRef::new(b"cache-control", b"max-age=0"),
    QpackHeaderFieldRef::new(b"cache-control", b"max-age=2592000"),
    QpackHeaderFieldRef::new(b"cache-control", b"max-age=604800"),
    QpackHeaderFieldRef::new(b"cache-control", b"no-cache"),
    QpackHeaderFieldRef::new(b"cache-control", b"no-store"),
    QpackHeaderFieldRef::new(b"cache-control", b"public, max-age=31536000"),
    QpackHeaderFieldRef::new(b"content-encoding", b"br"),
    QpackHeaderFieldRef::new(b"content-encoding", b"gzip"),
    QpackHeaderFieldRef::new(b"content-type", b"application/dns-message"),
    QpackHeaderFieldRef::new(b"content-type", b"application/javascript"),
    QpackHeaderFieldRef::new(b"content-type", b"application/json"),
    QpackHeaderFieldRef::new(b"content-type", b"application/x-www-form-urlencoded"),
    QpackHeaderFieldRef::new(b"content-type", b"image/gif"),
    QpackHeaderFieldRef::new(b"content-type", b"image/jpeg"),
    QpackHeaderFieldRef::new(b"content-type", b"image/png"),
    QpackHeaderFieldRef::new(b"content-type", b"text/css"),
    QpackHeaderFieldRef::new(b"content-type", b"text/html; charset=utf-8"),
    QpackHeaderFieldRef::new(b"content-type", b"text/plain"),
    QpackHeaderFieldRef::new(b"content-type", b"text/plain;charset=utf-8"),
    QpackHeaderFieldRef::new(b"range", b"bytes=0-"),
    QpackHeaderFieldRef::new(b"strict-transport-security", b"max-age=31536000"),
    QpackHeaderFieldRef::new(
        b"strict-transport-security",
        b"max-age=31536000; includesubdomains",
    ),
    QpackHeaderFieldRef::new(
        b"strict-transport-security",
        b"max-age=31536000; includesubdomains; preload",
    ),
    QpackHeaderFieldRef::new(b"vary", b"accept-encoding"),
    QpackHeaderFieldRef::new(b"vary", b"origin"),
    QpackHeaderFieldRef::new(b"x-content-type-options", b"nosniff"),
    QpackHeaderFieldRef::new(b"x-xss-protection", b"1; mode=block"),
    QpackHeaderFieldRef::new(b":status", b"100"),
    QpackHeaderFieldRef::new(b":status", b"204"),
    QpackHeaderFieldRef::new(b":status", b"206"),
    QpackHeaderFieldRef::new(b":status", b"302"),
    QpackHeaderFieldRef::new(b":status", b"400"),
    QpackHeaderFieldRef::new(b":status", b"403"),
    QpackHeaderFieldRef::new(b":status", b"421"),
    QpackHeaderFieldRef::new(b":status", b"425"),
    QpackHeaderFieldRef::new(b":status", b"500"),
    QpackHeaderFieldRef::new(b"accept-language", b""),
    QpackHeaderFieldRef::new(b"access-control-allow-credentials", b"FALSE"),
    QpackHeaderFieldRef::new(b"access-control-allow-credentials", b"TRUE"),
    QpackHeaderFieldRef::new(b"access-control-allow-headers", b"*"),
    QpackHeaderFieldRef::new(b"access-control-allow-methods", b"get"),
    QpackHeaderFieldRef::new(b"access-control-allow-methods", b"get, post, options"),
    QpackHeaderFieldRef::new(b"access-control-allow-methods", b"options"),
    QpackHeaderFieldRef::new(b"access-control-expose-headers", b"content-length"),
    QpackHeaderFieldRef::new(b"access-control-request-headers", b"content-type"),
    QpackHeaderFieldRef::new(b"access-control-request-method", b"get"),
    QpackHeaderFieldRef::new(b"access-control-request-method", b"post"),
    QpackHeaderFieldRef::new(b"alt-svc", b"clear"),
    QpackHeaderFieldRef::new(b"authorization", b""),
    QpackHeaderFieldRef::new(
        b"content-security-policy",
        b"script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    QpackHeaderFieldRef::new(b"early-data", b"1"),
    QpackHeaderFieldRef::new(b"expect-ct", b""),
    QpackHeaderFieldRef::new(b"forwarded", b""),
    QpackHeaderFieldRef::new(b"if-range", b""),
    QpackHeaderFieldRef::new(b"origin", b""),
    QpackHeaderFieldRef::new(b"purpose", b"prefetch"),
    QpackHeaderFieldRef::new(b"server", b""),
    QpackHeaderFieldRef::new(b"timing-allow-origin", b"*"),
    QpackHeaderFieldRef::new(b"upgrade-insecure-requests", b"1"),
    QpackHeaderFieldRef::new(b"user-agent", b""),
    QpackHeaderFieldRef::new(b"x-forwarded-for", b""),
    QpackHeaderFieldRef::new(b"x-frame-options", b"deny"),
    QpackHeaderFieldRef::new(b"x-frame-options", b"sameorigin"),
];
