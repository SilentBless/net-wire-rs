# TLS ClientHello inspection

Inspect the first TLS ClientHello in a raw TLS record with `net-wire`'s borrowed wire views. The embedded record is deterministic and includes SNI, `supported_versions`, RFC 7685 padding, a GREASE extension, and an unknown extension.

> [!NOTE]
> The input is binary TLS record bytes, not PEM, a pcap, or hex text.

## Run

Inspect the embedded record:

```sh
cargo run --example tls-client-hello --features tls
```

Inspect the first record in a file:

```sh
cargo run --example tls-client-hello --features tls -- ./client-hello.record
```

Representative output:

```text
input: embedded record (105 bytes)
record: 105 represented bytes, type 22, legacy version 0x0301
handshake: 100 represented bytes, type 1
ClientHello: legacy version 0x0303, 2 cipher suites
extensions (wire order):
  0: type 0x0000, 17 payload bytes
     server_name: example.test
  1: type 0x002b, 5 payload bytes
     supported_versions: 0x0304 0x0303
  2: type 0x0015, 4 payload bytes
     RFC 7685 padding: 4 zero bytes
  3: type 0x0a0a, 2 payload bytes (GREASE)
  4: type 0x1234, 3 payload bytes
     unknown extension payload preserved
extension count: 5
```

## Data flow

`TlsRecord::parse` bounds the first declared record and leaves any coalesced record suffix outside `as_bytes()`. The example then parses the first complete `TlsHandshake` from that record's fragment, and asks it for a `ClientHello`. Each layer consumes only the bytes it represents; a same-record handshake suffix and a later-record suffix are reported rather than silently treated as ClientHello bytes.

Extensions are iterated once in wire order as raw `TlsExtension` values. The dispatcher first reads and checks `extension_type()`. Only then does it call a matching `net-wire` typed view, such as `client_supported_versions()` or `client_server_name_list()`. GREASE and unrecognised types stay visible as raw values and payload lengths.

`ClientHello::offers_tls13()` is a convenient best-effort inspection helper: malformed extension entries are skipped, so it is not a substitute for strict ClientHello validation. This example parses the selected extension explicitly because malformed input should remain visible.

RFC 7685 padding (type 21) is intentionally implemented in `padding.rs`, not added to the library. The dispatch loop checks type 21 and passes only `extension.data()` to the local borrowed parser. That tiny view validates that every payload byte is zero and borrows the original bytes without allocation. Copy that ownership boundary for an extension `net-wire` does not yet expose: keep its wire validation in a dedicated local module, and keep the top-level dispatcher boring.

> [!TIP]
> Preserve unknown extensions. A ClientHello is an ordered, extensible wire format; dropping unfamiliar values is how inspection tools become obsolete on contact with the internet.

## Limits

This is structural inspection only. It does not reassemble TCP streams, decrypt records, validate certificates, perform cryptography, or maintain TLS handshake state. It expects the first input record to contain a complete ClientHello handshake. Feed reassembled record bytes when the handshake spans transport segments.

> [!WARNING]
> Do not use this example as a TLS endpoint or security policy engine. `net-wire` exposes wire layouts; it does not implement all TLS extensions or a complete TLS protocol stack.
