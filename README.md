# net-wire

**`net-wire`** is one `no_std` Rust crate for inspecting and constructing exact network-wire layouts. It exposes byte-oriented, borrowed views; leaves storage and I/O with the caller; and provides bounded protocol state where the wire format actually needs it.

It targets **Rust 1.91** and **edition 2024**.

## ✨ What it promises

- **No production allocation or `unsafe`.** Production code is allocation-free and builds with `unsafe_code = deny`; the foundational `wire-repr` representation dependency is always present; protocol surfaces remain opt-in with their features.
- **Opt in deliberately.** The default feature set is empty.
- **Borrowed wire views.** Variable-length bytes stay borrowed from caller input; construction writes into caller-provided buffers.
- **Wire fidelity.** Unknown, private, reserved, GREASE, duplicate, ordered, and legal noncanonical values remain representable and preserved when the format permits them.
- **Bounded, not ambient state.** Protocol-local state such as compression-table accounting can be caller-owned without turning the crate into a connection runtime.

> [!NOTE]
> A successful parse establishes the structural boundary promised by that parser. It does not silently apply an application's semantic policy.

## 🧱 Built with `wire-repr`

`net-wire` uses our [`wire-repr`](https://github.com/SilentBless/wire-repr-rs) library to generate safe byte-backed views and caller-buffer builders from explicit wire layouts. The generated code remains ordinary direct Rust: there are no runtime schemas, reflection, allocation, dynamic dispatch, or `unsafe` byte reinterpretation.

It is a foundational physical-representation dependency rather than an optional protocol-scoped feature edge. Protocol features still select their public surfaces; `wire-repr` remains available to the crate regardless of those selections. Other protocol owners will migrate incrementally only where the generated representation preserves their existing wire and code-generation contracts.

## 🚫 What it is not

`net-wire` does **not** provide sockets or I/O, an async runtime, connection or application state machines, a TLS/cryptography stack, a universal codec/schema framework, or automatic semantic policy. It is deliberately a wire-layout crate, not a network stack wearing a fake moustache.

## 🚀 Quick start

Enable only the formats you use. For Ethernet, IPv4, and UDP dispatch:

```toml
[dependencies]
net-wire = { version = "0.1.0", default-features = false, features = ["ethernet", "ipv4", "udp"] }
```

### Parse a nested packet

Each layer first parses its own bounded bytes, then dispatches only when its discriminator agrees:

```rust
use net_wire::{
    ethernet::{EtherType, EthernetFrame},
    ipv4::Ipv4Packet,
};

fn inspect(bytes: &[u8]) {
    let Ok(frame) = EthernetFrame::view(bytes).without_trailing() else {
        return;
    };
    if frame.ether_type() != EtherType::IPV4 {
        return;
    }

    let Ok(packet) = Ipv4Packet::parse(frame.payload()) else {
        return;
    };
    match packet.udp() {
        Ok(Some(datagram)) => {
            println!("UDP {} -> {}", datagram.source_port(), datagram.destination_port());
            println!("payload: {:02x?}", datagram.payload());
        }
        Ok(None) => println!("not a whole UDP datagram for this IPv4 packet"),
        Err(error) => println!("malformed UDP datagram: {error}"),
    }
}
```

Feature-gated dispatch methods use `Result<Option<T>, E>` on purpose:

- `Ok(Some(value))` — the selected protocol matches and its bounded bytes are structurally valid.
- `Ok(None)` — the discriminator does not match, or the enclosing packet is fragmented where that dispatch cannot safely claim a whole child.
- `Err(error)` — the selected child is malformed.

### Build into caller storage

Write payload bytes first, then calculate the transport checksum, then build the IPv4 header (and therefore its header checksum):

```rust
use net_wire::{
    ipv4::{Ipv4Address, Ipv4PacketBuilder, Ipv4Protocol},
    udp::UdpDatagramBuilder,
};

let source = Ipv4Address::new([192, 0, 2, 10]);
let destination = Ipv4Address::new([198, 51, 100, 20]);
let payload = b"ping";
let mut bytes = [0_u8; 20 + 8 + 4];

{
    let mut udp = UdpDatagramBuilder::new(&mut bytes[20..], payload.len())
        .source_port(49_152)
        .destination_port(53)
        .build()
        .unwrap();
    udp.payload_mut().copy_from_slice(payload);
    udp.update_checksum_ipv4(source, destination);
}

let packet = Ipv4PacketBuilder::new(&mut bytes, 8 + payload.len())
    .source(source)
    .destination(destination)
    .protocol(Ipv4Protocol::UDP)
    .ttl(64)
    .build()
    .unwrap();
assert!(packet.checksum_is_valid());
```

> [!IMPORTANT]
> An Ethernet frame on the medium may end with minimum-frame padding and a four-byte FCS. `EthernetFrame` intentionally does not guess those boundaries: Ethernet II has no payload-length field, receive APIs commonly remove the FCS, and captured input may contain padding, FCS, both, or neither. The view is therefore caller-bounded and treats every supplied byte after its 14-byte header as payload. Use capture metadata to exclude known trailers before parsing.
>
> A nested parser may establish a narrower boundary. In the example above, IPv4's `total_length` keeps trailing Ethernet bytes out of `Ipv4Packet` and its UDP/TCP payload. The remaining bytes are still only an unclassified tail; without source metadata they cannot safely be called padding or a valid FCS, and `Ipv4Packet::parse` does not return them as a formal suffix.

> [!IMPORTANT]
> Structural validation answers whether bytes form a safely bounded layout. Semantic validation answers protocol-specific questions such as allowed values, ordering, or state transitions. Keep those decisions explicit.
>
> Editing payloads or fields through mutable views can stale checksums and dependent lengths. Setters and mutable protocol regions do not repair them automatically; recompute or rebuild in the right order. Whole-view mutable bytes are exposed only where changing them cannot invalidate cached framing.

## 🧭 Consumption is part of the contract

Not every protocol consumes input the same way. `TlsRecord::parse` returns the first complete record; `record.as_bytes().len()` tells you the prefix it represented. Some public APIs intentionally return `(item, suffix)`, such as a KCP segment or QUIC frame. Other APIs validate a complete sequence, such as QPACK instruction sequences.

Use the contract of the specific parser rather than assuming every `parse` consumes all input. That distinction prevents a coalesced TLS record, a frame stream, or a sequence codec from being accidentally treated as one uniform blob.

## 🧩 Features

| Feature | Wire surface |
| --- | --- |
| `ethernet` | Ethernet II frames |
| `arp` | ARP packets |
| `ipv4` / `ipv6` | Internet packets and dispatch helpers |
| `icmpv4` / `icmpv6` | ICMP messages |
| `udp` / `tcp` | Transport datagrams and segments |
| `kcp` | KCP segments |
| `tls` | TLS records, handshakes, and extensions |
| `http1` | HTTP/1 heads and chunked framing |
| `http2` | HTTP/2 frames, sequencing, and HPACK |
| `quic` | QUIC primitives, packets, frames, and transport parameters |
| `qpack` | QPACK primitives and caller-owned bounded state |
| `http3` | HTTP/3 frames and bounded protocol state; enables `quic` and `qpack` |

Features select public protocol modules. Optional cross-layer adapters are available only when **both** involved features are enabled; enabling a lower layer never drags in an upper one.

## 📚 Examples

- [`packet-inspector`](examples/packet-inspector/) — parses an Ethernet frame and follows IPv4/IPv6 payloads to UDP or TCP, including checksum reporting.
- [`dns-query`](examples/dns-query/) — a **Linux-only raw IPv4** DNS query path without Ethernet framing, with a small project-local DNS codec; `socket2` is an example-only dev dependency, not a production dependency of `net-wire`.
- [`tls-client-hello`](examples/tls-client-hello/) — walks a TLS ClientHello while preserving extension envelopes and handles RFC 7685 padding with a small local borrowed parser.

For contributor and design rules, see [**ARCHITECTURE.md**](ARCHITECTURE.md).
