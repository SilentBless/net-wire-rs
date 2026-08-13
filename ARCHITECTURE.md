# Architecture

`net-wire` is a `no_std`, allocation-free crate for exact, borrowed network-wire views and caller-buffer construction. This guide is **normative**.

## 🧠 Mental model

Keep the handoff visible:

```text
caller bytes
    ↓
raw, structurally bounded owner
    ↓
typed/semantic view or a small local parser
    ↓
caller policy and connection/application state
```

The crate owns wire boundaries, byte layouts, protocol-local validation, and bounded state that a caller explicitly stores. The caller owns buffers, I/O, scheduling, connection/stream/application state, and policy.

Views borrow input exactly. Fixed-width scalars may be decoded into values, but variable-length packet data is not copied into hidden storage. Preserve unknown, private, reserved, GREASE, duplicate, ordered, and legal noncanonical values whenever the layout remains structurally knowable.

Structural validation establishes safe bounds and representable layout. Semantic validation establishes explicit protocol rules. Do not smuggle semantic policy into a raw parser.

## 🧱 Layer boundaries

Dependencies point down:

```text
wire values → borrowed/raw views → checked builders and semantic validation
                                      ↓
                              bounded protocol state
                                      ↓
                             optional cross-layer adapters
```

- Raw parsers and views do not depend on builders, state, policy, or another protocol.
- Raw encoding preserves caller-selected representable values and checks only safe, bounded output.
- Checked builders add their named invariants and may return a validated view.
- Bounded state defines its commit boundary explicitly. Failures are atomic unless an API explicitly documents prefix commitment for successfully applied sequence items; callers must not replay a committed prefix.
- Adapters live with the higher-level behavior they provide and require every relevant feature.
- Lower-layer features never enable upper layers. Protocol modules import physical owners, not another module's public facade.

The crate root exports only truly shared contracts. A protocol has one canonical public namespace. Facades dispatch and reexport; they do not become implementation owners. Do not add catch-all `common`, `utils`, or `helpers` modules.

Errors belong to the producer domain: frame, builder, codec, state, or integration owner. Preserve useful failure context—operation or field, documented offset, required and available lengths, nested cause, and wire value where relevant.

## 🔎 Parsing and consumption

Every parser documents whether it accepts one prefix, returns a suffix, or validates a complete input. Its return shape is part of its contract:

- A bounded prefix item exposes its represented length through `as_bytes()`; `TlsRecord::parse` is one example.
- APIs whose public contract returns `(item, suffix)` do so directly, including KCP segments and QUIC frames.
- Complete-sequence parsers validate the whole sequence, as with QPACK instruction sequences.

External framing remains caller-owned when the bytes do not identify their own boundary. Ethernet II is the reference case: the on-medium frame may contain minimum-frame padding and a four-octet FCS, but the header has no payload length, receive paths commonly strip the FCS, and capture input may contain either trailer independently. The Ethernet view therefore consumes the caller-bounded remainder instead of guessing. A nested IPv4 `total_length` can exclude trailing Ethernet bytes from the IPv4 view, but it cannot classify that tail as padding or prove an FCS. Source or capture metadata must own that interpretation.

Do not force these different wire contracts behind a generic cursor or a uniform consumption API. Check every length, offset, and conversion with exact bounds and checked arithmetic. Unknown values remain raw if their envelope establishes a boundary; return an unsupported-layout error only when the layout itself cannot be known.

## ✍️ Writing and mutation

All output storage is caller-owned. Builders preflight capacity and arithmetic before writing; a whole-buffer builder is atomic unless its documentation explicitly says otherwise. Canonical builder output is appropriate for a checked contract, while raw encoding may intentionally preserve legal noncanonical or malformed-but-representable choices.

For nested IPv4/UDP construction, write in this order:

```text
payload → transport checksum → IPv4 header checksum
```

Mutable setters and raw mutable slices edit bytes; they do **not** automatically repair checksums, lengths, or dependent fields. A mutation that breaks an established boundary must either be unavailable on the validated view or return to a raw-byte contract.

## 🧩 Unsupported protocol material

Keep a raw envelope when it has a known boundary. Add typed interpretation only when the crate owns that protocol material.

TLS is the reference pattern. Iterate `TlsExtension` raw envelopes, inspect the preserved extension type, then either invoke the crate's typed extension parser or pass `extension.data()` to a small project-local borrowed parser. Unknown extensions remain raw. The TLS ClientHello example does this for RFC 7685 padding.

Do not put a project's local extension parser into `net-wire` merely because it is nearby. Do not build a registry, cursor framework, or plugin mechanism to parse one extension format. Add shared machinery only after multiple current consumers prove identical semantics.

## ⚙️ Features and dependencies

This is one package and one crate, using Rust 1.91 and edition 2024. It has `#![no_std]`, `#![deny(missing_docs)]`, `unsafe_code = deny`, an empty default feature set, no production allocation, and no production I/O. `wire-repr` is an optional protocol-scoped production dependency currently used by ARP, Ethernet, and IPv4.

Protocol features own their modules: Ethernet, ARP, IPv4/IPv6, ICMPv4/ICMPv6, UDP/TCP, KCP, TLS, HTTP/1, HTTP/2 (including HPACK), QUIC, QPACK, and HTTP/3. `http3` enables `quic` and `qpack`. Cross-layer adapters use conjunction gates; they must not create transitive upper-layer coupling.

Keep hot wire paths direct. Avoid trait frameworks, dynamic dispatch, broad generic combinators, `build.rs`, and macros unless a real accepted need proves them smaller and clearer than direct code. Generated layout code is acceptable only where verified direct operations preserve the protocol API, bounds, and atomicity.

A generated layout owns physical field placement, framing, borrowed views, and caller-buffer construction. Protocol modules continue to own nominal value spaces, registry constants, semantic validation, and cross-layer behavior. Map physical scalar fields to those protocol-owned types rather than moving domain semantics into the layout DSL.

## 🗂️ Code organization and testing

Put an implementation with its physical protocol owner. A simple protocol may have a thin facade, one view owner for immutable and mutable forms, and a builder owner. Complex protocols split by real wire object, state boundary, or independent behavior; facades remain declarations, dispatch, and reexports.

A shared private mechanism needs at least two current consumers with identical semantics. Prefer a small ordinary function or narrowly named invariant-bearing type. Never split files just to satisfy a line count; split when responsibility changes.

Test one behavior in its deliberate home:

- Narrow implementation invariants stay near their owner.
- Public, cross-module, feature-gated, caller-buffer, and fixture-heavy contracts live under `tests/<protocol>/`, rooted by the thin `main.rs` harness.
- Cross-protocol behavior belongs in integration tests.
- Use a separate test target only for a genuinely distinct standalone feature contract.

Avoid duplicate tests unless they prove different contracts. Test malformed boundaries, checked arithmetic, raw-vs-checked behavior, atomic destination/state failure, and noncanonical or state-dependent cases when that protocol has them.

## ➕ Adding a protocol or extension

1. Identify the physical owner and the raw/semantic/state boundary.
2. Preserve the wire representation; design parse/build errors and caller storage first.
3. Gate the module and any adapter precisely.
4. Test the real public contracts, including failure and ownership behavior.
5. Add documentation or an example when composition is not obvious.
6. Delete a superseded owner immediately rather than keeping a second authority around.

Do not create a generic framework for a single new format. Reuse follows proven identical semantics, not similar spelling.

## 🚫 Non-goals

`net-wire` does not own sockets, I/O, async runtimes, cryptography, TLS handshaking, or complete connection, stream, endpoint, and application state machines. It is not a universal codec/schema framework and does not claim complete RFC coverage or network interoperability verification.

Caller-owned bounded protocol state is in scope: QPACK/HPACK-style table and instruction accounting are useful wire-adjacent state. A connection runtime built around that state is not.
