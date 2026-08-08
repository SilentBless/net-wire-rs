# Architecture

`net-wire` is a `no_std`, allocation-free library for inspecting and constructing exact network wire representations. It provides borrowed views, in-place mutation, caller-buffer encoding, bounded codec state, and protocol-specific semantic validation without owning I/O or connection runtimes.

This document is normative. New code follows these rules even when an older path has not yet been normalized.

## Document scope

This file records durable architecture: ownership, dependency direction, public API topology,
naming, test placement, and completion criteria. It does not track migration order, task status,
agent instructions, temporary exceptions, or work already completed. Put execution plans in the
task tracker and explain one-off implementation constraints in the owning code or review.

When a refactor establishes a reusable precedent, record the resulting rule and the smallest useful
example here. Do not preserve the refactor diary or turn one protocol's current file inventory into a
mandatory taxonomy for every protocol.

## Goals

- Keep raw wire parsing zero-copy for variable-length input bytes.
- Keep production code allocation-free, dependency-free, and safe Rust.
- Preserve unknown, private, reserved, GREASE, duplicate, ordered, and legal noncanonical wire values when the protocol permits them.
- Make each protocol selectable through its own Cargo feature; intrinsic lower-protocol
  requirements are enabled transitively and documented, while optional adapters remain
  orthogonal.
- Keep public APIs byte-oriented, discoverable through protocol namespaces, and suitable for usermode or kernel consumers.
- Keep generated machine code small through narrow features, direct control flow, and ordinary reusable functions rather than codegen tricks.
- Support defensive, interoperability, fuzzing, and authorized red-team tooling without imposing application policy on raw wire data.

## Non-goals

- I/O, sockets, async runtimes, callbacks, or transport ownership.
- Hidden allocation or unbounded storage.
- Cryptographic implementations.
- Complete connection, stream, endpoint, or application runtimes.
- A generic parser framework or packet DSL.
- Generated code, `build.rs`, or procedural macros.
- Preventing callers from constructing unusual or intentionally malformed bytes.

## Code map

- `src/lib.rs` declares feature-gated protocol modules and only truly protocol-independent public items. It contains no protocol implementation.
- `src/<protocol>/` owns one protocol's raw views, encoders, builders, semantic validation, bounded state, and integrations.
- Private cross-protocol implementation shared by multiple real consumers lives in a narrowly named root module. It must not become a public alternate facade.
- `tests/<protocol>/main.rs` is a thin integration-test harness; its directory contains
  problem-focused modules resolved through the ordinary Rust module hierarchy.

Simple protocols should resemble the UDP shape: a thin facade, a file owning both immutable and mutable views of the same datagram, and a separate construction owner.

Complex protocols should use responsibility directories. A directory facade dispatches and reexports; sibling files own real frame families, state machines, codecs, or integrations. QUIC frame families demonstrate the useful part of this shape, but large dispatch and error owners must still be split when they accumulate independent responsibilities.

The accepted HTTP/3 shape is the reference for a complex protocol, not a template to copy
mechanically:

```text
http3/
├── codepoints.rs
├── ids.rs
├── enums/          shared vocabulary with multiple semantic consumers
├── frame/          raw envelope and intrinsic typed payload layouts
├── stream/         unidirectional, peer, control, and message sequencing
├── settings.rs     SETTINGS wire, validation, and peer state
├── headers.rs      decoded-header semantics
├── content.rs      message-content accounting
└── qpack.rs        HTTP/3-to-QPACK handoff
```

Apply the ownership decisions behind that shape:

- a file or directory is named for a protocol object, behavior, or operation, never for a
  historical implementation category;
- a shared enum owner contains only vocabulary used by multiple semantic owners; a type with one
  consumer moves to that consumer;
- raw framing, semantic validation, sequencing state, content accounting, and cross-protocol
  handoff remain separate responsibilities even when they participate in one message flow;
- private directory facades reexport their public surface through the protocol namespace without
  exposing the physical directory taxonomy as a second public API;
- similar protocols may reuse these decisions, but they add only owners justified by their own wire
  format and state boundaries.

## Dependency direction

Within a protocol, dependencies point downward:

```text
wire values and codepoints
          ↓
borrowed views, parsing, and raw encoding
          ↓
checked builders and stateless semantic validation
          ↓
bounded state and state-dependent validation
          ↓
cross-layer adapters
```

The rules are:

1. Raw views and parsers do not depend on builders, semantic policy, state, or another protocol.
2. A raw encoder writes caller-selected wire values and performs only the checks required for safe, bounded output.
3. A checked builder validates its stronger contract, delegates byte emission to the raw encoding owner, and may return a validated typed view.
4. Semantic validators consume raw or decoded views; they do not redefine raw parsing.
5. Bounded state consumes structurally decoded views and validated semantic inputs. It owns
   validation whose meaning depends on that bounded state, performs it before commit, and leaves
   state unchanged on failure; it does not redefine structural wire parsing or own transport
   buffers or I/O.
6. Cross-layer adapters live with the higher-level behavior they provide and are gated by every required lower-layer feature.
7. A lower-layer feature never enables an upper-layer feature. Parsers remain usable without optional integrations.
8. Protocol modules do not reach through another protocol's private implementation.

Internal imports name the real owner rather than relying on public facade reexports. This keeps
file moves and feature gates independent from public API topology.

## Public API

Public items are discovered through protocol namespaces:

```rust
net_wire::http3::Http3Frame
net_wire::qpack::QpackDynamicTable
net_wire::kcp::KcpSegment
```

The crate root exports only genuinely protocol-independent contracts. It is not a duplicate facade for every protocol item, and there is no prelude.

A public type has one canonical module path. Reexports inside a protocol may hide its internal file layout, but unrelated protocol concepts must not share a facade merely for convenience.

Public names describe protocol concepts or precise operations. Avoid historical or catch-all names such as `standard`, `misc`, `common`, `utils`, or `helpers`. Use `frame`, `packet`, `segment`, `record`, `field_section`, `encoder`, `decoder`, `builder`, `state`, `codepoint`, or another protocol term that identifies ownership.

Immutable and mutable views of the same wire layout belong to the same owner. Do not create a separate `_mut.rs` file merely because one type contains `&mut [u8]`.

## Raw and checked construction

Raw encoding is the lowest construction API. It must:

- preflight arithmetic and destination capacity;
- avoid panics and out-of-bounds writes;
- preserve caller-selected representable wire values;
- allow declared fields and actual trailing bytes to disagree when the API explicitly supports malformed construction;
- return raw bytes rather than claim a validated typed invariant it did not establish;
- leave the destination unchanged on failure unless the API explicitly documents a different transaction boundary.

Checked builders are thin validated layers over the same private writer. They add the guarantees
named by their contract, such as required fields, structural consistency, canonical encodings, or
protocol semantics, and return typed validated views where appropriate. A builder that deliberately
permits a legal noncanonical form requires an explicit option and documents the guarantee it does
not provide.

Do not add a universal `force_build` switch. When malformed construction is useful, expose a precise raw encoding contract for that owner. The name and result must make the removed guarantees visible.

## Parsing and mutation

Raw parsers validate structural boundaries and retain caller input. Variable-length payloads, extensions, tokens, names, values, and suffixes are returned as borrowed slices or views.

Decoding fixed-width scalars into value types is compatible with zero-copy parsing. Copying a packet-sized or variable-length field into hidden storage is not.

Mutable views edit caller-owned bytes in place. Methods that can invalidate a view's established boundary either do not exist on the validated view or return to a raw byte contract.

A parser that may receive following wire data documents whether it consumes one prefix or the
complete input. A prefix parser exposes the exact consumed byte range or remaining suffix without
copying; complete-input validation rejects or explicitly returns trailing bytes according to its
named contract.

Raw parsing does not reject an unknown value merely because the library has no semantic
interpretation for it when the format still supplies enough information to establish a safe
structural boundary. If an unknown value makes the wire layout or boundary indeterminate, parsing
returns an explicit unsupported-layout error. Strict protocol or application rules otherwise belong
in explicit typed conversion or semantic validation.

## Shared code

Reuse is justified by an identical invariant, not similar spelling.

A shared private function or module needs at least two current consumers and one canonical responsibility. Prefer, in order:

1. an existing standard-library operation;
2. a small ordinary private function;
3. a private type that carries a real invariant;
4. a private declarative macro for repeated declarations or wire forms.

Do not create root `common`, `utils`, or `helpers` modules. Name the shared responsibility, such as internet checksum handling or RFC 7541 Huffman coding.

A helper must not erase protocol-specific diagnostics, weaken checked arithmetic, force unrelated feature dependencies, or introduce generic monomorphization larger than the duplicated direct code.

## Declarative macros

Private `macro_rules!` macros are appropriate when several current wire forms have the same fields, control flow, diagnostics, and generated API shape. They are especially useful for scalar wrappers, fixed-layout declarations, and repetitive iterator/view definitions.

Do not use a macro:

- only to reduce a file's line count;
- when variants need materially different validation or errors;
- when expanded control flow becomes harder to review than direct code;
- when rust-analyzer signatures, documentation, or autocomplete become worse;
- when a small function expresses the reuse without duplicating generated code.

Macros remain private unless exposing a macro is itself the library's concrete feature. This crate does not use procedural macros or source generation.

## File ownership and size

Line counts are review triggers, not architecture. Count physical lines, including documentation, because navigation cost is real.

- A facade (`lib.rs` or `mod.rs`) should normally stay below 150 lines and contain declarations, gates, and reexports only.
- A production responsibility owner should normally stay below 400 lines.
- At 400–600 lines, review whether the file owns more than one reason to change.
- Above 600 lines, a split or a concise cohesion justification is expected.
- Above 800 lines should be exceptional, usually a single RFC table or another indivisible data definition.
- A test target entrypoint should normally stay below 100 lines.
- A test problem group should normally stay below 400 lines; above 600 lines requires a split or cohesion justification.

Never split by line range, mutability alone, or arbitrary suffixes. Split by protocol concept, state ownership, error boundary, or independently testable behavior. Static tables are not improved by scattering one table across decorative files.

## Errors

Simple protocols may use one focused error owner. Complex protocols colocate error types with the frame family, codec, state machine, or semantic boundary that produces them and reexport them through the protocol facade.

An error preserves the information needed to locate and classify failure: field or operation, absolute or local offset as documented, required and available lengths, nested cause, and wire value where relevant.

A protocol-wide `error.rs` must not become a catalog of unrelated parser, builder, state, and integration failures.

## Tests

Each protocol normally uses one primary explicit Cargo integration-test target rooted at the thin
`tests/<protocol>/main.rs` harness. Its child modules live under the same directory and use the
ordinary Rust module hierarchy rather than `#[path]` indirection; the harness only declares
problem-focused modules and target-wide support. A separate cross-feature target is justified when
it has a genuinely different `required-features` contract and may root directly at its semantic
integration owner.

Test modules are grouped by what they prove, not by implementation chronology. Useful groups include:

- raw wire parsing and exact boundary preservation;
- malformed, truncated, overflow, and noncanonical inputs;
- iteration, offsets, and fail-closed behavior;
- raw encoding and checked builder behavior;
- destination and state atomicity;
- semantic or state transitions;
- feature-gated and cross-layer integration;
- public namespace and API discoverability;
- `community.rs` at `tests/<protocol>/community.rs` for sourced external findings, when that
  protocol has any.

Do not create every group for every protocol. Empty taxonomy is bureaucracy wearing a hard hat.

Narrow private invariants may use unit tests beside their owner. Public behavior, cross-module contracts, feature combinations, caller-buffer behavior, and realistic wire vectors belong in integration tests. Avoid duplicate coverage unless the layers prove different contracts.

A small fixture constructor shared by several modules in one target belongs in
`tests/<protocol>/fixtures.rs`. If target-local support grows into multiple independent jobs, split it
under `tests/<protocol>/fixtures/<named_job>.rs`. Support shared by multiple explicit test targets
lives under `tests/support/<named_job>.rs` and is justified in a module comment by its identical
fixture or independent-oracle contract and current consumers. Do not create `common`, `utils`,
`helpers`, or a miscellaneous test toolbox.

Public API discoverability tests use the canonical protocol namespace. Do not retain root-level
reexport assertions for protocol-specific items unless an explicit compatibility policy names that
root path as supported.

### Adversarial and community cases

Every protocol with parsing, caller-buffer encoding, iteration, or bounded state covers each
applicable failure class: boundary truncation, declared-length mismatch, checked-arithmetic
overflow, duplicate or noncanonical values, forbidden state transitions, resource-accounting
limits, and destination or state preservation on failure. A group may omit a class only when the
protocol has no corresponding operation or invariant.

A sourced external finding belongs in `tests/<protocol>/community.rs`, not an unrelated behavior
group. Every case records a stable source URL or advisory identifier, source title or publisher,
publication or revision date when available, the minimal local reproduction bytes, the concrete
failure mechanism, and expected library behavior. Sources establish provenance; the local assertion
establishes the contract. It is not a dump of unsourced scary-looking payloads.

For every malformed-but-representable condition intentionally supported by a raw encoder, add a
paired test: the raw API emits the caller-selected bytes, while the checked builder or explicit
semantic validator rejects the same violated invariant. The paired tests also verify destination
and state transaction behavior on failure where the API promises atomicity.

Security tests verify safe, deterministic handling; they do not turn raw wire parsing into application policy. Callers may intentionally construct unusual or malformed bytes for interoperability, fuzzing, defensive validation, or authorized red-team work.

## Features and footprint

Cargo features own protocol modules and are orthogonal unless a public protocol contract intrinsically requires another protocol. Optional adapters use conjunction gates rather than forcing lower-level users to enable unrelated layers.

Keep hot wire paths direct. Prefer concrete types and small functions. Avoid trait frameworks,
dynamic dispatch, boxed callbacks, and broad generic combinators without a concrete need; require
measurement when code size or hot-path performance is the stated justification. Use `#[inline]`
deliberately for tiny boundary helpers, not as decoration.

Macros reduce source repetition, not necessarily machine code. Reused non-generic functions can be smaller than repeated macro expansion or monomorphized generic helpers. Inspect code generation only when a concrete refactor changes a hot path or duplicates instantiations; do not build architecture around hand-tuned assembly.

## Change review

A structural change is complete only when:

- every moved responsibility has one canonical owner;
- protocol namespaces and feature gates remain coherent;
- raw, checked, semantic, state, and integration boundaries remain distinct;
- public names and rust-analyzer discoverability were reviewed;
- tests moved to deliberate problem groups with a reviewable old-behavior-to-new-module coverage
  map; no public, adversarial, or regression behavior is lost, and duplicate coverage is retained
  only where distinct layers prove different contracts;
- the Rust 1.91 validation matrix passes: the empty default feature set, each protocol's
  required-features integration target, each supported cross-layer conjunction, and
  `--all-features`;
- no allocation, dependency, unsafe code, generated residue, or unrelated cleanup was introduced;
- package contents and the complete diff, including untracked files, were inspected.
