# Packet inspector

A small command-line example that prints a safe, layered summary of one Ethernet II frame with `net-wire`.

> [!IMPORTANT]
> Input is raw Ethernet II frame bytes, not a pcap file. Remove the four-byte Ethernet FCS before inspection.

## ✨ What it shows

- Ethernet addresses, EtherType, and represented lengths.
- IPv4 or IPv6 addresses and protocol codepoints.
- IPv4 header checksum validation.
- UDP or TCP ports and transport checksum validation when the IP pseudoheader is available.
- Parse failures, fragments, unsupported extension-header paths, and unknown codepoints without discarding the raw value.

## ▶ Run it

Run the deterministic built-in IPv4/UDP frame:

```sh
cargo run --example packet-inspector --features ethernet,ipv4,ipv6,udp,tcp
```

Inspect a raw frame file instead:

```sh
cargo run --example packet-inspector --features ethernet,ipv4,ipv6,udp,tcp -- frame.bin
```

> [!TIP]
> The embedded frame is built at runtime with the public builders. It has valid IPv4 and UDP checksums, so it is a quick sanity check for the full path.

### Representative output

The exact output depends on the supplied frame. The built-in frame reports:

```text
Frame: 46 bytes supplied
Ethernet:
  destination: 02:00:00:00:00:02
  source:      02:00:00:00:00:01
  EtherType:   0x0800
  represented: 46 bytes (32 payload)
IPv4:
  source:      192.0.2.10
  destination: 198.51.100.20
  protocol:    17
  represented: 32 bytes (12 payload)
  header checksum: valid (0x7c47)
UDP:
  ports:       49152 -> 443
  represented: 12 bytes (4 payload)
  checksum:    valid (0x7ff3)
```

## 🧭 Code flow

`main.rs` only selects the input and reports top-level errors. `inspect.rs` parses Ethernet first, dispatches IPv4 or IPv6 from the EtherType, then asks the IP view to safely dispatch UDP or TCP. Checksum checks receive the parsed source and destination addresses needed for the IP pseudoheader.

## Limits

- This is an inspector, not a packet capture reader: it does no network I/O and does not parse pcap/pcapng.
- It handles Ethernet II, IPv4, IPv6, UDP, and TCP only. It does not decode DNS, TLS, VLAN tags, or IPv6 extension contents.
- IPv6 transport dispatch uses the crate's supported extension traversal. A fragment or unsupported traversal is reported rather than guessed at.
- Unknown EtherTypes and IP protocol values remain visible as raw codepoints.
- The Ethernet view does **not** detect FCS bytes. Every byte after the 14-byte Ethernet header is payload under the current API contract, so capture padding may be represented as payload too.

> [!WARNING]
> Checksum output validates bytes as supplied. Capture hardware checksum offload, truncation, or an included FCS can make an otherwise legitimate capture look invalid.
