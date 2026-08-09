# Raw IPv4 DNS query (Linux)

A small, synchronous DNS client that builds the DNS message, UDP datagram, and IPv4 packet itself, then sends it through a Linux raw socket. It is an example, not a resolver.

> [!WARNING]
> **Linux only.** It uses `AF_INET`/`SOCK_RAW` and needs `CAP_NET_RAW` (normally root). It deliberately has no BSD, macOS, or Windows socket implementation.

## Run it

Use a source address actually configured on a local interface; it is not an address to invent for the occasion.

```sh
cargo run --example dns-query --features ipv4,udp -- 192.0.2.10 1.1.1.1 example.com
sudo cargo run --example dns-query --features ipv4,udp -- 192.0.2.10 1.1.1.1 example.com AAAA
```

Alternatively, grant only the built executable the capability:

```sh
cargo build --example dns-query --features ipv4,udp
sudo setcap cap_net_raw+ep target/debug/examples/dns-query
./target/debug/examples/dns-query 192.0.2.10 1.1.1.1 example.com A
```

Exact CLI:

```text
dns-query <source-ip> <server-ip> <name> [A|AAAA]
```

`A` is the default. Names are ASCII DNS wire labels only; there is no IDNA conversion.

> [!NOTE]
> The commands above are usage instructions, not evidence of a network run here. Raw I/O cannot be exercised on the current macOS host.

Representative output (illustrative):

```text
response id=0x4a19 rcode=0 answers=1 truncated=false recursion-available=true
example.com	300	IN	A	93.184.216.34
```

## Packet flow

```text
CLI -> dns.rs: DNS payload (<= 484 bytes in this example)
    -> packet.rs: UDP checksum, then IPv4 header
    -> raw_socket.rs: Linux raw IPv4 socket
    -> network: IPv4 + UDP + DNS
    <- raw socket: IPv4 packet (no Ethernet frame)
    <- packet.rs: address/port/checksum/transaction-ID filter
    <- dns.rs: header and answers in wire order
```

The builder order matters: DNS first, then UDP (whose checksum covers its payload and IPv4 pseudo-header), then IPv4. `net-wire` builds and parses those wire structures; local `dns.rs` owns the deliberately small RFC 1035 codec; `socket2` owns Linux socket calls.

## Linux raw-socket behavior

The socket is created as IPv4 raw UDP and uses `IP_HDRINCL`. The application supplies the IPv4 header. Linux still fills the IPv4 total length and header checksum on send. UDP's checksum remains the caller's responsibility, so `packet.rs` computes it.

The bind and connected raw sockaddr use port zero. Connecting narrows received traffic, but the example still validates IPv4 source/destination, UDP ports, IPv4 checksum, UDP checksum, and the DNS transaction ID. Unrelated valid UDP datagrams are ignored until the finite read timeout; malformed packets that otherwise match the flow are reported.

There is no Ethernet header in an `AF_INET` raw socket packet. Link-layer framing belongs below this socket API, so manufacturing an Ethernet frame here would be wrong.

## Troubleshooting

- `Operation not permitted`: run through `sudo`, or apply `cap_net_raw+ep` to the built binary.
- `Cannot assign requested address`: the supplied source IP is not configured locally.
- Timeout: check routing, firewall rules, the source IP, and that the server accepts ordinary UDP DNS.
- `response packet rejected`: traffic reached the raw socket but failed a checksum or expected-flow check.
- `rcode` is nonzero: DNS replied with a protocol failure such as NXDOMAIN; the response is still shown rather than being pretended away.

> [!TIP]
> Start with a public resolver and a real local unicast address. `0.0.0.0` is rejected because it does not identify a configured source.

## Deliberate limits

No TCP fallback, EDNS, DNSSEC, cache, resolver search rules, retries, async I/O, IDNA, or general DNS record decoding. Unsupported records retain and report their class, type, and RDATA length. The receive buffer fits one complete IPv4 datagram; the complete outbound IPv4 packet is bounded to 512 bytes.
