//! Linux-only raw IPv4 DNS query example.

#[cfg(any(target_os = "linux", test))]
mod dns;
#[cfg(any(target_os = "linux", test))]
mod packet;
#[cfg(any(target_os = "linux", test))]
mod raw_socket;

#[cfg(target_os = "linux")]
use std::{
    fmt::Write,
    net::Ipv4Addr,
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(target_os = "linux")]
use dns::{QueryType, RecordData};
#[cfg(target_os = "linux")]
use net_wire::ipv4::Ipv4Address;
#[cfg(target_os = "linux")]
use packet::{QueryParameters, ResponseExpectation, build_query_packet, parse_response_packet};

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("dns-query: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("dns-query: Linux only (requires Linux raw IPv4 sockets)");
    std::process::ExitCode::FAILURE
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), String> {
    let mut arguments = std::env::args().skip(1);
    let source = parse_address(arguments.next(), "source-ip")?;
    let server = parse_address(arguments.next(), "server-ip")?;
    let name = arguments.next().ok_or_else(usage)?;
    let query_type = match arguments.next().as_deref() {
        None | Some("A") => QueryType::A,
        Some("AAAA") => QueryType::Aaaa,
        Some(_) => return Err(usage()),
    };
    if arguments.next().is_some() {
        return Err(usage());
    }

    let transaction_id = transaction_id();
    let query = QueryParameters {
        source,
        destination: server,
        source_port: 49_152 + transaction_id % 16_384,
        destination_port: 53,
        transaction_id,
        qname: &name,
        query_type,
        ipv4_identification: transaction_id.rotate_left(5),
        ttl: 64,
    };
    let mut request_buffer = [0u8; 512];
    let request =
        build_query_packet(&mut request_buffer, query).map_err(|error| error.to_string())?;
    let expected = ResponseExpectation::from(query);
    let response_bytes = raw_socket::send_and_receive(source, server, request, expected)
        .map_err(|error| error.to_string())?;
    let response =
        parse_response_packet(&response_bytes, expected).map_err(|error| error.to_string())?;
    let header = response.dns.header();
    println!(
        "response id={:#06x} rcode={} answers={} truncated={} recursion-available={}",
        header.id,
        header.response_code(),
        header.answer_count,
        header.truncated(),
        header.recursion_available()
    );
    for answer in response.dns.answers().map_err(|error| error.to_string())? {
        let answer = answer.map_err(|error| error.to_string())?;
        let owner = display_name(answer.name)?;
        match answer.data {
            RecordData::A(octets) => {
                println!("{owner}\t{}\tIN\tA\t{}", answer.ttl, Ipv4Addr::from(octets))
            }
            RecordData::Aaaa(octets) => println!(
                "{owner}\t{}\tIN\tAAAA\t{}",
                answer.ttl,
                std::net::Ipv6Addr::from(octets)
            ),
            RecordData::Other(bytes) => println!(
                "{owner}\t{}\tclass={} type={} rdata={} bytes",
                answer.ttl,
                answer.class,
                answer.kind,
                bytes.len()
            ),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn parse_address(value: Option<String>, role: &str) -> Result<Ipv4Address, String> {
    let value = value.ok_or_else(usage)?;
    let address: Ipv4Addr = value
        .parse()
        .map_err(|_| format!("{role} must be an IPv4 address: {value}"))?;
    if address.is_unspecified() {
        return Err(format!("{role} must not be 0.0.0.0"));
    }
    Ok(Ipv4Address::new(address.octets()))
}

#[cfg(target_os = "linux")]
fn transaction_id() -> u16 {
    let nanos = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos(),
        Err(_) => 0,
    };
    let time_bytes = nanos.to_le_bytes();
    let pid_bytes = std::process::id().to_le_bytes();
    u16::from_le_bytes([time_bytes[0] ^ pid_bytes[0], time_bytes[1] ^ pid_bytes[1]])
}

#[cfg(target_os = "linux")]
fn display_name(name: dns::Name<'_>) -> Result<String, String> {
    let mut output = String::new();
    for (index, label) in name.labels().enumerate() {
        if index != 0 {
            output.push('.');
        }
        for byte in label.map_err(|error| error.to_string())? {
            if (0x21..=0x7e).contains(byte) && *byte != b'.' && *byte != b'\\' {
                output.push(char::from(*byte));
            } else {
                write!(&mut output, "\\x{byte:02x}")
                    .map_err(|_| "name formatting failed".to_owned())?;
            }
        }
    }
    if output.is_empty() {
        output.push('.');
    }
    Ok(output)
}

#[cfg(target_os = "linux")]
fn usage() -> String {
    "usage: dns-query <source-ip> <server-ip> <name> [A|AAAA]".to_owned()
}
