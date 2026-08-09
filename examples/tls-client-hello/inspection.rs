use net_wire::tls::{
    TlsContentType, TlsExtension, TlsExtensionType, TlsHandshake, TlsRecord, TlsServerNameType,
};

use crate::padding::{PADDING_EXTENSION_TYPE, PaddingExtension};

pub fn inspect(input: &[u8]) -> Result<String, String> {
    let record = TlsRecord::parse(input).map_err(|error| error.to_string())?;
    if record.content_type() != TlsContentType::HANDSHAKE {
        return Err(format!(
            "first record has content type {}, not handshake",
            record.content_type().raw()
        ));
    }

    let handshake = TlsHandshake::parse(record.fragment()).map_err(|error| error.to_string())?;
    let hello = handshake
        .client_hello()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| {
            format!(
                "first handshake has type {}",
                handshake.handshake_type().raw()
            )
        })?;

    let mut report = String::new();
    report.push_str(&format!(
        "record: {} represented bytes, type {}, legacy version 0x{:04x}\n",
        record.as_bytes().len(),
        record.content_type().raw(),
        record.version().raw()
    ));
    if input.len() > record.as_bytes().len() {
        report.push_str(&format!(
            "record suffix: {} bytes not consumed; parse it as later record(s)\n",
            input.len() - record.as_bytes().len()
        ));
    }
    report.push_str(&format!(
        "handshake: {} represented bytes, type {}\n",
        handshake.as_bytes().len(),
        handshake.handshake_type().raw()
    ));
    if record.fragment().len() > handshake.as_bytes().len() {
        report.push_str(&format!(
            "handshake suffix: {} bytes remain in this record\n",
            record.fragment().len() - handshake.as_bytes().len()
        ));
    }
    report.push_str(&format!(
        "ClientHello: legacy version 0x{:04x}, {} cipher suites\n",
        hello.legacy_version().raw(),
        hello.cipher_suites().count()
    ));
    report.push_str("extensions (wire order):\n");

    let mut extension_count = 0;
    for (index, extension) in hello.extensions().enumerate() {
        let extension = extension.map_err(|error| error.to_string())?;
        report_extension(&mut report, index, extension)?;
        extension_count += 1;
    }
    report.push_str(&format!("extension count: {extension_count}\n"));

    Ok(report)
}

fn report_extension(
    report: &mut String,
    index: usize,
    extension: TlsExtension<'_>,
) -> Result<(), String> {
    let extension_type = extension.extension_type();
    report.push_str(&format!(
        "  {index}: type 0x{:04x}, {} payload bytes",
        extension_type.raw(),
        extension.data().len()
    ));

    if extension_type.is_grease() {
        report.push_str(" (GREASE)\n");
        return Ok(());
    }
    report.push('\n');

    if extension_type == TlsExtensionType::SUPPORTED_VERSIONS {
        let versions = extension
            .client_supported_versions()
            .map_err(|error| format!("supported_versions: {error}"))?;
        report.push_str("     supported_versions:");
        for version in versions.iter() {
            report.push_str(&format!(" 0x{:04x}", version.raw()));
        }
        report.push('\n');
    } else if extension_type == TlsExtensionType::SERVER_NAME {
        let names = extension
            .client_server_name_list()
            .map_err(|error| format!("server_name: {error}"))?;
        for name in names.iter() {
            let name = name.map_err(|error| format!("server_name entry: {error}"))?;
            if name.name_type() == TlsServerNameType::HOST_NAME {
                report.push_str("     server_name: ");
            } else {
                report.push_str(&format!(
                    "     server_name type {}: ",
                    name.name_type().raw()
                ));
            }
            push_escaped_bytes(report, name.as_bytes());
            report.push('\n');
        }
    } else if extension_type == PADDING_EXTENSION_TYPE {
        let padding = PaddingExtension::parse(extension.data())
            .map_err(|error| format!("padding: {error}"))?;
        report.push_str(&format!(
            "     RFC 7685 padding: {} zero bytes\n",
            padding.as_bytes().len()
        ));
    } else {
        report.push_str("     unknown extension payload preserved\n");
    }

    Ok(())
}

fn push_escaped_bytes(report: &mut String, bytes: &[u8]) {
    for byte in bytes {
        for escaped in std::ascii::escape_default(*byte) {
            report.push(char::from(escaped));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reported_bytes_escape_terminal_controls_and_invalid_utf8() {
        let mut report = String::new();
        push_escaped_bytes(&mut report, b"host\x1b\n\xff");
        assert_eq!(report, "host\\x1b\\n\\xff");
    }
}
