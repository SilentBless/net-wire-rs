mod inspection;
mod padding;

use std::{env, fs, process::ExitCode};

use inspection::inspect;

const EMBEDDED_RECORD: &[u8] = &[
    0x16, 0x03, 0x01, 0x00, 0x64, 0x01, 0x00, 0x00, 0x60, 0x03, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x00, 0x04, 0x13, 0x01,
    0x13, 0x02, 0x01, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x11, 0x00, 0x0f, 0x00, 0x00, 0x0c, b'e',
    b'x', b'a', b'm', b'p', b'l', b'e', b'.', b't', b'e', b's', b't', 0x00, 0x2b, 0x00, 0x05, 0x04,
    0x03, 0x04, 0x03, 0x03, 0x00, 0x15, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x0a, 0x00, 0x02,
    0xde, 0xad, 0x12, 0x34, 0x00, 0x03, 0x01, 0x02, 0x03,
];

fn main() -> ExitCode {
    let mut arguments = env::args_os();
    let program = arguments
        .next()
        .unwrap_or_else(|| "tls-client-hello".into());
    let input = match (arguments.next(), arguments.next()) {
        (None, None) => ("embedded record".to_owned(), Ok(EMBEDDED_RECORD.to_vec())),
        (Some(path), None) => {
            let label = path.to_string_lossy().into_owned();
            (label, fs::read(path).map_err(|error| error.to_string()))
        }
        _ => {
            eprintln!("usage: {} [raw-tls-record]", program.to_string_lossy());
            return ExitCode::from(2);
        }
    };

    let bytes = match input.1 {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("cannot read {}: {error}", input.0);
            return ExitCode::from(1);
        }
    };

    println!("input: {} ({} bytes)", input.0, bytes.len());
    match inspect(&bytes) {
        Ok(report) => {
            print!("{report}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("inspection failed: {error}");
            ExitCode::from(1)
        }
    }
}
