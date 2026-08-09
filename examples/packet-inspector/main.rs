mod inspect;

use std::{env, fs, path::PathBuf, process};

fn main() {
    if let Err(error) = run() {
        eprintln!("packet-inspector: {error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let path = input_path()?;
    let bytes = match path {
        Some(path) => fs::read(&path)
            .map_err(|error| format!("could not read {}: {error}", path.display()))?,
        None => inspect::demo_frame()?,
    };

    print!("{}", inspect::report(&bytes));
    Ok(())
}

fn input_path() -> Result<Option<PathBuf>, String> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let path = arguments.next().map(PathBuf::from);

    if arguments.next().is_some() {
        return Err("usage: cargo run --example packet-inspector -- [frame.bin]".to_owned());
    }

    Ok(path)
}
