use std::io::{self, BufRead, Write};
use doria_core::scanner::scan_package;
use doria_types::{Ecosystem, ScanResult};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 4 {
        eprintln!("usage: doria-scanner <package_dir> <package_name> <package_version> <ecosystem>");
        std::process::exit(1);
    }

    let package_dir = &args[1];
    let package_name = &args[2];
    let package_version = &args[3];
    let ecosystem = match args.get(4).map(|s| s.as_str()) {
        Some("pip") => Ecosystem::Pip,
        _ => Ecosystem::Npm, // default to npm
    };

    let result = scan_package(package_dir, package_name, package_version, ecosystem);

    // Write result as a single newline-delimited JSON object to stdout
    // This is the contract with doria-engine — one JSON line per package
    let json = serde_json::to_string(&result).expect("failed to serialize scan result");
    println!("{}", json);
    io::stdout().flush().expect("failed to flush stdout");
}