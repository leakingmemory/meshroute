use flate2::read::GzDecoder;
use std::io::Read;
use std::process::ExitCode;

const MAIN_LICENSE: &str = include_str!("../LICENSE");
const DEPS_LICENSE_GZ: &[u8] = include_bytes!("../DEPENDENCIES_LICENSE.gz");

pub fn run_licenses() -> ExitCode {
    println!("--- Main License ---\n");
    println!("{}", MAIN_LICENSE);
    println!("\n--- Dependency Licenses ---\n");

    let mut decoder = GzDecoder::new(DEPS_LICENSE_GZ);
    let mut s = String::new();
    if let Err(e) = decoder.read_to_string(&mut s) {
        eprintln!("Error decompressing licenses: {}", e);
        return ExitCode::from(1);
    }
    println!("{}", s);

    ExitCode::from(0)
}
