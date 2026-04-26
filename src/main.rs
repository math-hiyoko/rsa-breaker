mod encode;
mod error;
mod key;
mod parse;
mod solver;

use clap::Parser;

use crate::{encode::encode_private_key, parse::parse_auto, solver::solve_key};

#[derive(Debug, Parser)]
#[command(name = "rsa-breaker")]
#[command(version, about = "RSA key utility", long_about = None)]
struct Args {
    /// Input RSA public key file (PEM, DER, OpenSSH)
    #[arg(short, long, value_name = "FILE")]
    input: std::path::PathBuf,

    /// Output private key file (PEM/DER). Defaults to auto-generated name
    #[arg(short, long, value_name = "FILE")]
    output: Option<std::path::PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Args::parse();

    let input = args.input;
    let output = match args.output {
        Some(path) => path,
        None => {
            let parent = input.parent().unwrap_or_else(|| std::path::Path::new("."));
            match input.file_name().and_then(|file| file.to_str()) {
                Some("id_rsa.pub") => parent.join("id_rsa"),
                Some("public.pem") => parent.join("private.pem"),
                Some("key.pub") => parent.join("key.pem"),
                Some("server.crt") => parent.join("server.key"),
                Some("public.der") => parent.join("private.der"),
                _ => {
                    let stem = input.file_stem().unwrap_or_else(|| input.as_os_str());
                    let mut file_name = std::ffi::OsString::from(stem);
                    file_name.push("_private");

                    if let Some(ext) = input.extension() {
                        file_name.push(".");
                        file_name.push(ext);
                    }
                    parent.join(file_name)
                }
            }
        }
    };

    log::info!("reading the contents of input file: {input:?}...");
    let public_bytes = std::fs::read(input)?;
    log::info!("parsing the contents of public key...");
    let public_key = parse_auto(&public_bytes)?;
    log::info!("solving public key...");
    let private_key = solve_key(public_key)?;
    log::info!("writing public key to output file: {output:?}...");
    encode_private_key(&output, private_key)?;

    Ok(())
}
