mod cache;
mod client;
mod config;
mod doh;
mod metrics;
mod native;
mod proxy;
mod wire;

use std::process::ExitCode;

fn main() -> ExitCode {
    curl::init();
    let config = match config::Config::parse(std::env::args_os().skip(1)) {
        Ok(Some(config)) => config,
        Ok(None) => {
            println!("{}", config::Config::usage());
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    if let Err(error) = native::signals() {
        eprintln!("level=error event=signals message={error}");
        return ExitCode::FAILURE;
    }
    match proxy::Proxy::new(config).and_then(proxy::Proxy::run) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("level=error {error}");
            ExitCode::FAILURE
        }
    }
}
