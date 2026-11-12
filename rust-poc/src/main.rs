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
        Ok(config::Command::Run(config)) => *config,
        Ok(config::Command::Help) => {
            println!("{}", config::Config::usage());
            return ExitCode::SUCCESS;
        }
        Ok(config::Command::Version) => {
            let curl = curl::Version::get();
            println!(
                "dnsp-modern {}\nimplementation=rust-poc\nlibcurl_build={}\nlibcurl_runtime={}\ntls_backend={}\nhttp2={}\nhttp3={}\nprefer_h3={}",
                include_str!("../../VERSION").trim(),
                env!("DNSP_LIBCURL_BUILD"),
                curl.version(),
                curl.ssl_version().unwrap_or("none"),
                if curl.feature_http2() { "yes" } else { "no" },
                if curl.feature_http3() { "yes" } else { "no" },
                if curl.version_num() >= 0x07_58_00 && curl.feature_http3() { "yes" } else { "no" },
            );
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
