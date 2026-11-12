use std::{env, fs, path::Path};

fn main() {
    println!("cargo:rerun-if-env-changed=DEP_CURL_INCLUDE");
    let includes = env::var_os("DEP_CURL_INCLUDE").expect("curl-sys must provide its header path");
    let (header, version) = env::split_paths(&includes)
        .filter_map(|path| {
            let header = Path::new(&path).join("curl/curlver.h");
            let text = fs::read_to_string(&header).ok()?;
            let version = text.lines().find_map(|line| {
                line.strip_prefix("#define LIBCURL_VERSION ")
                    .map(|value| value.trim().trim_matches('"').to_owned())
            })?;
            Some((header, version))
        })
        .next()
        .expect("libcurl version header must be readable");
    println!("cargo:rerun-if-changed={}", header.display());
    println!("cargo:rustc-env=DNSP_LIBCURL_BUILD={version}");
}
