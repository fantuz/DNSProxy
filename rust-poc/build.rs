use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-env-changed=DEP_CURL_INCLUDE");
    let includes = env::var_os("DEP_CURL_INCLUDE").expect("curl-sys must provide its header path");
    let mut paths: Vec<_> = env::split_paths(&includes).collect();
    // curl-sys can expose only the last pkg-config include directory, which may
    // belong to a dependency such as Kerberos. Ask libcurl for its own directory.
    if let Ok(output) = Command::new("pkg-config")
        .args(["--variable=includedir", "libcurl"])
        .output()
    {
        if output.status.success() {
            if let Ok(path) = String::from_utf8(output.stdout) {
                let path = path.trim();
                if !path.is_empty() {
                    paths.push(PathBuf::from(path));
                }
            }
        }
    }
    let (header, version) = paths
        .into_iter()
        .flat_map(|path| [path.join("curl/curlver.h"), path.join("curlver.h")])
        .find_map(|header| {
            let text = fs::read_to_string(&header).ok()?;
            let version = text.lines().find_map(|line| {
                let mut fields = line.split_whitespace();
                match (fields.next(), fields.next(), fields.next()) {
                    (Some("#define"), Some("LIBCURL_VERSION"), Some(value)) => {
                        Some(value.trim_matches('"').to_owned())
                    }
                    _ => None,
                }
            })?;
            Some((header, version))
        })
        .unwrap_or_else(|| panic!("libcurl version header missing from {includes:?}"));
    println!("cargo:rerun-if-changed={}", header.display());
    println!("cargo:rustc-env=DNSP_LIBCURL_BUILD={version}");
}
