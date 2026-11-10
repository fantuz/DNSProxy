use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::time::Duration;

use curl::Version;
use curl::easy::HttpVersion;

use crate::{native, wire};

pub const MAX_CLIENTS: usize = 128;
pub const MAX_ACTIVE: usize = 128;
pub const MAX_WAITERS: usize = 8;
pub const MAX_CACHE: usize = 1024;

const USAGE: &str = "Usage: dnsp-modern-rust [options]
  -l IPv4                     DNS bind address (default 127.0.0.1)
  -p PORT                     UDP/TCP DNS port, 1..65535 (default 5300)
  -s URL                      DoH upstream (default https://cloudflare-dns.com/dns-query)
  --backup-upstream URL        Optional DoH endpoint for transport failover
  --backup-bootstrap-address IP  Numeric address for the backup HTTPS upstream
  -m PORT                     Loopback metrics port, 1..65535 (default disabled)
  --bootstrap-address IP      Numeric IPv4 or IPv6 address for the HTTPS upstream
  --edns-padding               Pad eligible HTTPS DNS queries to 128-byte blocks
  --ca-file PEM                CA bundle for upstream TLS verification
  --upstream-http MODE         auto (default) or prefer-h3 (HTTPS with fallback)
  --max-host-connections N     Upstream connections per origin, 1..16 (default 8)
  --tcp-max-per-source N       TCP connections per IPv4 source, 1..128 (default 32)
  --tcp-idle-ms MS             Idle TCP session, 100..600000 (default 15000)
  --tcp-io-ms MS               TCP frame read/write deadline, 100..600000 (default 15000)
  --doh-connect-ms MS          Upstream connection deadline, 100..60000 (default 1500)
  --doh-timeout-ms MS          Total upstream deadline, 100..60000 (default 3000)
  --cache-entries N            In-memory DNS cache slots, 0..1024 (default disabled)
  --udp-reply-max BYTES        UDP reply cap, 512..4096 (default 1232)
  -h, --help                   Show this help";

pub struct Endpoint {
    pub url: String,
    pub loopback_http: bool,
    pub resolve: Option<String>,
    host: String,
    port: u16,
}

impl Endpoint {
    fn new(url: String, bootstrap: Option<&str>) -> Option<Self> {
        let (scheme, host, port) = native::url_parts(&url)?;
        let loopback_http = scheme == "http" && host == "127.0.0.1" && bootstrap.is_none();
        if scheme != "https" && !loopback_http {
            return None;
        }
        let resolve = if let Some(address) = bootstrap {
            if host.starts_with('[') || host.parse::<Ipv4Addr>().is_ok() {
                return None;
            }
            let entry = match address.parse::<IpAddr>().ok()? {
                IpAddr::V4(_) => format!("{host}:{port}:{address}"),
                IpAddr::V6(_) => format!("{host}:{port}:[{address}]"),
            };
            if entry.len() >= 512 {
                return None;
            }
            Some(entry)
        } else {
            None
        };
        Some(Self {
            url,
            loopback_http,
            resolve,
            host,
            port,
        })
    }

    pub fn scheme(&self) -> &str {
        if self.loopback_http { "http" } else { "https" }
    }

    fn same_origin(&self, other: &Self) -> bool {
        let host = |name: &str| name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
        self.port == other.port && host(&self.host) == host(&other.host)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Primary = 0,
    Backup = 1,
}

pub struct Config {
    pub listen: SocketAddrV4,
    pub metrics_port: u16,
    pub primary: Endpoint,
    pub backup: Option<Endpoint>,
    pub version: HttpVersion,
    pub ca_file: Option<PathBuf>,
    pub padding: bool,
    pub udp_cap: u16,
    pub host_connections: usize,
    pub per_source: usize,
    pub cache_entries: usize,
    pub tcp_idle: Duration,
    pub tcp_io: Duration,
    pub connect: Duration,
    pub timeout: Duration,
}

impl Config {
    pub fn endpoint(&self, role: Role) -> &Endpoint {
        match role {
            Role::Primary => &self.primary,
            Role::Backup => self
                .backup
                .as_ref()
                .expect("backup role requires a configured endpoint"),
        }
    }

    pub fn preference(&self) -> &str {
        match self.version {
            HttpVersion::V3 => "h3",
            HttpVersion::V2TLS if !self.primary.loopback_http => "h2",
            _ => "http/1.1",
        }
    }

    pub fn usage() -> &'static str {
        USAGE
    }

    pub fn parse(args: impl Iterator<Item = OsString>) -> Result<Option<Self>, String> {
        let mut args = args;
        let mut ip = Ipv4Addr::LOCALHOST.to_string();
        let mut port = 5300;
        let mut metrics_port = 0;
        let mut primary = String::from("https://cloudflare-dns.com/dns-query");
        let mut backup = None;
        let mut bootstrap = None;
        let mut backup_bootstrap = None;
        let mut ca_file = None;
        let mut padding = false;
        let mut prefer_h3 = false;
        let mut host_connections = 8;
        let mut per_source = 32;
        let mut cache_entries = 0;
        let mut udp_cap = wire::UDP_REPLY_DEFAULT;
        let mut tcp_idle = Duration::from_secs(15);
        let mut tcp_io = Duration::from_secs(15);
        let mut connect = Duration::from_millis(1500);
        let mut timeout = Duration::from_secs(3);

        while let Some(arg) = args.next() {
            let option = arg.to_str().ok_or(USAGE)?;
            match option {
                "-h" | "--help" => return Ok(None),
                "--edns-padding" => {
                    padding = true;
                    continue;
                }
                _ => {}
            }
            if option == "--ca-file" {
                ca_file = Some(PathBuf::from(args.next().ok_or(USAGE)?));
                continue;
            }
            let (option, value) = if let Some(mode) = option.strip_prefix("--upstream-http=") {
                ("--upstream-http", mode.to_owned())
            } else {
                let value = args
                    .next()
                    .ok_or(match option {
                        "--bootstrap-address" => {
                            "--bootstrap-address requires an IPv4 or IPv6 address"
                        }
                        "--upstream-http" => "--upstream-http requires auto or prefer-h3",
                        _ => USAGE,
                    })?
                    .into_string()
                    .map_err(|_| format!("invalid {option}"))?;
                (option, value)
            };
            let range = |min, max| -> Result<u64, String> {
                let n = value
                    .trim_start()
                    .parse::<u64>()
                    .ok()
                    .filter(|n| (min..=max).contains(n));
                n.ok_or_else(|| format!("invalid {option} ({min}..{max})"))
            };
            match option {
                "-l" => ip = value,
                "-p" => port = range(1, 65535).map_err(|_| "invalid port")? as u16,
                "-m" => metrics_port = range(1, 65535).map_err(|_| "invalid port")? as u16,
                "-s" => primary = value,
                "--backup-upstream" => backup = Some(value),
                "--bootstrap-address" => bootstrap = Some(value),
                "--backup-bootstrap-address" => backup_bootstrap = Some(value),
                "--upstream-http" => {
                    prefer_h3 = match value.as_str() {
                        "auto" => false,
                        "prefer-h3" => true,
                        _ => return Err("--upstream-http requires auto or prefer-h3".into()),
                    }
                }
                "--max-host-connections" => host_connections = range(1, 16)? as usize,
                "--tcp-max-per-source" => per_source = range(1, MAX_CLIENTS as u64)? as usize,
                "--tcp-idle-ms" => tcp_idle = Duration::from_millis(range(100, 600_000)?),
                "--tcp-io-ms" => tcp_io = Duration::from_millis(range(100, 600_000)?),
                "--doh-connect-ms" => connect = Duration::from_millis(range(100, 60_000)?),
                "--doh-timeout-ms" => timeout = Duration::from_millis(range(100, 60_000)?),
                "--cache-entries" => cache_entries = range(0, MAX_CACHE as u64)? as usize,
                "--udp-reply-max" => udp_cap = range(512, wire::UDP_REPLY_MAX.into())? as u16,
                _ => return Err(USAGE.into()),
            }
        }
        if port == metrics_port {
            return Err("invalid port".into());
        }
        if connect > timeout {
            return Err("--doh-connect-ms must be no greater than --doh-timeout-ms".into());
        }
        if backup_bootstrap.is_some() && backup.is_none() {
            return Err("--backup-bootstrap-address requires --backup-upstream".into());
        }
        let lib = Version::get();
        let version = if prefer_h3 {
            if lib.version_num() < 0x07_58_00 || !lib.feature_http3() {
                return Err("--upstream-http=prefer-h3 requires libcurl with HTTP/3 support and TCP fallback (7.88.0 or newer)".into());
            }
            HttpVersion::V3
        } else if lib.feature_http2() {
            HttpVersion::V2TLS
        } else {
            HttpVersion::V11
        };
        let primary =
            Endpoint::new(primary, bootstrap.as_deref()).ok_or(if bootstrap.is_some() {
                "--bootstrap-address requires a numeric IP and an HTTPS upstream hostname"
            } else {
                "invalid upstream (only HTTPS or loopback HTTP test endpoint)"
            })?;
        let backup = match backup {
            Some(url) => Some(
                Endpoint::new(url, backup_bootstrap.as_deref())
                    .ok_or("invalid --backup-upstream or --backup-bootstrap-address")?,
            ),
            None => None,
        };
        if backup
            .as_ref()
            .is_some_and(|endpoint| primary.same_origin(endpoint))
        {
            return Err(
                "--backup-upstream requires a different host or port from the primary".into(),
            );
        }
        if prefer_h3
            && (primary.loopback_http || backup.as_ref().is_some_and(|ep| ep.loopback_http))
        {
            return Err(
                "--upstream-http=prefer-h3 requires an HTTPS upstream for each configured endpoint"
                    .into(),
            );
        }
        let address = ip
            .parse::<Ipv4Addr>()
            .map_err(|_| "invalid DNS bind address (expected IPv4)")?;
        Ok(Some(Self {
            listen: SocketAddrV4::new(address, port),
            metrics_port,
            primary,
            backup,
            version,
            ca_file,
            padding,
            udp_cap,
            host_connections,
            per_source,
            cache_entries,
            tcp_idle,
            tcp_io,
            connect,
            timeout,
        }))
    }
}
