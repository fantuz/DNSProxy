use std::mem;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use curl::easy::{Easy2, Handler, HttpVersion, WriteError};
use curl::multi::{Easy2Handle, Events, Multi, Socket};
use curl::{MultiError, Version};
use curl_sys as sys;

use crate::config::{Config, Role};
use crate::native::{self, HeaderList, LongInfo, TimeInfo};
use crate::wire;

const MAX_WATCHES: usize = 1024;
const EASY_POOL: usize = 16;
const HTTP3_ERROR: sys::CURLcode = 95;

pub struct Headers {
    pub age: u32,
    pub max_age: u32,
    pub blocked: bool,
    age_seen: bool,
    date_seen: bool,
    date: Option<i64>,
}

impl Default for Headers {
    fn default() -> Self {
        Self {
            age: 0,
            max_age: u32::MAX,
            blocked: false,
            age_seen: false,
            date_seen: false,
            date: None,
        }
    }
}

fn trim_header(mut bytes: &[u8]) -> &[u8] {
    while matches!(bytes.first(), Some(b' ' | b'\t')) {
        bytes = &bytes[1..];
    }
    while matches!(bytes.last(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn header_uint(value: &[u8]) -> Option<u32> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(value).ok()?.parse().ok()
}

impl Headers {
    fn cache_control(&mut self, value: &[u8]) {
        // A final comma was ignored by the reference. An empty header or an
        // empty directive between commas still blocks shared reuse.
        let value = value.strip_suffix(b",").unwrap_or(value);
        for token in value.split(|&b| b == b',') {
            let token = trim_header(token);
            if token.eq_ignore_ascii_case(b"public") {
                continue;
            }
            let limit = [b"max-age=".as_slice(), b"s-maxage="]
                .into_iter()
                .find(|key| {
                    token
                        .get(..key.len())
                        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(key))
                })
                .and_then(|key| header_uint(&token[key.len()..]));
            if let Some(limit) = limit {
                self.max_age = self.max_age.min(limit);
            } else {
                self.blocked = true;
            }
        }
    }

    fn read(&mut self, line: &[u8]) {
        if line.starts_with(b"HTTP/") {
            *self = Self::default();
            return;
        }
        let Some(at) = line.iter().position(|&b| b == b':') else {
            return;
        };
        let name = &line[..at];
        let value = trim_header(&line[at + 1..]);
        if name.eq_ignore_ascii_case(b"Age") {
            match header_uint(value) {
                Some(age) if !self.age_seen => self.age = age,
                _ => self.blocked = true,
            }
            self.age_seen = true;
        } else if name.eq_ignore_ascii_case(b"Cache-Control") {
            self.cache_control(value);
        } else if name.eq_ignore_ascii_case(b"Date") {
            if self.date_seen || value.len() >= 64 {
                self.blocked = true;
            } else {
                self.date = native::http_date(value);
                self.blocked |= self.date.is_none();
            }
            self.date_seen = true;
        } else if name.eq_ignore_ascii_case(b"Vary") {
            self.blocked |= !value.eq_ignore_ascii_case(b"Accept");
        } else if [b"Expires".as_slice(), b"Pragma", b"Set-Cookie"]
            .iter()
            .any(|key| name.eq_ignore_ascii_case(key))
        {
            self.blocked = true;
        }
    }

    pub fn age_ms(&self, transfer_us: u64) -> u64 {
        let corrected = u64::from(self.age) * 1000 + transfer_us / 1000;
        let apparent = self
            .date
            .and_then(|date| {
                let seconds = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
                let seconds = (seconds as i64)
                    .saturating_sub(date)
                    .clamp(0, i64::from(u32::MAX));
                Some(seconds as u64 * 1000)
            })
            .unwrap_or_default();
        corrected.max(apparent)
    }
}

#[derive(Default)]
pub struct Collector {
    body: Vec<u8>,
    headers: Headers,
    post: Option<Rc<Vec<u8>>>,
    request_headers: Option<Rc<HeaderList>>,
    resolve: Option<Rc<HeaderList>>,
}

impl Handler for Collector {
    fn write(&mut self, data: &[u8]) -> Result<usize, WriteError> {
        let required = self.body.len().saturating_add(data.len());
        if required > wire::TCP_MAX {
            return Ok(0);
        }
        if required > self.body.capacity() {
            let mut cap = self.body.capacity().max(512);
            while cap < required {
                cap *= 2;
            }
            let cap = cap.min(wire::TCP_MAX);
            if self.body.try_reserve_exact(cap - self.body.len()).is_err() {
                return Ok(0);
            }
        }
        self.body.extend_from_slice(data);
        Ok(data.len())
    }

    fn header(&mut self, data: &[u8]) -> bool {
        self.headers.read(data);
        true
    }
}

#[derive(Clone, Copy)]
pub struct Watch {
    pub fd: Socket,
    pub flags: i16,
    pub generation: u64,
}

#[derive(Default)]
struct CallbackState {
    watches: Vec<Watch>,
    generation: u64,
    timer: Option<u64>,
    socket_calls: u64,
    timer_calls: u64,
    watch_limit_exceeded: bool,
}

impl CallbackState {
    fn watch(&mut self, fd: Socket, flags: Option<i16>) {
        let slot = self.watches.iter().position(|watch| watch.fd == fd);
        let Some(flags) = flags else {
            if let Some(slot) = slot {
                self.watches.swap_remove(slot);
            }
            return;
        };
        if slot.is_some_and(|i| self.watches[i].flags == flags) {
            return;
        }
        if slot.is_none() && self.watches.len() == MAX_WATCHES {
            // The Rust binding's socket callback returns void. Stop the
            // loop after this native action instead of losing a watch.
            self.watch_limit_exceeded = true;
            return;
        }
        self.generation = self.generation.wrapping_add(1);
        let watch = Watch {
            fd,
            flags,
            generation: self.generation,
        };
        if let Some(slot) = slot {
            self.watches[slot] = watch;
        } else {
            self.watches.push(watch);
        }
    }

    fn current(&self, watch: Watch) -> bool {
        self.watches
            .iter()
            .any(|current| current.fd == watch.fd && current.generation == watch.generation)
    }
}

pub struct Engine {
    multi: Multi,
    callbacks: Arc<Mutex<CallbackState>>,
    headers: Rc<HeaderList>,
    resolve: [Option<Rc<HeaderList>>; 2],
    idle: Vec<Easy2<Collector>>,
    openssl: bool,
}

pub struct Transfer {
    pub code: sys::CURLcode,
    pub status: libc::c_long,
    pub version: libc::c_long,
    pub connects: u64,
    pub content_type_ok: bool,
    pub total_us: u64,
    pub phases: [Option<u64>; 3],
    pub body: Vec<u8>,
    pub headers: Headers,
    pub backup_safe: bool,
}

impl Engine {
    pub fn new(config: &Config) -> Result<Self, Box<dyn std::error::Error>> {
        let mut multi = Multi::new();
        multi.set_max_total_connections(16)?;
        multi.set_max_host_connections(config.host_connections)?;
        let https = !config.primary.loopback_http
            || config.backup.as_ref().is_some_and(|ep| !ep.loopback_http);
        multi.pipelining(false, https && !matches!(config.version, HttpVersion::V11))?;
        let callbacks = Arc::new(Mutex::new(CallbackState::default()));
        let state = Arc::clone(&callbacks);
        multi.socket_function(move |fd, event, _| {
            let mut state = state.lock().expect("socket callback lock");
            state.socket_calls += 1;
            let flags = (if event.input() { libc::POLLIN } else { 0 })
                | (if event.output() { libc::POLLOUT } else { 0 });
            state.watch(fd, (!event.remove()).then_some(flags));
        })?;
        let state = Arc::clone(&callbacks);
        multi.timer_function(move |timeout| {
            let mut state = state.lock().expect("timer callback lock");
            state.timer_calls += 1;
            state.timer = timeout
                .map(|delay| native::monotonic_millis().saturating_add(delay.as_millis() as u64));
            true
        })?;
        let headers = Rc::new(HeaderList::new(&[
            "Content-Type: application/dns-message",
            "Accept: application/dns-message",
        ])?);
        let mut resolve = [None, None];
        for (slot, endpoint) in [Some(&config.primary), config.backup.as_ref()]
            .into_iter()
            .enumerate()
        {
            if let Some(entry) = endpoint.and_then(|ep| ep.resolve.as_deref()) {
                resolve[slot] = Some(Rc::new(HeaderList::new(&[entry])?));
            }
        }
        let openssl = Version::get()
            .ssl_version()
            .is_some_and(|ssl| ssl.starts_with("OpenSSL/"));
        Ok(Self {
            multi,
            callbacks,
            headers,
            resolve,
            idle: Vec::with_capacity(EASY_POOL),
            openssl,
        })
    }

    pub fn start(
        &mut self,
        config: &Config,
        role: Role,
        post: Rc<Vec<u8>>,
        timeout: Duration,
        token: usize,
    ) -> (Result<Easy2Handle<Collector>, sys::CURLcode>, bool) {
        let (mut easy, reused) = match self.idle.pop() {
            Some(easy) => (easy, true),
            None => (Easy2::new(Collector::default()), false),
        };
        let endpoint = config.endpoint(role);
        let version = if endpoint.loopback_http {
            HttpVersion::V11
        } else {
            config.version
        };
        *easy.get_mut() = Collector {
            post: Some(post),
            request_headers: Some(Rc::clone(&self.headers)),
            resolve: self.resolve[role as usize].clone(),
            ..Collector::default()
        };
        let setup = (|| -> Result<(), curl::Error> {
            easy.url(&endpoint.url)?;
            if endpoint.loopback_http || endpoint.resolve.is_some() {
                easy.proxy("")?;
            }
            easy.http_version(version)?;
            if !matches!(version, HttpVersion::V11) {
                easy.pipewait(true)?;
            }
            easy.tcp_keepalive(true)?;
            easy.timeout(timeout)?;
            easy.connect_timeout(config.connect)?;
            easy.ssl_verify_peer(true)?;
            easy.ssl_verify_host(true)?;
            if let Some(ca) = &config.ca_file {
                easy.cainfo(ca)?;
            }
            easy.follow_location(false)?;
            easy.signal(false)?;
            let held = easy.get_ref();
            // SAFETY: POST bytes and both lists are immutable and retained in
            // this easy's handler until after reset or native cleanup.
            unsafe {
                if let Some(resolve) = &held.resolve {
                    resolve.attach(&easy, sys::CURLOPT_RESOLVE)?;
                }
                held.request_headers
                    .as_ref()
                    .expect("header list")
                    .attach(&easy, sys::CURLOPT_HTTPHEADER)?;
                native::post(&easy, held.post.as_ref().expect("POST bytes"))?;
            }
            Ok(())
        })();
        if let Err(error) = setup {
            return (Err(error.code()), reused);
        }
        let result = self
            .multi
            .add2(easy)
            .map_err(|_| sys::CURLE_FAILED_INIT)
            .and_then(|mut handle| {
                handle.set_token(token).map_err(|error| error.code())?;
                Ok(handle)
            });
        (result, reused)
    }

    pub fn recycle(&mut self, handle: Easy2Handle<Collector>) -> Result<(), MultiError> {
        let mut easy = self.multi.remove2(handle)?;
        if self.idle.len() < EASY_POOL {
            easy.reset();
            *easy.get_mut() = Collector::default();
            self.idle.push(easy);
        }
        Ok(())
    }

    pub fn metadata(
        &self,
        config: &Config,
        handle: &mut Easy2Handle<Collector>,
        code: sys::CURLcode,
    ) -> Transfer {
        let status = native::get_long(handle, LongInfo::Status).unwrap_or_default();
        let proxy_status = native::get_long(handle, LongInfo::ProxyStatus).unwrap_or_default();
        let verify = native::get_long(handle, LongInfo::Verify);
        let proxy_verify = native::get_long(handle, LongInfo::ProxyVerify);
        let connects = native::get_long(handle, LongInfo::Connections)
            .unwrap_or_default()
            .max(0) as u64;
        let connected = native::get_micros(handle, TimeInfo::Connect);
        let handshake = native::get_micros(handle, TimeInfo::Tls);
        let quic_pending = matches!(config.version, HttpVersion::V3)
            && self.openssl
            && status == 0
            && proxy_status == 0
            && matches!(
                code,
                sys::CURLE_COULDNT_CONNECT | sys::CURLE_OPERATION_TIMEDOUT
            )
            && connected == Some(0)
            && handshake == Some(0);
        let backup_safe = status < 300
            && proxy_status < 300
            && proxy_verify == Some(0)
            && (verify == Some(0) || (verify == Some(1) && quic_pending))
            && retryable(code);
        let queue = native::get_micros(handle, TimeInfo::Queue);
        let tls = connected
            .zip(handshake)
            .filter(|&(connected, _)| connects > 0 && connected > 0)
            .and_then(|(connected, handshake)| handshake.checked_sub(connected));
        let first_byte = native::get_micros(handle, TimeInfo::Ready)
            .zip(native::get_micros(handle, TimeInfo::FirstByte))
            .filter(|&(ready, _)| ready > 0)
            .and_then(|(ready, first)| first.checked_sub(ready));
        Transfer {
            code,
            status,
            connects,
            backup_safe,
            phases: [queue, tls, first_byte],
            version: native::get_long(handle, LongInfo::HttpVersion).unwrap_or_default(),
            content_type_ok: native::dns_content_type(handle),
            total_us: native::get_micros(handle, TimeInfo::Total).unwrap_or_default(),
            body: mem::take(&mut handle.get_mut().body),
            headers: mem::take(&mut handle.get_mut().headers),
        }
    }

    pub fn timer(&self) -> Option<u64> {
        self.callbacks.lock().expect("curl callback lock").timer
    }

    pub fn watches(&self, out: &mut Vec<Watch>) {
        out.clear();
        out.extend_from_slice(&self.callbacks.lock().expect("curl callback lock").watches);
    }

    pub fn counters(&self) -> (u64, u64, usize) {
        let state = self.callbacks.lock().expect("curl callback lock");
        (state.socket_calls, state.timer_calls, state.watches.len())
    }

    pub fn action(&self, watch: Watch, ready: i16) -> Result<(), String> {
        let matches = self
            .callbacks
            .lock()
            .expect("curl callback lock")
            .current(watch);
        if matches {
            let mut events = Events::new();
            events
                .input(ready & libc::POLLIN != 0)
                .output(ready & libc::POLLOUT != 0)
                .error(ready & native::POLL_ERROR != 0);
            self.multi
                .action(watch.fd, &events)
                .map_err(|err| err.to_string())?;
        }
        self.check_capacity()
    }

    pub fn timeout(&self) -> Result<(), String> {
        self.multi.timeout().map_err(|err| err.to_string())?;
        self.check_capacity()
    }

    pub fn check_capacity(&self) -> Result<(), String> {
        if self
            .callbacks
            .lock()
            .expect("curl callback lock")
            .watch_limit_exceeded
        {
            Err("libcurl socket watch capacity reached".into())
        } else {
            Ok(())
        }
    }

    pub fn completions(&self, out: &mut Vec<(usize, sys::CURLcode)>) {
        out.clear();
        self.multi.messages(|msg| {
            if let (Ok(token), Some(result)) = (msg.token(), msg.result()) {
                out.push((token, result.err().map_or(sys::CURLE_OK, |err| err.code())));
            }
        });
    }
}

fn retryable(code: sys::CURLcode) -> bool {
    matches!(
        code,
        sys::CURLE_COULDNT_RESOLVE_HOST
            | sys::CURLE_COULDNT_CONNECT
            | sys::CURLE_OPERATION_TIMEDOUT
            | sys::CURLE_GOT_NOTHING
            | sys::CURLE_SEND_ERROR
            | sys::CURLE_RECV_ERROR
            | sys::CURLE_PARTIAL_FILE
            | sys::CURLE_HTTP2_STREAM
            | HTTP3_ERROR
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interim_headers_get_replaced() {
        let mut policy = Headers::default();
        policy.read(b"Age: 999\r\n");
        policy.read(b"Cache-Control: private\r\n");
        policy.read(b"HTTP/2 200\r\n");
        policy.read(b"Cache-Control: public, max-age=200, s-maxage=100\r\n");
        policy.read(b"Age: 2\r\n");
        policy.read(b"Vary: Accept\r\n");
        assert!(!policy.blocked);
        assert_eq!(policy.max_age, 100);
        assert_eq!(policy.age_ms(51_000), 2051);
        policy.read(b"Age: 0\r\n");
        assert!(policy.blocked);
        assert_eq!(policy.age, 2);
    }

    #[test]
    fn unsafe_http_reuse_is_denied() {
        for header in [
            b"Cache-Control: no-store".as_slice(),
            b"Cache-Control: max-age=4294967296",
            b"Cache-Control: public,, max-age=2",
            b"Vary: *",
            b"Set-Cookie: a=b",
            b"Age: -1",
            b"Date: invalid",
        ] {
            let mut policy = Headers::default();
            policy.read(header);
            assert!(policy.blocked, "{header:?}");
        }
    }

    #[test]
    fn failover_error_allowlist() {
        assert!(retryable(sys::CURLE_HTTP2_STREAM));
        assert!(retryable(HTTP3_ERROR));
        assert!(retryable(sys::CURLE_OPERATION_TIMEDOUT));
        assert!(!retryable(sys::CURLE_PEER_FAILED_VERIFICATION));
        assert!(!retryable(sys::CURLE_WRITE_ERROR));
        assert!(!retryable(sys::CURLE_OK));
    }
}

#[cfg(test)]
mod callback_tests {
    use super::*;

    #[test]
    fn obsolete_socket_events_are_rejected() {
        let mut state = CallbackState::default();
        state.watch(5, Some(libc::POLLIN));
        let initial = state.watches[0];
        state.watch(5, Some(libc::POLLIN));
        assert!(state.current(initial));
        state.watch(5, None);
        assert!(!state.current(initial));
        state.watch(5, Some(libc::POLLIN));
        let reused = state.watches[0];
        assert!(state.current(reused));
        assert!(!state.current(initial));
        state.watch(5, Some(libc::POLLOUT));
        assert!(!state.current(reused));
    }

    #[test]
    fn socket_watch_limit_is_bounded() {
        let mut state = CallbackState::default();
        for fd in 0..MAX_WATCHES {
            state.watch(fd as Socket, Some(libc::POLLIN));
        }
        assert!(!state.watch_limit_exceeded);
        state.watch(MAX_WATCHES as Socket, Some(libc::POLLIN));
        assert!(state.watch_limit_exceeded);
        assert_eq!(state.watches.len(), MAX_WATCHES);
    }

    #[test]
    fn collect_is_bounded_and_preserves_previous_bytes() {
        let mut collector = Collector::default();
        assert_eq!(collector.write(b"").unwrap(), 0);
        assert!(collector.body.is_empty());
        assert_eq!(collector.write(b"dns").unwrap(), 3);
        let body = vec![1; wire::TCP_MAX - 3];
        assert_eq!(collector.write(&body).unwrap(), body.len());
        assert_eq!(collector.write(b"!").unwrap(), 0);
        assert_eq!(collector.body.len(), wire::TCP_MAX);
        assert_eq!(&collector.body[..3], b"dns");
    }
}
