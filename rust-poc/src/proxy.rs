use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use curl::multi::Easy2Handle;
use curl_sys as sys;

use crate::cache::Cache;
use crate::client::{
    Client, METRIC_IDLE, METRIC_LIMIT, MetricClient, MetricRead, ReadEvent, WriteEvent,
};
use crate::config::{Config, MAX_ACTIVE, MAX_CLIENTS, MAX_WAITERS, Role};
use crate::doh::{Collector, Engine, Transfer, Watch};
use crate::metrics::{Failure, Metrics, RateLog, enabled};
use crate::{native, wire};

#[derive(Clone, Copy)]
enum Target {
    Udp(SocketAddrV4, native::UdpLocal),
    Tcp(usize),
}

impl Target {
    fn tcp(self) -> bool {
        matches!(self, Self::Tcp(_))
    }
}

struct Waiter {
    peer: SocketAddrV4,
    local: native::UdpLocal,
    id: u16,
    deadline: Instant,
}

struct Query {
    request: Rc<Vec<u8>>,
    padded: Option<Rc<Vec<u8>>>,
    info: wire::Info,
    target: Target,
    role: Role,
    cache_slot: Option<usize>,
    shareable: bool,
    waiters: Vec<Waiter>,
    failover_deadline: Option<Instant>,
}

impl Query {
    fn post(&self, cfg: &Config) -> (&Rc<Vec<u8>>, bool) {
        if !cfg.endpoint(self.role).loopback_http {
            if let Some(padded) = &self.padded {
                return (padded, true);
            }
        }
        (&self.request, false)
    }
}

struct Active {
    query: Query,
    handle: Easy2Handle<Collector>,
    padded: bool,
}

#[derive(Clone, Copy)]
enum Interest {
    Udp,
    TcpListen,
    MetricsListen,
    Tcp(usize),
    Metrics(usize),
    Curl(Watch),
}

pub struct Proxy {
    cfg: Config,
    udp: UdpSocket,
    tcp: TcpListener,
    metrics_listener: Option<TcpListener>,
    clients: BTreeMap<usize, Client>,
    metrics_clients: BTreeMap<usize, MetricClient>,
    active: BTreeMap<usize, Active>,
    engine: Engine,
    cache: Cache,
    metrics: Metrics,
    logs: RateLog,
    next_id: usize,
}

impl Proxy {
    pub fn new(cfg: Config) -> Result<Self, String> {
        let engine =
            Engine::new(&cfg).map_err(|err| format!("event=curl_multi_init message={err}"))?;
        let bind_error = |role, addr: SocketAddrV4, error: io::Error| {
            format!(
                "event=listener_failed role={role} port={} errno={} message={error}",
                addr.port(),
                error.raw_os_error().unwrap_or_default()
            )
        };
        let udp = native::udp_listener(cfg.listen)
            .map_err(|err| bind_error("dns_udp", cfg.listen, err))?;
        let tcp = native::tcp_listener(cfg.listen)
            .map_err(|err| bind_error("dns_tcp", cfg.listen, err))?;
        let metrics_listener = if cfg.metrics_port != 0 {
            let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, cfg.metrics_port);
            Some(native::tcp_listener(addr).map_err(|err| bind_error("metrics", addr, err))?)
        } else {
            None
        };
        let cache = Cache::new(cfg.cache_entries);
        Ok(Self {
            cfg,
            udp,
            tcp,
            metrics_listener,
            clients: BTreeMap::new(),
            metrics_clients: BTreeMap::new(),
            active: BTreeMap::new(),
            engine,
            cache,
            metrics: Metrics::default(),
            logs: RateLog::default(),
            next_id: 0,
        })
    }

    fn id(&mut self) -> usize {
        // A monotonically increasing token identifies an owned client or
        // query independently of file descriptor reuse.
        self.next_id = self
            .next_id
            .checked_add(1)
            .expect("process token space exhausted");
        self.next_id
    }

    fn record_query(&mut self, target: Target) {
        match target {
            Target::Udp(_, _) => self.metrics.udp_queries += 1,
            Target::Tcp(id) => {
                if let Some(client) = self.clients.get_mut(&id) {
                    if client.queries > 0 {
                        self.metrics.tcp_keepalive_queries += 1;
                    }
                    client.queries += 1;
                    self.metrics.tcp_queries += 1;
                }
            }
        }
    }

    fn reply(&mut self, target: Target, waiters: &[Waiter], response: &[u8], satisfies: bool) {
        match target {
            Target::Tcp(id) => {
                if let Some(client) = self.clients.get_mut(&id) {
                    if !client.queue(response, satisfies, self.cfg.tcp_io) {
                        self.logs
                            .warn(Failure::TcpBuffer, true, sys::CURLE_OUT_OF_MEMORY, 0, None, 0);
                    }
                }
            }
            Target::Udp(peer, local) => {
                if native::send_udp_with_id(&self.udp, peer, local, wire::u16_at(response, 0), &response[2..]).ok() == Some(response.len()) && satisfies {
                    self.metrics.queries_satisfied += 1;
                }
                for waiter in waiters {
                    if native::send_udp_with_id(&self.udp, waiter.peer, waiter.local, waiter.id, &response[2..])
                        .ok()
                        == Some(response.len())
                        && satisfies
                    {
                        self.metrics.queries_satisfied += 1;
                    }
                }
            }
        }
    }

    fn local_error(
        &mut self,
        target: Target,
        waiters: &[Waiter],
        request: &[u8],
        info: &wire::Info,
        code: u8,
    ) {
        self.reply(
            target,
            waiters,
            &wire::error_reply(request, info, code),
            false,
        );
    }

    fn join(&mut self, peer: SocketAddrV4, local: native::UdpLocal, request: &[u8]) -> bool {
        let id = wire::u16_at(request, 0);
        let mut available = None;
        for (&token, active) in self.active.iter().rev() {
            let q = &active.query;
            if !q.shareable || q.request[2..] != request[2..] {
                continue;
            }
            if matches!(q.target, Target::Udp(leader, address) if leader == peer && address.destination == local.destination && wire::u16_at(&q.request, 0) == id)
                || q.waiters.iter().any(|w| w.peer == peer && w.local.destination == local.destination && w.id == id)
            {
                return true;
            }
            if available.is_none() && q.waiters.len() < MAX_WAITERS {
                available = Some(token);
            }
        }
        let Some(token) = available else {
            return false;
        };
        self.active
            .get_mut(&token)
            .expect("coalescing candidate remains active")
            .query
            .waiters
            .push(Waiter {
                peer,
                local,
                id,
                deadline: Instant::now() + self.cfg.timeout,
            });
        true
    }

    fn start(&mut self, query: Query, token: usize, timeout: Duration) -> Result<(), Box<Query>> {
        let (post, padded) = query.post(&self.cfg);
        let (result, reused) =
            self.engine
                .start(&self.cfg, query.role, Rc::clone(post), timeout, token);
        self.metrics.easy_reused += u64::from(reused);
        match result {
            Ok(handle) => {
                self.metrics.upstream_requests += 1;
                self.metrics.endpoints[query.role as usize].requests += 1;
                if let Target::Tcp(id) = query.target {
                    self.clients.get_mut(&id).expect("TCP target is open").busy = Some(token);
                }
                self.active.insert(
                    token,
                    Active {
                        query,
                        handle,
                        padded,
                    },
                );
                Ok(())
            }
            Err(code) => {
                self.logs.warn(Failure::Setup, query.target.tcp(), code, 0, Some(query.role), 0);
                Err(Box::new(query))
            }
        }
    }

    fn submit(
        &mut self,
        request: Cow<'_, [u8]>,
        target: Target,
        role: Role,
        deadline: Option<Instant>,
    ) -> bool {
        let (status, info) = wire::parse(&request, None, self.cfg.udp_cap);
        match status {
            wire::Status::Drop => {
                self.metrics.invalid_queries += 1;
                return false;
            }
            wire::Status::FormErr | wire::Status::NotImp => {
                if status == wire::Status::FormErr {
                    self.metrics.invalid_queries += 1;
                }
                self.local_error(
                    target,
                    &[],
                    &request,
                    &info,
                    if status == wire::Status::FormErr {
                        1
                    } else {
                        4
                    },
                );
                return true;
            }
            wire::Status::Ok => {}
        }
        let now = Instant::now();
        let mut timeout = self.cfg.timeout;
        if let Some(deadline) = deadline {
            if now >= deadline {
                self.local_error(target, &[], &request, &info, 2);
                return true;
            }
            timeout = self.cfg.timeout.min(deadline.duration_since(now));
        }
        let cache_slot = if deadline.is_none() && role == Role::Primary {
            self.cache.index(&request, &info)
        } else {
            None
        };
        if let Some(slot) = cache_slot {
            if let Some(response) =
                self.cache
                    .lookup(slot, &request, (!target.tcp()).then_some(info.udp_limit))
            {
                self.reply(target, &[], &response, true);
                self.metrics.cache_hits += 1;
                self.record_query(target);
                return true;
            }
            self.metrics.cache_misses += 1;
        }
        let shareable = deadline.is_none()
            && !target.tcp()
            && wire::u16_at(&request, 10) == 0
            && wire::plain_address(&request, &info);
        if let Target::Udp(peer, local) = target {
            if shareable && self.join(peer, local, &request) {
                self.metrics.udp_queries_coalesced += 1;
                self.record_query(target);
                return true;
            }
        }
        if self.active.len() >= MAX_ACTIVE {
            self.logs
                .warn(Failure::Capacity, target.tcp(), sys::CURLE_OK, 0, None, 0);
            self.metrics.overload += 1;
            self.local_error(target, &[], &request, &info, 2);
            return true;
        }
        let mut failover_deadline = None;
        if role == Role::Primary
            && self.cfg.backup.is_some()
            && wire::failover_eligible(&request, &info)
            && timeout.as_millis() > 1
        {
            failover_deadline = Some(deadline.unwrap_or(now + timeout));
            timeout = Duration::from_millis(timeout.as_millis() as u64 / 2);
        }
        let https = !self.cfg.endpoint(role).loopback_http
            || (failover_deadline.is_some()
                && self.cfg.backup.as_ref().is_some_and(|ep| !ep.loopback_http));
        let padded = if self.cfg.padding && https {
            wire::padded_query(&request, &info).map(Rc::new)
        } else {
            None
        };
        let query = Query {
            request: Rc::new(request.into_owned()),
            padded,
            info,
            target,
            role,
            cache_slot,
            shareable,
            waiters: Vec::new(),
            failover_deadline,
        };
        let token = self.id();
        if let Err(query) = self.start(query, token, curl_timeout(timeout)) {
            self.metrics.overload += 1;
            self.local_error(target, &[], &query.request, &query.info, 2);
        } else if deadline.is_none() {
            self.record_query(target);
        }
        true
    }

    fn recycle(&mut self, handle: Easy2Handle<Collector>) -> Result<(), String> {
        self.engine
            .recycle(handle)
            .map_err(|err| format!("event=curl_multi_remove message={err}"))
    }

    fn finish_tcp(&mut self, target: Target) -> Result<(), String> {
        if let Target::Tcp(id) = target {
            if let Some(client) = self.clients.get_mut(&id) {
                client.busy = None;
                if !client.has_reply() {
                    self.close_tcp(id)?;
                }
            }
        }
        Ok(())
    }

    fn complete(&mut self, token: usize, code: sys::CURLcode) -> Result<(), String> {
        let Some(Active {
            mut query,
            mut handle,
            padded,
        }) = self.active.remove(&token)
        else {
            return Ok(());
        };
        let mut transfer = self.engine.metadata(&self.cfg, &mut handle, code);
        self.metrics.record_transfer(&transfer);
        self.recycle(handle)?;

        match validate(&query, &transfer, self.cfg.udp_cap) {
            Ok(info) => {
                if padded {
                    wire::strip_padding(&mut transfer.body, &info);
                }
                self.metrics.upstream_ok += 1;
                self.metrics.endpoints[query.role as usize].replies += 1;
                let age_ms = transfer.headers.age_ms(transfer.total_us);
                let reusable = transfer.status == 200
                    && !transfer.headers.blocked
                    && !info.signed
                    && age_ms < u64::from(transfer.headers.max_age) * 1000;
                let retry_waiters = if reusable {
                    if let Some(slot) = query.cache_slot {
                        self.cache.store(
                            slot,
                            &query.request,
                            &transfer.body,
                            &info,
                            age_ms,
                            transfer.headers.max_age,
                        );
                    }
                    Vec::new()
                } else {
                    std::mem::take(&mut query.waiters)
                };
                wire::age_forwarded(&mut transfer.body, &info, transfer.headers.age);
                if !query.target.tcp() && transfer.body.len() > query.info.udp_limit {
                    let response =
                        wire::truncated_reply(&query.request, &query.info, &transfer.body, &info);
                    self.metrics.truncated += 1;
                    self.reply(query.target, &query.waiters, &response, false);
                } else {
                    let satisfies = wire::satisfies(&transfer.body, &info);
                    self.reply(query.target, &query.waiters, &transfer.body, satisfies);
                }
                self.finish_tcp(query.target)?;
                if !retry_waiters.is_empty() {
                    let mut request = query.request.as_ref().clone();
                    for waiter in retry_waiters {
                        request[..2].copy_from_slice(&waiter.id.to_be_bytes());
                        self.submit(
                            Cow::Borrowed(&request),
                            Target::Udp(waiter.peer, waiter.local),
                            query.role,
                            Some(waiter.deadline),
                        );
                    }
                }
            }
            Err(failure) => {
                self.metrics.upstream_failed += 1;
                self.metrics.endpoints[query.role as usize].failures += 1;
                if matches!(failure, Failure::Timeout) {
                    self.metrics.upstream_timeouts += 1;
                }
                if matches!(failure, Failure::Content | Failure::Dns) {
                    self.metrics.invalid_responses += 1;
                }
                self.logs
                    .warn(failure, query.target.tcp(), transfer.code, transfer.status, Some(query.role), transfer.proxy_status);

                if query.role == Role::Primary && transfer.backup_safe {
                    if let Some(deadline) = query.failover_deadline {
                        let now = Instant::now();
                        if now < deadline {
                            query.role = Role::Backup;
                            query.shareable = false;
                            query.cache_slot = None;
                            query = match self.start(query, token, curl_timeout(deadline - now)) {
                                Ok(()) => return Ok(()),
                                Err(query) => *query,
                            };
                        }
                    }
                }
                self.local_error(query.target, &query.waiters, &query.request, &query.info, 2);
                self.finish_tcp(query.target)?;
            }
        }
        Ok(())
    }

    fn close_tcp(&mut self, id: usize) -> Result<(), String> {
        if let Some(client) = self.clients.remove(&id) {
            self.metrics.tcp_closed += 1;
            if let Some(active) = client.busy.and_then(|token| self.active.remove(&token)) {
                self.metrics.tcp_cancelled_upstream += 1;
                self.recycle(active.handle)?;
            }
        }
        Ok(())
    }

    fn start_tcp(&mut self, id: usize) -> Result<(), String> {
        if let Some(request) = self.clients.get_mut(&id).and_then(Client::take_request) {
            let accepted = self.submit(Cow::Owned(request), Target::Tcp(id), Role::Primary, None);
            let client = &self.clients[&id];
            if !accepted || (client.busy.is_none() && !client.has_reply()) {
                self.close_tcp(id)?;
            }
        }
        Ok(())
    }

    fn tcp_io(&mut self, id: usize, events: i16) -> Result<(), String> {
        if events & native::POLL_ERROR != 0 {
            return self.close_tcp(id);
        }
        let Some(client) = self.clients.get_mut(&id) else {
            return Ok(());
        };
        if events & libc::POLLOUT != 0 && client.has_reply() {
            match client.write() {
                WriteEvent::Close => return self.close_tcp(id),
                WriteEvent::Retry => return Ok(()),
                WriteEvent::Pending => {}
                WriteEvent::Finished { satisfies } => {
                    self.metrics.queries_satisfied += u64::from(satisfies);
                    self.start_tcp(id)?;
                    if self
                        .clients
                        .get(&id)
                        .is_some_and(|c| c.read_eof && c.busy.is_none() && !c.has_reply())
                    {
                        return self.close_tcp(id);
                    }
                }
            }
        }
        if events & libc::POLLIN == 0 {
            return Ok(());
        }
        let Some(client) = self.clients.get_mut(&id) else {
            return Ok(());
        };
        match client.read(self.cfg.tcp_io) {
            ReadEvent::FrameReady if client.busy.is_some() || client.has_reply() => {
                self.metrics.tcp_pipeline_buffered += 1
            }
            ReadEvent::FrameReady => self.start_tcp(id)?,
            ReadEvent::HalfClose { partial } => {
                self.metrics.tcp_half_closes += 1;
                if partial || (client.busy.is_none() && !client.has_reply()) {
                    self.close_tcp(id)?;
                }
            }
            ReadEvent::NoMemory => {
                self.logs
                    .warn(Failure::TcpBuffer, true, sys::CURLE_OUT_OF_MEMORY, 0, None, 0);
                self.close_tcp(id)?;
            }
            ReadEvent::Close => self.close_tcp(id)?,
            ReadEvent::Pending => {}
        }
        Ok(())
    }

    fn accept(&mut self, metrics: bool) {
        for _ in 0..16 {
            let listener = if metrics {
                self.metrics_listener.as_ref().expect("metrics enabled")
            } else {
                &self.tcp
            };
            let Ok((stream, SocketAddr::V4(peer))) = listener.accept() else {
                break;
            };
            if stream.set_nonblocking(true).is_err() {
                continue;
            }
            if metrics {
                if self.metrics_clients.len() < METRIC_LIMIT {
                    let id = self.id();
                    self.metrics_clients.insert(id, MetricClient::new(stream));
                }
                continue;
            }
            let from_source = self
                .clients
                .values()
                .filter(|client| client.source == *peer.ip())
                .count();
            if from_source >= self.cfg.per_source {
                self.metrics.tcp_rejected_source += 1;
            } else if self.clients.len() == MAX_CLIENTS {
                self.metrics.tcp_rejected_capacity += 1;
            } else {
                let id = self.id();
                self.clients.insert(id, Client::new(stream, *peer.ip()));
                self.metrics.tcp_accepted += 1;
            }
        }
    }

    fn metric_io(&mut self, id: usize, events: i16) {
        if events & native::POLL_ERROR != 0 {
            self.metrics_clients.remove(&id);
            return;
        }
        let Some(client) = self.metrics_clients.get_mut(&id) else {
            return;
        };
        if events & libc::POLLIN != 0 {
            match client.read() {
                MetricRead::Close => {
                    self.metrics_clients.remove(&id);
                    return;
                }
                MetricRead::Ready => client.queue(self.metrics.response(
                    &self.engine,
                    self.active.len(),
                    self.clients.len(),
                )),
                MetricRead::Pending => {}
            }
        }
        if events & libc::POLLOUT != 0 && !client.write() {
            self.metrics_clients.remove(&id);
        }
    }

    fn udp_io(&mut self, buffer: &mut [u8]) {
        let mut bytes = 0;
        for _ in 0..32 {
            if bytes >= 65_536 {
                break;
            }
            let Ok((len, peer, local, truncated)) = native::recv_udp(&self.udp, buffer) else {
                break;
            };
            bytes += len;
            if truncated {
                self.metrics.invalid_queries += 1;
            } else {
                self.submit(
                    Cow::Borrowed(&buffer[..len]),
                    Target::Udp(peer, local),
                    Role::Primary,
                    None,
                );
            }
        }
    }

    fn expire(
        &mut self,
        now: Instant,
        idle: Duration,
        expired: &mut Vec<(usize, bool)>,
    ) -> Result<(), String> {
        expired.clear();
        expired.extend(self.clients.iter().filter_map(|(&id, c)| {
            c.deadline(idle)
                .filter(|(deadline, _)| now >= *deadline)
                .map(|(_, io)| (id, io))
        }));
        for &(id, io) in expired.iter() {
            if io {
                self.metrics.tcp_io_timeouts += 1;
            } else {
                self.metrics.tcp_idle_timeouts += 1;
            }
            self.close_tcp(id)?;
        }
        self.metrics_clients
            .retain(|_, c| now.duration_since(c.last) < METRIC_IDLE);
        Ok(())
    }

    fn drain(&mut self, completed: &mut Vec<(usize, sys::CURLcode)>) -> Result<(), String> {
        self.engine.completions(completed);
        for &(token, code) in completed.iter() {
            self.complete(token, code)?;
        }
        self.engine.check_capacity().map_err(curl_error)
    }

    fn event_loop(&mut self, started: Instant) -> Result<(), String> {
        let mut buffer = vec![0; wire::UDP_RX_MAX];
        let mut fds = Vec::with_capacity(3 + MAX_CLIENTS + METRIC_LIMIT + 1024);
        let mut items = Vec::with_capacity(fds.capacity());
        let mut watches = Vec::new();
        let mut completed = Vec::with_capacity(MAX_ACTIVE);
        let mut expired = Vec::with_capacity(MAX_CLIENTS);
        while !native::STOP.load(Ordering::Relaxed) {
            let now = Instant::now();
            if native::REPORT.swap(false, Ordering::Relaxed) {
                self.metrics.status(
                    &self.cfg,
                    now - started,
                    self.active.len(),
                    self.clients.len(),
                );
            }
            if self
                .engine
                .timer()
                .is_some_and(|deadline| native::monotonic_millis() >= deadline)
            {
                self.metrics.timer_fires += 1;
                self.engine.timeout().map_err(curl_error)?;
                self.drain(&mut completed)?;
            }
            fds.clear();
            items.clear();
            let mut add = |kind, fd: RawFd, events| {
                fds.push(libc::pollfd {
                    fd,
                    events,
                    revents: 0,
                });
                items.push(kind);
            };
            add(Interest::Udp, self.udp.as_raw_fd(), libc::POLLIN);
            add(Interest::TcpListen, self.tcp.as_raw_fd(), libc::POLLIN);
            if let Some(listener) = &self.metrics_listener {
                add(Interest::MetricsListen, listener.as_raw_fd(), libc::POLLIN);
            }
            let idle = if self.clients.len() >= MAX_CLIENTS * 3 / 4 {
                self.cfg.tcp_idle.min(Duration::from_secs(3))
            } else {
                self.cfg.tcp_idle
            };
            let mut deadline = now + Duration::from_secs(1);
            for (&id, client) in &self.clients {
                // Poll even with no requested events so resets are observed.
                add(
                    Interest::Tcp(id),
                    client.stream.as_raw_fd(),
                    client.events(),
                );
                if let Some((d, _)) = client.deadline(idle) {
                    deadline = deadline.min(d);
                }
            }
            for (&id, client) in &self.metrics_clients {
                add(
                    Interest::Metrics(id),
                    client.stream.as_raw_fd(),
                    client.events(),
                );
                deadline = deadline.min(client.last + METRIC_IDLE);
            }
            self.engine.watches(&mut watches);
            for &watch in &watches {
                add(Interest::Curl(watch), watch.fd, watch.flags);
            }

            let mut wait = deadline
                .saturating_duration_since(Instant::now())
                .as_nanos()
                .div_ceil(1_000_000) as i32;
            // Keep libcurl's millisecond clock and deadlines aligned with the
            // C reactor, including zero-delay callbacks and QUIC pacing.
            if let Some(timer) = self.engine.timer() {
                wait = i64::from(wait).min(timer.saturating_sub(native::monotonic_millis()) as i64)
                    as i32;
            }
            if let Err(err) = native::poll(&mut fds, wait) {
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(format!("event=poll message={err}"));
            }
            self.expire(Instant::now(), idle, &mut expired)?;
            for (item, fd) in items.iter().zip(&fds) {
                if native::STOP.load(Ordering::Relaxed) {
                    break;
                }
                if fd.revents == 0 {
                    continue;
                }
                match *item {
                    Interest::Udp if fd.revents & libc::POLLIN != 0 => self.udp_io(&mut buffer),
                    Interest::TcpListen if fd.revents & libc::POLLIN != 0 => self.accept(false),
                    Interest::MetricsListen if fd.revents & libc::POLLIN != 0 => self.accept(true),
                    Interest::Tcp(id) => self.tcp_io(id, fd.revents)?,
                    Interest::Metrics(id) => self.metric_io(id, fd.revents),
                    Interest::Curl(watch) => {
                        self.engine.action(watch, fd.revents).map_err(curl_error)?;
                        self.drain(&mut completed)?;
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    pub fn run(mut self) -> Result<(), String> {
        let started = Instant::now();
        eprintln!(
            "level=info event=listening address={} port={} metrics_port={} upstream_scheme={} http_preference={} backup={} libcurl_build={} libcurl_runtime={}",
            self.cfg.listen.ip(),
            self.cfg.listen.port(),
            self.cfg.metrics_port,
            self.cfg.primary.scheme(),
            self.cfg.preference(),
            enabled(self.cfg.backup.is_some()),
            env!("DNSP_LIBCURL_BUILD"),
            curl::Version::get().version()
        );
        let result = self.event_loop(started);
        self.clients.clear();
        self.metrics_clients.clear();
        let mut cleanup_error = None;
        for (_, active) in std::mem::take(&mut self.active) {
            if let Err(err) = self.recycle(active.handle) {
                cleanup_error.get_or_insert(err);
            }
        }
        result.and_then(|()| cleanup_error.map_or(Ok(()), Err))
    }
}

fn validate(query: &Query, transfer: &Transfer, cap: u16) -> Result<wire::Info, Failure> {
    if transfer.code == sys::CURLE_OPERATION_TIMEDOUT {
        return Err(Failure::Timeout);
    }
    if transfer.code != sys::CURLE_OK {
        return Err(Failure::Transport);
    }
    if !(200..300).contains(&transfer.status) {
        return Err(Failure::Status);
    }
    if !transfer.content_type_ok {
        return Err(Failure::Content);
    }
    if transfer.body.len() < wire::HEADER || transfer.body[..2] != query.request[..2] {
        return Err(Failure::Dns);
    }
    let (status, info) = wire::parse(&transfer.body, Some(&query.info), cap);
    if status == wire::Status::Ok {
        Ok(info)
    } else {
        Err(Failure::Dns)
    }
}

fn curl_error(error: String) -> String {
    format!("event=curl_multi_action message={error}")
}

fn curl_timeout(time: Duration) -> Duration {
    // CURLOPT_TIMEOUT_MS uses integers and zero disables the deadline.
    Duration::from_millis((time.as_millis() as u64).max(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpStream;

    fn proxy() -> Proxy {
        curl::init();
        let command = Config::parse(
            ["-s", "http://127.0.0.1:1234/dns-query"]
                .into_iter()
                .map(Into::into),
        )
        .unwrap();
        let crate::config::Command::Run(config) = command else {
            panic!("expected a runnable configuration");
        };
        let mut config = *config;
        config.listen.set_port(0);
        Proxy::new(config).unwrap()
    }

    #[test]
    fn udp_dispatch_obeys_packet_and_byte_budgets() {
        let mut proxy = proxy();
        let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let server = proxy.udp.local_addr().unwrap();
        let mut buffer = vec![0; wire::UDP_RX_MAX];
        for i in 0..33 {
            peer.send_to(&[i; 1], server).unwrap();
        }
        proxy.udp_io(&mut buffer);
        assert_eq!(proxy.metrics.invalid_queries, 32);
        proxy.udp_io(&mut buffer);
        assert_eq!(proxy.metrics.invalid_queries, 33);

        let mut invalid = vec![0; 32_769];
        invalid[2] = 0x80;
        for _ in 0..3 {
            peer.send_to(&invalid, server).unwrap();
        }
        proxy.udp_io(&mut buffer);
        assert_eq!(proxy.metrics.invalid_queries, 35);
        proxy.udp_io(&mut buffer);
        assert_eq!(proxy.metrics.invalid_queries, 36);
    }

    #[test]
    fn overload_returns_tcp_servfail_without_starting_transfer() {
        let mut proxy = proxy();
        let udp = Target::Udp(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1234), native::UdpLocal::default());
        // RD clear bypasses coalescing. Transfers remain queued in the multi
        // until it is driven, so the fixture never contacts the upstream.
        let query = [0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1];
        for _ in 0..MAX_ACTIVE {
            assert!(proxy.submit(Cow::Borrowed(&query), udp, Role::Primary, None));
        }
        let mut peer = TcpStream::connect(proxy.tcp.local_addr().unwrap()).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        proxy.accept(false);
        let id = *proxy.clients.keys().next().unwrap();
        assert!(proxy.submit(Cow::Borrowed(&query), Target::Tcp(id), Role::Primary, None));
        assert_eq!(proxy.metrics.overload, 1);
        assert_eq!(proxy.active.len(), MAX_ACTIVE);
        assert!(proxy.clients[&id].busy.is_none());
        proxy.tcp_io(id, libc::POLLOUT).unwrap();
        let mut response = [0; 19];
        peer.read_exact(&mut response).unwrap();
        assert_eq!(&response[..4], &[0, 17, 0x12, 0x34]);
        assert_eq!(response[5] & 15, 2);
    }
}
