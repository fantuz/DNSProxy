use std::fmt::Write;
use std::time::{Duration, Instant};

use crate::config::{Config, MAX_ACTIVE, MAX_CLIENTS};
use crate::doh::{Engine, Transfer};

#[derive(Default)]
pub struct EndpointCounts {
    pub requests: u64,
    pub replies: u64,
    pub failures: u64,
}

#[derive(Default)]
pub struct Metrics {
    pub udp_queries: u64,
    pub tcp_queries: u64,
    pub queries_satisfied: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub udp_queries_coalesced: u64,
    pub tcp_accepted: u64,
    pub tcp_rejected_source: u64,
    pub tcp_rejected_capacity: u64,
    pub tcp_closed: u64,
    pub tcp_keepalive_queries: u64,
    pub tcp_pipeline_buffered: u64,
    pub tcp_half_closes: u64,
    pub tcp_idle_timeouts: u64,
    pub tcp_io_timeouts: u64,
    pub tcp_cancelled_upstream: u64,
    pub upstream_requests: u64,
    pub upstream_ok: u64,
    pub upstream_failed: u64,
    pub upstream_timeouts: u64,
    pub endpoints: [EndpointCounts; 2],
    pub invalid_queries: u64,
    pub invalid_responses: u64,
    pub overload: u64,
    pub truncated: u64,
    pub easy_reused: u64,
    pub timer_fires: u64,
    new_connections: u64,
    reused_requests: u64,
    http: [u64; 3],
    upstream_micros: u64,
    phase_totals: [(u64, u64); 3],
}

impl Metrics {
    pub fn record_transfer(&mut self, transfer: &Transfer) {
        self.upstream_micros += transfer.total_us;
        if transfer.connects > 0 {
            self.new_connections += transfer.connects;
        } else if transfer.code == curl_sys::CURLE_OK {
            self.reused_requests += 1;
        }
        match transfer.version as libc::c_int {
            curl_sys::CURL_HTTP_VERSION_1_0 | curl_sys::CURL_HTTP_VERSION_1_1 => self.http[0] += 1,
            curl_sys::CURL_HTTP_VERSION_2_0 => self.http[1] += 1,
            curl_sys::CURL_HTTP_VERSION_3 => self.http[2] += 1,
            _ => {}
        }
        for (total, micros) in self.phase_totals.iter_mut().zip(transfer.phases) {
            if let Some(micros) = micros {
                total.0 += micros;
                total.1 += 1;
            }
        }
    }

    pub fn status(&self, cfg: &Config, uptime: Duration, inflight: usize, tcp_open: usize) {
        let mut message = format!(
            "level=info event=stats uptime_ms={} address={} port={} metrics_port={} upstream_scheme={} http_preference={} bootstrap={} backup={}",
            uptime.as_millis(),
            cfg.listen.ip(),
            cfg.listen.port(),
            cfg.metrics_port,
            cfg.primary.scheme(),
            cfg.preference(),
            enabled(cfg.primary.resolve.is_some()),
            enabled(cfg.backup.is_some()),
        );
        for (key, value) in [
            ("max_host_connections", cfg.host_connections as u64),
            ("doh_connect_ms", cfg.connect.as_millis() as u64),
            ("doh_timeout_ms", cfg.timeout.as_millis() as u64),
            ("tcp_idle_ms", cfg.tcp_idle.as_millis() as u64),
            ("tcp_io_ms", cfg.tcp_io.as_millis() as u64),
            ("queries_satisfied", self.queries_satisfied),
            ("udp_queries", self.udp_queries),
            ("tcp_queries", self.tcp_queries),
            ("udp_queries_coalesced", self.udp_queries_coalesced),
            ("upstream_ok", self.upstream_ok),
            ("upstream_failed", self.upstream_failed),
            ("upstream_timeouts", self.upstream_timeouts),
            ("invalid_queries", self.invalid_queries),
            ("invalid_responses", self.invalid_responses),
            ("overload", self.overload),
            ("udp_truncated", self.truncated),
            ("tcp_cancelled_upstream", self.tcp_cancelled_upstream),
            ("http1_responses", self.http[0]),
            ("http2_responses", self.http[1]),
            ("http3_responses", self.http[2]),
            ("new_connections", self.new_connections),
            ("reused_requests", self.reused_requests),
            ("easy_handles_reused", self.easy_reused),
            ("cache_entries", cfg.cache_entries as u64),
            ("cache_hits", self.cache_hits),
            ("cache_misses", self.cache_misses),
            ("inflight", inflight as u64),
            ("max_inflight", MAX_ACTIVE as u64),
            ("tcp_clients", tcp_open as u64),
            ("max_tcp_clients", MAX_CLIENTS as u64),
            ("max_tcp_per_source", cfg.per_source as u64),
            ("tcp_rejected_source", self.tcp_rejected_source),
            ("tcp_rejected_capacity", self.tcp_rejected_capacity),
        ] {
            write!(message, " {key}={value}").unwrap();
        }
        eprintln!("{message}");
    }

    pub fn response(&self, engine: &Engine, inflight: usize, tcp_open: usize) -> String {
        let mut body = String::with_capacity(4096);
        for (name, value) in [
            ("queries_satisfied_total", self.queries_satisfied),
            ("cache_hits_total", self.cache_hits),
            ("cache_misses_total", self.cache_misses),
            ("udp_queries_coalesced_total", self.udp_queries_coalesced),
            ("tcp_connections_accepted_total", self.tcp_accepted),
            ("tcp_connections_closed_total", self.tcp_closed),
            ("tcp_keepalive_queries_total", self.tcp_keepalive_queries),
            ("tcp_pipeline_buffered_total", self.tcp_pipeline_buffered),
            ("tcp_half_closes_total", self.tcp_half_closes),
            ("tcp_idle_timeouts_total", self.tcp_idle_timeouts),
            ("tcp_io_timeouts_total", self.tcp_io_timeouts),
            ("tcp_cancelled_upstream_total", self.tcp_cancelled_upstream),
            ("upstream_requests_total", self.upstream_requests),
            ("upstream_success_total", self.upstream_ok),
            ("upstream_failures_total", self.upstream_failed),
            ("upstream_timeouts_total", self.upstream_timeouts),
            ("invalid_queries_total", self.invalid_queries),
            ("invalid_responses_total", self.invalid_responses),
            ("overload_total", self.overload),
            ("truncated_responses_total", self.truncated),
            ("upstream_new_connections_total", self.new_connections),
            ("upstream_reused_requests_total", self.reused_requests),
            ("upstream_easy_handles_reused_total", self.easy_reused),
            ("curl_timer_fires_total", self.timer_fires),
        ] {
            writeln!(body, "# TYPE dnsp_{name} counter\ndnsp_{name} {value}").unwrap();
        }
        writeln!(body, "# TYPE dnsp_queries_total counter").unwrap();
        writeln!(
            body,
            "dnsp_queries_total{{transport=\"udp\"}} {}",
            self.udp_queries
        )
        .unwrap();
        writeln!(
            body,
            "dnsp_queries_total{{transport=\"tcp\"}} {}",
            self.tcp_queries
        )
        .unwrap();
        writeln!(body, "# TYPE dnsp_tcp_connections_rejected_total counter").unwrap();
        writeln!(
            body,
            "dnsp_tcp_connections_rejected_total{{reason=\"source_limit\"}} {}",
            self.tcp_rejected_source
        )
        .unwrap();
        writeln!(
            body,
            "dnsp_tcp_connections_rejected_total{{reason=\"capacity\"}} {}",
            self.tcp_rejected_capacity
        )
        .unwrap();
        for (role, counters) in ["primary", "backup"].into_iter().zip(&self.endpoints) {
            writeln!(
                body,
                "dnsp_upstream_endpoint_requests_total{{role=\"{role}\"}} {}",
                counters.requests
            )
            .unwrap();
            writeln!(
                body,
                "dnsp_upstream_endpoint_replies_total{{role=\"{role}\"}} {}",
                counters.replies
            )
            .unwrap();
            writeln!(
                body,
                "dnsp_upstream_endpoint_failures_total{{role=\"{role}\"}} {}",
                counters.failures
            )
            .unwrap();
        }
        for (version, responses) in (1..=3).zip(self.http) {
            writeln!(
                body,
                "dnsp_upstream_http_responses_total{{version=\"{version}\"}} {responses}"
            )
            .unwrap();
        }
        let (sockets, timers, watches) = engine.counters();
        writeln!(
            body,
            "dnsp_curl_socket_callbacks_total {sockets}\ndnsp_curl_timer_callbacks_total {timers}"
        )
        .unwrap();
        writeln!(body, "# TYPE dnsp_upstream_duration_seconds_sum counter\ndnsp_upstream_duration_seconds_sum {:.6}", seconds(self.upstream_micros)).unwrap();
        writeln!(
            body,
            "dnsp_upstream_duration_seconds_count {}",
            self.upstream_ok + self.upstream_failed
        )
        .unwrap();
        writeln!(body, "# HELP dnsp_upstream_phase_duration_seconds Time spent in observed upstream transfer phases.\n# TYPE dnsp_upstream_phase_duration_seconds summary").unwrap();
        for (phase, (total, count)) in ["queue", "tls", "first_byte"]
            .into_iter()
            .zip(self.phase_totals)
        {
            writeln!(
                body,
                "dnsp_upstream_phase_duration_seconds_sum{{phase=\"{phase}\"}} {:.6}",
                seconds(total)
            )
            .unwrap();
            writeln!(
                body,
                "dnsp_upstream_phase_duration_seconds_count{{phase=\"{phase}\"}} {count}"
            )
            .unwrap();
        }
        writeln!(body, "# TYPE dnsp_queries_inflight gauge\ndnsp_queries_inflight {inflight}\ndnsp_tcp_clients {tcp_open}\ndnsp_curl_socket_watches {watches}").unwrap();
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }
}

fn seconds(micros: u64) -> f64 {
    micros as f64 / 1_000_000.0
}

pub fn enabled(value: bool) -> &'static str {
    if value { "enabled" } else { "disabled" }
}

#[derive(Clone, Copy)]
pub enum Failure {
    Capacity,
    Setup,
    Timeout,
    Transport,
    Status,
    Content,
    Dns,
    TcpBuffer,
}

#[derive(Default)]
pub struct RateLog([(Option<Instant>, u64); 8]);

impl RateLog {
    pub fn warn(
        &mut self,
        failure: Failure,
        tcp: bool,
        code: curl_sys::CURLcode,
        status: libc::c_long,
    ) {
        let now = Instant::now();
        let (next, suppressed) = &mut self.0[failure as usize];
        if next.is_some_and(|deadline| now < deadline) {
            *suppressed += 1;
            return;
        }
        let event = match failure {
            Failure::Capacity => "capacity",
            Failure::Setup => "upstream_setup",
            Failure::Timeout => "upstream_timeout",
            Failure::Transport => "upstream_transport",
            Failure::Status => "upstream_http_status",
            Failure::Content => "upstream_content_type",
            Failure::Dns => "upstream_dns_response",
            Failure::TcpBuffer => "tcp_buffer_allocation",
        };
        let transport = if tcp { "tcp" } else { "udp" };
        eprintln!(
            "level=warning event={event} transport={transport} curl_code={code} http_status={status} suppressed={suppressed}"
        );
        *next = Some(now + Duration::from_secs(10));
        *suppressed = 0;
    }
}
