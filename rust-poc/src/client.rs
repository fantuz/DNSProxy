use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::time::{Duration, Instant};

use crate::wire;

pub const METRIC_LIMIT: usize = 16;
pub const METRIC_IDLE: Duration = Duration::from_secs(3);

pub struct Client {
    pub stream: TcpStream,
    pub source: Ipv4Addr,
    pub busy: Option<usize>,
    pub queries: u64,
    pub read_eof: bool,
    idle_since: Instant,
    length: [u8; 2],
    input: Vec<u8>,
    have: usize,
    frame_deadline: Option<Instant>,
    output: Vec<u8>,
    sent: usize,
    write_deadline: Option<Instant>,
    satisfies: bool,
}

pub enum ReadEvent {
    Pending,
    FrameReady,
    HalfClose { partial: bool },
    Close,
    NoMemory,
}

pub enum WriteEvent {
    Pending,
    Retry,
    Finished { satisfies: bool },
    Close,
}

fn retry(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

impl Client {
    pub fn new(stream: TcpStream, source: Ipv4Addr) -> Self {
        Self {
            stream,
            source,
            busy: None,
            queries: 0,
            read_eof: false,
            idle_since: Instant::now(),
            length: [0; 2],
            input: Vec::new(),
            have: 0,
            frame_deadline: None,
            output: Vec::new(),
            sent: 0,
            write_deadline: None,
            satisfies: false,
        }
    }

    pub fn has_reply(&self) -> bool {
        !self.output.is_empty()
    }

    pub fn ready(&self) -> bool {
        !self.input.is_empty() && self.have == self.input.len()
    }

    pub fn take_request(&mut self) -> Option<Vec<u8>> {
        if !self.ready() || self.busy.is_some() || self.has_reply() {
            return None;
        }
        self.have = 0;
        Some(std::mem::take(&mut self.input))
    }

    pub fn events(&self) -> i16 {
        let read = if self.read_eof || self.ready() {
            0
        } else {
            libc::POLLIN
        };
        read | if self.has_reply() { libc::POLLOUT } else { 0 }
    }

    pub fn deadline(&self, idle: Duration) -> Option<(Instant, bool)> {
        if let Some(deadline) = [self.frame_deadline, self.write_deadline]
            .into_iter()
            .flatten()
            .min()
        {
            Some((deadline, true))
        } else if self.busy.is_none() {
            Some((self.idle_since + idle, false))
        } else {
            None
        }
    }

    pub fn queue(&mut self, reply: &[u8], satisfies: bool, io_timeout: Duration) -> bool {
        debug_assert!(!self.has_reply());
        if self.output.try_reserve_exact(reply.len() + 2).is_err() {
            return false;
        }
        self.output
            .extend_from_slice(&(reply.len() as u16).to_be_bytes());
        self.output.extend_from_slice(reply);
        self.satisfies = satisfies;
        self.write_deadline = Some(Instant::now() + io_timeout);
        true
    }

    pub fn write(&mut self) -> WriteEvent {
        match self.stream.write(&self.output[self.sent..]) {
            Ok(0) => return WriteEvent::Close,
            Ok(n) => self.sent += n,
            Err(error) if retry(&error) => return WriteEvent::Retry,
            Err(_) => return WriteEvent::Close,
        }
        if self.sent != self.output.len() {
            return WriteEvent::Pending;
        }
        self.output = Vec::new();
        self.sent = 0;
        self.write_deadline = None;
        self.idle_since = Instant::now();
        WriteEvent::Finished {
            satisfies: std::mem::take(&mut self.satisfies),
        }
    }

    pub fn read(&mut self, io_timeout: Duration) -> ReadEvent {
        if self.read_eof || self.ready() {
            return ReadEvent::Pending;
        }
        let length = self.input.is_empty();
        let buffer = if length {
            &mut self.length[..]
        } else {
            &mut self.input[..]
        };
        let received = match self.stream.read(&mut buffer[self.have..]) {
            Ok(0) => {
                self.read_eof = true;
                return ReadEvent::HalfClose {
                    partial: self.have != 0 || !length,
                };
            }
            Ok(n) => n,
            Err(error) if retry(&error) => return ReadEvent::Pending,
            Err(_) => return ReadEvent::Close,
        };
        if length && self.have == 0 {
            self.frame_deadline = Some(Instant::now() + io_timeout);
        }
        self.have += received;
        if length && self.have == 2 {
            let need = u16::from_be_bytes(self.length) as usize;
            if need < wire::HEADER {
                return ReadEvent::Close;
            }
            if self.input.try_reserve_exact(need).is_err() {
                return ReadEvent::NoMemory;
            }
            self.input.resize(need, 0);
            self.have = 0;
        }
        if self.ready() {
            self.frame_deadline = None;
            ReadEvent::FrameReady
        } else {
            ReadEvent::Pending
        }
    }
}

pub struct MetricClient {
    pub stream: TcpStream,
    pub last: Instant,
    input: [u8; 512],
    have: usize,
    response: Option<String>,
    sent: usize,
}

pub enum MetricRead {
    Pending,
    Ready,
    Close,
}

impl MetricClient {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            last: Instant::now(),
            input: [0; 512],
            have: 0,
            response: None,
            sent: 0,
        }
    }

    pub fn events(&self) -> i16 {
        if self.response.is_some() {
            libc::POLLOUT
        } else {
            libc::POLLIN
        }
    }

    pub fn read(&mut self) -> MetricRead {
        match self.stream.read(&mut self.input[self.have..]) {
            Ok(0) => return MetricRead::Close,
            Ok(n) => self.have += n,
            Err(error) if retry(&error) => return MetricRead::Pending,
            Err(_) => return MetricRead::Close,
        }
        self.last = Instant::now();
        if self.have == self.input.len() {
            return MetricRead::Close;
        }
        // Match the reference's bounded HTTP/1.x endpoint.
        let request = self.input[..self.have]
            .split(|&b| b == 0)
            .next()
            .unwrap_or_default();
        if !request.windows(4).any(|part| part == b"\r\n\r\n") {
            return MetricRead::Pending;
        }
        if request.starts_with(b"GET /metrics HTTP/1.") {
            MetricRead::Ready
        } else {
            MetricRead::Close
        }
    }

    pub fn queue(&mut self, response: String) {
        self.response = Some(response);
    }

    pub fn write(&mut self) -> bool {
        let Some(response) = &self.response else {
            return false;
        };
        match self.stream.write(&response.as_bytes()[self.sent..]) {
            Ok(0) => return false,
            Ok(n) => self.sent += n,
            Err(error) if retry(&error) => return true,
            Err(_) => return false,
        }
        self.last = Instant::now();
        self.sent < response.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native;
    use std::net::TcpListener;
    use std::os::fd::AsRawFd;

    #[test]
    fn tcp_write_resumes_under_backpressure() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        socket2::SockRef::from(&server)
            .set_send_buffer_size(4096)
            .unwrap();
        server.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        let mut client = Client::new(server, Ipv4Addr::LOCALHOST);
        let payload: Vec<_> = (0..wire::TCP_MAX).map(|i| (i ^ (i >> 8)) as u8).collect();
        assert!(client.queue(&payload, true, Duration::from_secs(5)));
        let deadline = client.deadline(Duration::from_secs(10)).unwrap();
        assert!(matches!(client.write(), WriteEvent::Pending));
        assert!(client.sent > 0 && client.sent < payload.len() + 2);
        assert_eq!(client.deadline(Duration::from_secs(10)), Some(deadline));

        let mut response = Vec::new();
        let mut done = false;
        let mut buffer = [0; 8192];
        while (!done || response.len() < payload.len() + 2) && Instant::now() < deadline.0 {
            let mut fds = [
                libc::pollfd {
                    fd: peer.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: client.stream.as_raw_fd(),
                    events: client.events() & libc::POLLOUT,
                    revents: 0,
                },
            ];
            native::poll(&mut fds, 100).unwrap();
            if fds[0].revents & libc::POLLIN != 0 {
                let n = peer.read(&mut buffer).unwrap();
                response.extend_from_slice(&buffer[..n]);
            }
            if fds[1].revents & libc::POLLOUT != 0 {
                match client.write() {
                    WriteEvent::Finished { satisfies } => {
                        assert!(satisfies);
                        done = true;
                    }
                    WriteEvent::Pending | WriteEvent::Retry => {}
                    WriteEvent::Close => panic!("server closed during partial write"),
                }
            }
        }
        assert!(done);
        assert!(!client.has_reply());
        assert_eq!(&response[..2], &u16::MAX.to_be_bytes());
        assert_eq!(&response[2..], payload.as_slice());
    }
}
