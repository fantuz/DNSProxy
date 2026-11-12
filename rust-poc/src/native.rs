use std::ffi::{CStr, CString};
use std::io;
use std::net::{SocketAddrV4, TcpListener, UdpSocket};
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicBool, Ordering};

use libc::{c_char, c_int, c_long, c_uint, c_void};
use socket2::{Domain, Protocol, Socket, Type};

pub static STOP: AtomicBool = AtomicBool::new(false);
pub static REPORT: AtomicBool = AtomicBool::new(false);
pub const POLL_ERROR: i16 = libc::POLLERR | libc::POLLHUP | libc::POLLNVAL;

extern "C" fn stop(_: c_int) {
    STOP.store(true, Ordering::Relaxed);
}

extern "C" fn report(_: c_int) {
    REPORT.store(true, Ordering::Relaxed);
}

pub fn signals() -> io::Result<()> {
    for (signal, handler) in [
        (libc::SIGINT, stop as libc::sighandler_t),
        (libc::SIGTERM, stop as libc::sighandler_t),
        (libc::SIGUSR1, report as libc::sighandler_t),
        (libc::SIGPIPE, libc::SIG_IGN),
    ] {
        // SAFETY: sigaction is a C value initialized with an empty mask.
        // The handlers only write lock-free atomics and have static lifetime.
        let result = unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            libc::sigemptyset(&mut action.sa_mask);
            action.sa_sigaction = handler;
            libc::sigaction(signal, &action, ptr::null_mut())
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn poll(fds: &mut [libc::pollfd], timeout_ms: c_int) -> io::Result<()> {
    // SAFETY: The array is writable for its supplied length during this call.
    let count = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn boot_millis() -> Option<u64> {
    clock_millis(libc::CLOCK_BOOTTIME)
}

pub fn monotonic_millis() -> u64 {
    clock_millis(libc::CLOCK_MONOTONIC).unwrap_or_default()
}

fn clock_millis(clock: libc::clockid_t) -> Option<u64> {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: t is writable and clock is a Linux clock ID.
    (unsafe { libc::clock_gettime(clock, &mut t) } == 0 && t.tv_sec >= 0)
        .then(|| t.tv_sec as u64 * 1000 + t.tv_nsec as u64 / 1_000_000)
}

fn listener(addr: SocketAddrV4, ty: Type, protocol: Protocol) -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, ty, Some(protocol))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(socket)
}

pub fn udp_listener(addr: SocketAddrV4) -> io::Result<UdpSocket> {
    use std::os::fd::AsRawFd;

    let socket = listener(addr, Type::DGRAM, Protocol::UDP)?;
    if addr.ip().is_unspecified() {
        let enabled: c_int = 1;
        // SAFETY: The option takes a pointer to an initialized C int.
        if unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_PKTINFO,
                (&enabled as *const c_int).cast(),
                std::mem::size_of_val(&enabled) as libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(socket.into())
}

pub fn tcp_listener(addr: SocketAddrV4) -> io::Result<TcpListener> {
    let socket = listener(addr, Type::STREAM, Protocol::TCP)?;
    socket.listen(128)?;
    Ok(socket.into())
}

// URL API added in libcurl 7.62. The project uses native libcurl 7.88+.
#[repr(C)]
struct CurlUrl {
    _private: [u8; 0],
}

unsafe extern "C" {
    fn curl_url() -> *mut CurlUrl;
    fn curl_url_cleanup(url: *mut CurlUrl);
    fn curl_url_set(url: *mut CurlUrl, part: c_int, content: *const c_char, flags: c_uint)
    -> c_int;
    fn curl_url_get(
        url: *const CurlUrl,
        part: c_int,
        content: *mut *mut c_char,
        flags: c_uint,
    ) -> c_int;
}

struct Url(NonNull<CurlUrl>);

impl Drop for Url {
    fn drop(&mut self) {
        // SAFETY: Url owns exactly one handle allocated by curl_url.
        unsafe { curl_url_cleanup(self.0.as_ptr()) };
    }
}

impl Url {
    fn part(&self, part: c_int, flags: c_uint) -> Option<String> {
        let mut text = ptr::null_mut();
        // SAFETY: Handle and output pointer are valid. Successful results are
        // owned NUL-terminated strings that must be released with curl_free.
        unsafe {
            if curl_url_get(self.0.as_ptr(), part, &mut text, flags) != 0 || text.is_null() {
                return None;
            }
            let value = CStr::from_ptr(text).to_str().map(str::to_owned).ok();
            curl_sys::curl_free(text.cast());
            value
        }
    }
}

pub fn url_parts(text: &str) -> Option<(String, String, u16)> {
    const URL: c_int = 0;
    const SCHEME: c_int = 1;
    const HOST: c_int = 5;
    const PORT: c_int = 6;
    const DEFAULT_PORT: c_uint = 1;
    let text = CString::new(text).ok()?;
    // SAFETY: libcurl is initialized by main. The C string lasts for set(),
    // which takes a copy, and the RAII handle is always freed.
    let url = Url(NonNull::new(unsafe { curl_url() })?);
    if unsafe { curl_url_set(url.0.as_ptr(), URL, text.as_ptr(), 0) } != 0 {
        return None;
    }
    Some((
        url.part(SCHEME, 0)?,
        url.part(HOST, 0)?,
        url.part(PORT, DEFAULT_PORT)?.parse().ok()?,
    ))
}

pub fn http_date(value: &[u8]) -> Option<i64> {
    let value = CString::new(value).ok()?;
    // SAFETY: Value is a live C string. The second argument is unused by curl.
    let date = unsafe { curl_sys::curl_getdate(value.as_ptr(), ptr::null()) } as i64;
    (date != -1).then_some(date)
}

// Typed getinfo accessors for fields the curl crate does not expose.
// The discriminants are part of libcurl's public CURLINFO ABI.
#[repr(u32)]
pub enum LongInfo {
    Status = curl_sys::CURLINFO_RESPONSE_CODE,
    ProxyStatus = curl_sys::CURLINFO_HTTP_CONNECTCODE,
    Verify = curl_sys::CURLINFO_SSL_VERIFYRESULT,
    ProxyVerify = curl_sys::CURLINFO_LONG + 47,
    Connections = curl_sys::CURLINFO_NUM_CONNECTS,
    HttpVersion = curl_sys::CURLINFO_LONG + 46,
}

#[repr(u32)]
pub enum TimeInfo {
    Total = 50,
    Connect = 52,
    Ready = 53,
    FirstByte = 54,
    Tls = 56,
    Queue = 65,
}

pub fn get_long<T>(handle: &curl::multi::Easy2Handle<T>, field: LongInfo) -> Option<c_long> {
    let mut value: c_long = 0;
    // SAFETY: The handle lives for the call and LongInfo contains only
    // fields that take a pointer to a C long.
    let code =
        unsafe { curl_sys::curl_easy_getinfo(handle.raw(), field as _, &mut value as *mut c_long) };
    (code == curl_sys::CURLE_OK).then_some(value)
}

pub fn get_micros<T>(handle: &curl::multi::Easy2Handle<T>, field: TimeInfo) -> Option<u64> {
    const OFF_T: curl_sys::CURLINFO = 0x600000;
    let mut value: curl_sys::curl_off_t = 0;
    // SAFETY: The handle lives for the call and the selected fields take curl_off_t*.
    let code = unsafe {
        curl_sys::curl_easy_getinfo(
            handle.raw(),
            OFF_T + field as curl_sys::CURLINFO,
            &mut value as *mut curl_sys::curl_off_t,
        )
    };
    (code == curl_sys::CURLE_OK && value >= 0).then_some(value as u64)
}

/// Immutable curl_slist with ownership shared by attached easy handlers.
pub struct HeaderList(NonNull<curl_sys::curl_slist>);

impl HeaderList {
    pub fn new(items: &[&str]) -> Result<Self, curl::Error> {
        let mut list = None;
        for item in items {
            let item = CString::new(*item)
                .map_err(|_| curl::Error::new(curl_sys::CURLE_BAD_FUNCTION_ARGUMENT))?;
            let head = list
                .as_ref()
                .map_or(ptr::null_mut(), |value: &Self| value.0.as_ptr());
            // SAFETY: head is null or the list we own. libcurl copies item.
            let next = unsafe { curl_sys::curl_slist_append(head, item.as_ptr()) };
            let next = NonNull::new(next)
                .ok_or_else(|| curl::Error::new(curl_sys::CURLE_OUT_OF_MEMORY))?;
            match &mut list {
                Some(value) => value.0 = next,
                None => list = Some(Self(next)),
            }
        }
        list.ok_or_else(|| curl::Error::new(curl_sys::CURLE_BAD_FUNCTION_ARGUMENT))
    }

    // SAFETY: The caller retains this immutable list until easy is reset or destroyed.
    pub unsafe fn attach<T>(
        &self,
        easy: &curl::easy::Easy2<T>,
        option: curl_sys::CURLoption,
    ) -> Result<(), curl::Error> {
        debug_assert!(matches!(
            option,
            curl_sys::CURLOPT_HTTPHEADER | curl_sys::CURLOPT_RESOLVE
        ));
        let code = unsafe { curl_sys::curl_easy_setopt(easy.raw(), option, self.0.as_ptr()) };
        curl_result(code)
    }
}

impl Drop for HeaderList {
    fn drop(&mut self) {
        // SAFETY: This list was allocated by libcurl and is owned by Self.
        unsafe { curl_sys::curl_slist_free_all(self.0.as_ptr()) };
    }
}

// SAFETY: The caller keeps data allocated and immutable until reset or cleanup.
pub unsafe fn post<T>(easy: &curl::easy::Easy2<T>, data: &[u8]) -> Result<(), curl::Error> {
    // SAFETY: Option types match the libcurl ABI. The transfer cannot start
    // until the handle is added to the multi after both options succeed.
    unsafe {
        curl_result(curl_sys::curl_easy_setopt(
            easy.raw(),
            curl_sys::CURLOPT_POSTFIELDSIZE_LARGE,
            data.len() as curl_sys::curl_off_t,
        ))?;
        curl_result(curl_sys::curl_easy_setopt(
            easy.raw(),
            curl_sys::CURLOPT_POSTFIELDS,
            data.as_ptr().cast::<c_void>(),
        ))
    }
}

fn curl_result(code: curl_sys::CURLcode) -> Result<(), curl::Error> {
    if code == curl_sys::CURLE_OK {
        Ok(())
    } else {
        Err(curl::Error::new(code))
    }
}

pub fn dns_content_type<T>(handle: &curl::multi::Easy2Handle<T>) -> bool {
    let mut text: *mut c_char = ptr::null_mut();
    // SAFETY: libcurl's string lives until the handle changes. We only use
    // the borrowed bytes during this call.
    let code = unsafe {
        curl_sys::curl_easy_getinfo(
            handle.raw(),
            curl_sys::CURLINFO_CONTENT_TYPE,
            &mut text as *mut *mut c_char,
        )
    };
    if code != curl_sys::CURLE_OK || text.is_null() {
        return false;
    }
    let value = unsafe { CStr::from_ptr(text) }.to_bytes();
    const MEDIA: &[u8] = b"application/dns-message";
    if !value
        .get(..MEDIA.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(MEDIA))
    {
        return false;
    }
    matches!(
        value[MEDIA.len()..]
            .iter()
            .find(|&&b| b != b' ' && b != b'\t'),
        None | Some(b';')
    )
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct UdpLocal {
    pub destination: u32,
    source: u32,
}

pub fn recv_udp(
    socket: &UdpSocket,
    buffer: &mut [u8],
) -> io::Result<(usize, SocketAddrV4, UdpLocal, bool)> {
    use std::os::fd::AsRawFd;

    // SAFETY: Zero initializes the C address and message. The iovec, address
    // and backing slice are writable and live for the syscall.
    unsafe {
        let mut address: libc::sockaddr_in = std::mem::zeroed();
        let mut io = libc::iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: buffer.len(),
        };
        let mut message: libc::msghdr = std::mem::zeroed();
        // usize storage aligns cmsghdr and holds one in_pktinfo on Linux.
        let mut control = [0usize; 8];
        message.msg_name = (&mut address as *mut libc::sockaddr_in).cast();
        message.msg_namelen = std::mem::size_of_val(&address) as libc::socklen_t;
        message.msg_iov = &mut io;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&control);
        let len = libc::recvmsg(socket.as_raw_fd(), &mut message, 0);
        if len < 0 {
            return Err(io::Error::last_os_error());
        }
        if address.sin_family as c_int != libc::AF_INET
            || (message.msg_namelen as usize) < std::mem::size_of_val(&address)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected an IPv4 UDP peer",
            ));
        }
        let ip = std::net::Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes());
        let peer = SocketAddrV4::new(ip, u16::from_be(address.sin_port));
        let mut local = UdpLocal::default();
        let truncated = message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0;
        if !truncated {
            let mut header = libc::CMSG_FIRSTHDR(&message);
            while !header.is_null() {
                if (*header).cmsg_level == libc::IPPROTO_IP
                    && (*header).cmsg_type == libc::IP_PKTINFO
                    && (*header).cmsg_len
                        >= libc::CMSG_LEN(std::mem::size_of::<libc::in_pktinfo>() as u32) as usize
                {
                    let info = ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::in_pktinfo>());
                    local = UdpLocal {
                        destination: info.ipi_addr.s_addr,
                        source: info.ipi_spec_dst.s_addr,
                    };
                    break;
                }
                header = libc::CMSG_NXTHDR(&message, header);
            }
        }
        Ok((len as usize, peer, local, truncated))
    }
}

pub fn send_udp_with_id(
    socket: &UdpSocket,
    peer: SocketAddrV4,
    local: UdpLocal,
    id: u16,
    tail: &[u8],
) -> io::Result<usize> {
    use std::os::fd::AsRawFd;

    let id = id.to_be_bytes();
    let mut address = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: peer.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(peer.ip().octets()),
        },
        sin_zero: [0; 8],
    };
    let mut parts = [
        libc::iovec {
            iov_base: id.as_ptr().cast_mut().cast(),
            iov_len: id.len(),
        },
        libc::iovec {
            iov_base: tail.as_ptr().cast_mut().cast(),
            iov_len: tail.len(),
        },
    ];
    // SAFETY: All pointers are valid until sendmsg returns. The syscall
    // only reads the iovec payloads, despite the C ABI's mutable pointer.
    let written = unsafe {
        let mut message: libc::msghdr = std::mem::zeroed();
        message.msg_name = (&mut address as *mut libc::sockaddr_in).cast();
        message.msg_namelen = std::mem::size_of_val(&address) as libc::socklen_t;
        message.msg_iov = parts.as_mut_ptr();
        message.msg_iovlen = parts.len();
        let mut control = [0usize; 8];
        if local.source != 0 {
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen =
                libc::CMSG_SPACE(std::mem::size_of::<libc::in_pktinfo>() as u32) as usize;
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::IPPROTO_IP;
            (*header).cmsg_type = libc::IP_PKTINFO;
            (*header).cmsg_len =
                libc::CMSG_LEN(std::mem::size_of::<libc::in_pktinfo>() as u32) as usize;
            let mut info: libc::in_pktinfo = std::mem::zeroed();
            info.ipi_spec_dst.s_addr = local.source;
            ptr::write_unaligned(libc::CMSG_DATA(header).cast::<libc::in_pktinfo>(), info);
        }
        libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_NOSIGNAL)
    };
    if written < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(written as usize)
    }
}
