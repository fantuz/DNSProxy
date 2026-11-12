#ifndef DNSP_PLATFORM_H
#define DNSP_PLATFORM_H

/* Only operating-system interfaces live here. DNS and libcurl state remain
 * in dnsp-modern.c, shared by the native Windows and Linux builds. */
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#define WIN32_LEAN_AND_MEAN
#ifndef FD_SETSIZE
#define FD_SETSIZE 2048
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#include <wchar.h>
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
typedef int dnsp_socklen_t;
typedef WSAPOLLFD dnsp_pollfd;
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
typedef socklen_t dnsp_socklen_t;
typedef struct pollfd dnsp_pollfd;
#endif
#include <curl/curl.h>
#if defined(_WIN32) && LIBCURL_VERSION_NUM < 0x080200
#error Native Windows PoC builds require libcurl 8.2.0 or newer
#endif
typedef curl_socket_t dnsp_socket_t;
typedef ptrdiff_t dnsp_ssize_t;
#define DNSP_BAD_SOCKET CURL_SOCKET_BAD
typedef struct { uint32_t destination,source,interface_index; } UdpLocal;

static inline void dnsp_close(dnsp_socket_t fd) {
#ifdef _WIN32
    closesocket(fd);
#else
    close(fd);
#endif
}
static inline int nonblock(dnsp_socket_t fd) {
#ifdef _WIN32
    u_long enabled=1;
    return ioctlsocket(fd,FIONBIO,&enabled);
#else
    int flags=fcntl(fd,F_GETFL,0);
    return flags<0?-1:fcntl(fd,F_SETFL,flags|O_NONBLOCK);
#endif
}
static inline int dnsp_socket_error(void) {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}
static inline bool dnsp_listener_options(dnsp_socket_t fd) {
    int enabled=1;
#ifdef _WIN32
    /* Windows SO_REUSEADDR can let another process take over a DNS port. */
    return setsockopt(fd,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,(const char*)&enabled,sizeof(enabled))==0;
#else
    return setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&enabled,sizeof(enabled))==0;
#endif
}
static inline bool dnsp_socket_retry(void) {
    int error=dnsp_socket_error();
#ifdef _WIN32
    return error==WSAEWOULDBLOCK || error==WSAEINTR;
#else
    return error==EAGAIN || error==EWOULDBLOCK || error==EINTR;
#endif
}
static inline const char *dnsp_socket_message(int error) {
#ifdef _WIN32
    static char message[256];
    if(!FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL,(DWORD)error,0,message,sizeof(message),NULL))
        return "Windows socket error";
    message[strcspn(message,"\r\n")]=0;
    return message;
#else
    return strerror(error);
#endif
}
static inline int dnsp_poll(dnsp_pollfd *fds,size_t count,int timeout) {
#ifdef _WIN32
    /* Winsock select reports a peer FIN as readable EOF. WSAPoll reports
     * POLLHUP while data is still queued, unlike Linux poll, and can spin
     * on half-closed clients whose framing reads are paused. */
    if(count>FD_SETSIZE) {WSASetLastError(WSAEINVAL);return -1;}
    fd_set reads,writes,errors;
    FD_ZERO(&reads);FD_ZERO(&writes);FD_ZERO(&errors);
    for(size_t i=0;i<count;i++) {
        fds[i].revents=0;
        if(fds[i].events&POLLIN) FD_SET(fds[i].fd,&reads);
        if(fds[i].events&POLLOUT) FD_SET(fds[i].fd,&writes);
        FD_SET(fds[i].fd,&errors);
    }
    struct timeval wait={.tv_sec=timeout/1000,.tv_usec=(timeout%1000)*1000};
    int result=select(0,&reads,&writes,&errors,timeout<0?NULL:&wait);
    if(result<=0) return result;
    int ready=0;
    for(size_t i=0;i<count;i++) {
        if(FD_ISSET(fds[i].fd,&reads)) fds[i].revents|=POLLIN;
        if(FD_ISSET(fds[i].fd,&writes)) fds[i].revents|=POLLOUT;
        if(FD_ISSET(fds[i].fd,&errors)) fds[i].revents|=POLLERR;
        if(fds[i].revents) ready++;
    }
    return ready;
#else
    return poll(fds,count,timeout);
#endif
}
static inline bool dnsp_paused_tcp_reset(dnsp_socket_t fd) {
#ifdef _WIN32
    /* select has no poll-style error-only subscription. Peek only on a TCP
     * reader paused at a full frame; do not consume data or mistake FIN for RST. */
    char byte;
    if(recv(fd,&byte,1,MSG_PEEK)>=0) return false;
    int error=WSAGetLastError();
    return error==WSAECONNRESET || error==WSAECONNABORTED;
#else
    (void)fd;
    return false;
#endif
}
static inline dnsp_ssize_t dnsp_recv(dnsp_socket_t fd,void *data,size_t size) {
#ifdef _WIN32
    return recv(fd,(char*)data,(int)size,0);
#else
    return recv(fd,data,size,0);
#endif
}
static inline dnsp_ssize_t dnsp_send(dnsp_socket_t fd,const void *data,size_t size) {
#ifdef _WIN32
    return send(fd,(const char*)data,(int)size,0);
#else
    return send(fd,data,size,MSG_NOSIGNAL);
#endif
}
static inline uint64_t dnsp_clock_ms(bool include_suspend) {
#ifdef _WIN32
    (void)include_suspend;
    /* GetTickCount64 includes sleep, so suspended machines cannot serve stale TTLs. */
    return GetTickCount64();
#else
    struct timespec t;
    if(clock_gettime(include_suspend?CLOCK_BOOTTIME:CLOCK_MONOTONIC,&t)!=0) return 0;
    return (uint64_t)t.tv_sec*1000u+(uint64_t)t.tv_nsec/1000000u;
#endif
}
#ifdef _WIN32
static inline const char *dnsp_bundled_ca(void) {
    static char utf8[MAX_PATH*3];
    static bool located;
    if(located) return utf8[0]?utf8:NULL;
    located=true; /* Resolve the installation path once, not on every query. */
    WCHAR path[MAX_PATH];
    DWORD size=GetModuleFileNameW(NULL,path,MAX_PATH);
    if(!size || size>=MAX_PATH) return NULL;
    WCHAR *slash=wcsrchr(path,L'\\');
    if(!slash || (size_t)(slash-path)+sizeof(L"\\ca-bundle.crt")/sizeof(WCHAR)>MAX_PATH) return NULL;
    wcscpy(slash,L"\\ca-bundle.crt");
    if(GetFileAttributesW(path)==INVALID_FILE_ATTRIBUTES) return NULL;
    if(!WideCharToMultiByte(CP_UTF8,0,path,-1,utf8,sizeof(utf8),NULL,NULL)) utf8[0]=0;
    return utf8[0]?utf8:NULL;
}
#endif

#ifdef _WIN32
static LPFN_WSARECVMSG dnsp_wsa_recvmsg;
#endif
static inline bool dnsp_udp_prepare(dnsp_socket_t fd,bool wildcard) {
#ifdef _WIN32
    GUID id=WSAID_WSARECVMSG;
    DWORD bytes;
    if(WSAIoctl(fd,SIO_GET_EXTENSION_FUNCTION_POINTER,&id,sizeof(id),
                &dnsp_wsa_recvmsg,sizeof(dnsp_wsa_recvmsg),&bytes,NULL,NULL)!=0) return false;
    DWORD enabled=1;
    return !wildcard || setsockopt(fd,IPPROTO_IP,IP_PKTINFO,(const char*)&enabled,sizeof(enabled))==0;
#else
    int enabled=1;
    return !wildcard || setsockopt(fd,IPPROTO_IP,IP_PKTINFO,&enabled,sizeof(enabled))==0;
#endif
}
static inline dnsp_ssize_t dnsp_recv_udp(dnsp_socket_t fd,void *data,size_t size,
                                        struct sockaddr_storage *peer,dnsp_socklen_t *peer_len,
                                        UdpLocal *local,bool *truncated) {
#ifdef _WIN32
    WSABUF buffer={.len=(ULONG)size,.buf=data};
    union { WSACMSGHDR align;char bytes[WSA_CMSG_SPACE(sizeof(IN_PKTINFO))]; } control;
    WSAMSG msg={.name=(struct sockaddr*)peer,.namelen=*peer_len,.lpBuffers=&buffer,
                .dwBufferCount=1,.Control={.len=sizeof(control.bytes),.buf=control.bytes}};
    DWORD bytes=0;
    int result=dnsp_wsa_recvmsg(fd,&msg,&bytes,NULL,NULL);
    if(result!=0 && WSAGetLastError()!=WSAEMSGSIZE) return -1;
    *truncated=result!=0 || (msg.dwFlags&(MSG_TRUNC|MSG_CTRUNC));
    *peer_len=msg.namelen;
    if(*truncated) return (dnsp_ssize_t)bytes;
    for(WSACMSGHDR *c=WSA_CMSG_FIRSTHDR(&msg);c;c=WSA_CMSG_NXTHDR(&msg,c)) {
        if(c->cmsg_level==IPPROTO_IP && c->cmsg_type==IP_PKTINFO &&
           c->cmsg_len>=WSA_CMSG_LEN(sizeof(IN_PKTINFO))) {
            IN_PKTINFO info;
            memcpy(&info,WSA_CMSG_DATA(c),sizeof(info));
            *local=(UdpLocal){.destination=info.ipi_addr.s_addr,.source=info.ipi_addr.s_addr,
                              .interface_index=info.ipi_ifindex};
            break;
        }
    }
    return (dnsp_ssize_t)bytes;
#else
    struct iovec buffer={.iov_base=data,.iov_len=size};
    union { struct cmsghdr align;unsigned char bytes[CMSG_SPACE(sizeof(struct in_pktinfo))]; } control;
    struct msghdr msg={.msg_name=peer,.msg_namelen=*peer_len,.msg_iov=&buffer,.msg_iovlen=1,
                       .msg_control=control.bytes,.msg_controllen=sizeof(control.bytes)};
    ssize_t bytes=recvmsg(fd,&msg,0);
    if(bytes<0) return -1;
    *truncated=(msg.msg_flags&(MSG_TRUNC|MSG_CTRUNC))!=0;
    *peer_len=msg.msg_namelen;
    if(*truncated) return bytes;
    for(struct cmsghdr *c=CMSG_FIRSTHDR(&msg);c;c=CMSG_NXTHDR(&msg,c)) {
        if(c->cmsg_level==IPPROTO_IP && c->cmsg_type==IP_PKTINFO &&
           c->cmsg_len>=CMSG_LEN(sizeof(struct in_pktinfo))) {
            struct in_pktinfo info;
            memcpy(&info,CMSG_DATA(c),sizeof(info));
            *local=(UdpLocal){.destination=info.ipi_addr.s_addr,.source=info.ipi_spec_dst.s_addr};
            break;
        }
    }
    return bytes;
#endif
}
static inline dnsp_ssize_t dnsp_send_udp(dnsp_socket_t fd,const struct sockaddr *peer,
                                        dnsp_socklen_t peer_len,const void *prefix,size_t prefix_len,
                                        const void *body,size_t body_len,UdpLocal local) {
    uint32_t source=local.source;
#ifdef _WIN32
    if(!prefix_len && !source) return sendto(fd,(const char*)body,(int)body_len,0,peer,peer_len);
    WSABUF parts[]={{.len=(ULONG)prefix_len,.buf=(char*)prefix},
                   {.len=(ULONG)body_len,.buf=(char*)body}};
    union { WSACMSGHDR align;char bytes[WSA_CMSG_SPACE(sizeof(IN_PKTINFO))]; } control={0};
    WSAMSG msg={.name=(struct sockaddr*)peer,.namelen=peer_len,
                .lpBuffers=prefix_len?parts:parts+1,.dwBufferCount=prefix_len?2:1};
    if(source) {
        msg.Control=(WSABUF){.len=sizeof(control.bytes),.buf=control.bytes};
        WSACMSGHDR *c=WSA_CMSG_FIRSTHDR(&msg);
        c->cmsg_level=IPPROTO_IP;c->cmsg_type=IP_PKTINFO;c->cmsg_len=WSA_CMSG_LEN(sizeof(IN_PKTINFO));
        /* Pin the local address and let routing select the outgoing interface. */
        IN_PKTINFO info={.ipi_addr.s_addr=source};
        memcpy(WSA_CMSG_DATA(c),&info,sizeof(info));
    }
    DWORD bytes=0;
    return WSASendMsg(fd,&msg,0,&bytes,NULL,NULL)==0?(dnsp_ssize_t)bytes:-1;
#else
    if(!prefix_len && !source) return sendto(fd,body,body_len,0,peer,peer_len);
    struct iovec parts[]={{.iov_base=(void*)prefix,.iov_len=prefix_len},
                         {.iov_base=(void*)body,.iov_len=body_len}};
    union { struct cmsghdr align;unsigned char bytes[CMSG_SPACE(sizeof(struct in_pktinfo))]; } control={0};
    struct msghdr msg={.msg_name=(void*)peer,.msg_namelen=peer_len,
                       .msg_iov=prefix_len?parts:parts+1,.msg_iovlen=prefix_len?2:1};
    if(source) {
        msg.msg_control=control.bytes;msg.msg_controllen=sizeof(control.bytes);
        struct cmsghdr *c=CMSG_FIRSTHDR(&msg);
        c->cmsg_level=IPPROTO_IP;c->cmsg_type=IP_PKTINFO;c->cmsg_len=CMSG_LEN(sizeof(struct in_pktinfo));
        struct in_pktinfo info={.ipi_spec_dst.s_addr=source};
        memcpy(CMSG_DATA(c),&info,sizeof(info));
    }
    return sendmsg(fd,&msg,0);
#endif
}

#ifdef _WIN32
static void (*dnsp_stop_handler)(int);
static BOOL WINAPI dnsp_console_handler(DWORD event) {
    if(event==CTRL_C_EVENT || event==CTRL_BREAK_EVENT || event==CTRL_CLOSE_EVENT) {
        dnsp_stop_handler(0);
        return TRUE;
    }
    return FALSE;
}
#endif
static inline bool dnsp_install_handlers(void (*stop)(int),void (*report)(int)) {
#ifdef _WIN32
    (void)report; /* Windows exposes counters through the shared metrics listener. */
    dnsp_stop_handler=stop;
    return SetConsoleCtrlHandler(dnsp_console_handler,TRUE)!=0;
#else
    struct sigaction action={.sa_handler=report,.sa_flags=SA_RESTART};
    sigemptyset(&action.sa_mask);
    return sigaction(SIGUSR1,&action,NULL)==0 && signal(SIGINT,stop)!=SIG_ERR &&
           signal(SIGTERM,stop)!=SIG_ERR && signal(SIGPIPE,SIG_IGN)!=SIG_ERR;
#endif
}
#endif
