#define _GNU_SOURCE
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "../dnsp-platform.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

static bool exchange(const char *address,bool truncate) {
    dnsp_socket_t server=socket(AF_INET,SOCK_DGRAM,0),client=socket(AF_INET,SOCK_DGRAM,0);
    bool ok=false;
    if(server==DNSP_BAD_SOCKET || client==DNSP_BAD_SOCKET) goto cleanup;
    struct sockaddr_in target={.sin_family=AF_INET},origin={.sin_family=AF_INET};
#ifndef _WIN32
    inet_pton(AF_INET,"127.0.0.1",&origin.sin_addr);
#endif
    if(bind(server,(struct sockaddr*)&target,sizeof(target))!=0 ||
       bind(client,(struct sockaddr*)&origin,sizeof(origin))!=0 ||
       nonblock(server)!=0 || nonblock(client)!=0 || !dnsp_udp_prepare(server,AF_INET,true)) goto cleanup;
    dnsp_socklen_t length=sizeof(target);
    if(getsockname(server,(struct sockaddr*)&target,&length)!=0) goto cleanup;
    inet_pton(AF_INET,address,&target.sin_addr);
    if(dnsp_send_udp(client,(struct sockaddr*)&target,sizeof(target),NULL,0,"request",7,(UdpLocal){0})!=7)
        goto cleanup;
    dnsp_pollfd ready={.fd=server,.events=POLLIN};
    if(dnsp_poll(&ready,1,1000)!=1) goto cleanup;
    unsigned char data[16];
    struct sockaddr_storage peer;
    dnsp_socklen_t peer_len=sizeof(peer);
    UdpLocal local={0};bool cut=false;
    dnsp_ssize_t received=dnsp_recv_udp(server,data,truncate?4:sizeof(data),&peer,&peer_len,&local,&cut);
    printf("destination=%s received=%td truncated=%d local=%08" PRIx32 " interface=%" PRIu32 "\n",
           address,received,cut,(uint32_t)ntohl(local.source),local.interface_index);
    if(received<0 || cut!=truncate) goto cleanup;
    if(truncate) {ok=true;goto cleanup;}
    if(local.source!=target.sin_addr.s_addr || received!=7 || memcmp(data,"request",7)) goto cleanup;
    if(dnsp_send_udp(server,(struct sockaddr*)&peer,peer_len,"re",2,"ply",3,local)!=5) goto cleanup;
    ready=(dnsp_pollfd){.fd=client,.events=POLLIN};
    if(dnsp_poll(&ready,1,1000)!=1) goto cleanup;
    peer_len=sizeof(peer);
    received=dnsp_recv_udp(client,data,sizeof(data),&peer,&peer_len,&local,&cut);
    ok=received==5 && !cut && !memcmp(data,"reply",5) &&
       ((struct sockaddr_in*)&peer)->sin_addr.s_addr==target.sin_addr.s_addr;
cleanup:
    if(!ok) fprintf(stderr,"platform UDP exchange failed address=%s socket_error=%d message=%s\n",
                    address,dnsp_socket_error(),dnsp_socket_message(dnsp_socket_error()));
    if(server!=DNSP_BAD_SOCKET) dnsp_close(server);
    if(client!=DNSP_BAD_SOCKET) dnsp_close(client);
    return ok;
}

static bool exchange6(bool truncate) {
    dnsp_socket_t server=socket(AF_INET6,SOCK_DGRAM,0),client=socket(AF_INET6,SOCK_DGRAM,0);
    bool ok=false;
    struct sockaddr_in6 target={.sin6_family=AF_INET6};
    if(server==DNSP_BAD_SOCKET || client==DNSP_BAD_SOCKET ||
       bind(server,(struct sockaddr*)&target,sizeof(target))!=0 ||
       nonblock(server)!=0 || nonblock(client)!=0 || !dnsp_udp_prepare(server,AF_INET6,true)) goto cleanup;
    dnsp_socklen_t length=sizeof(target);
    if(getsockname(server,(struct sockaddr*)&target,&length)!=0 ||
       inet_pton(AF_INET6,"::1",&target.sin6_addr)!=1) goto cleanup;
    if(dnsp_send_udp(client,(struct sockaddr*)&target,sizeof(target),NULL,0,"request",7,(UdpLocal){0})!=7) goto cleanup;
    dnsp_pollfd ready={.fd=server,.events=POLLIN};
    if(dnsp_poll(&ready,1,1000)!=1) goto cleanup;
    char data[16];struct sockaddr_storage peer={0};dnsp_socklen_t size=sizeof(peer);
    UdpLocal local={0};bool cut=false;
    dnsp_ssize_t count=dnsp_recv_udp(server,data,truncate?4:sizeof(data),&peer,&size,&local,&cut);
    if(count<0 || cut!=truncate) goto cleanup;
    if(truncate) {ok=true;goto cleanup;}
    if(count!=7 || !local.ipv6 || memcmp(&local.source6,&target.sin6_addr,sizeof(local.source6))) goto cleanup;
    if(dnsp_send_udp(server,(struct sockaddr*)&peer,size,"re",2,"ply",3,local)!=5) goto cleanup;
    ready=(dnsp_pollfd){.fd=client,.events=POLLIN};
    if(dnsp_poll(&ready,1,1000)!=1) goto cleanup;
    size=sizeof(peer);
    count=dnsp_recv_udp(client,data,sizeof(data),&peer,&size,&local,&cut);
    ok=count==5 && !cut && !memcmp(data,"reply",5) && peer.ss_family==AF_INET6 &&
       !memcmp(&((struct sockaddr_in6*)&peer)->sin6_addr,&target.sin6_addr,sizeof(target.sin6_addr));
cleanup:
    if(server!=DNSP_BAD_SOCKET) dnsp_close(server);
    if(client!=DNSP_BAD_SOCKET) dnsp_close(client);
    if(!ok) fprintf(stderr,"IPv6 packet metadata exchange failed\n");
    return ok;
}
static bool scoped_addresses(void) {
    struct sockaddr_storage a={0},b={0};
    struct sockaddr_in6 x={.sin6_family=AF_INET6,.sin6_port=htons(53),.sin6_scope_id=3};
    inet_pton(AF_INET6,"fe80::1",&x.sin6_addr);
    memcpy(&a,&x,sizeof(x));memcpy(&b,&x,sizeof(x));
    if(!dnsp_same_peer(&a,&b)) return false;
    ((struct sockaddr_in6*)&b)->sin6_scope_id=4;
    if(dnsp_same_ip(&a,&b)) return false;
    ((struct sockaddr_in6*)&b)->sin6_scope_id=3;
    ((struct sockaddr_in6*)&b)->sin6_port=htons(54);
    return dnsp_same_ip(&a,&b) && !dnsp_same_peer(&a,&b);
}

static bool ipv6_available(void) {
    dnsp_socket_t fd=socket(AF_INET6,SOCK_DGRAM,0);
    if(fd==DNSP_BAD_SOCKET) return false;
    struct sockaddr_in6 local={.sin6_family=AF_INET6};
    inet_pton(AF_INET6,"::1",&local.sin6_addr);
    bool ok=bind(fd,(struct sockaddr*)&local,sizeof(local))==0;
    dnsp_close(fd);
    return ok;
}
int main(void) {
    if(curl_global_init(CURL_GLOBAL_DEFAULT)!=CURLE_OK) return 1;
    const char *second=getenv("DNSP_TEST_SECOND_ADDRESS");
    if(!second || !*second) second="127.0.0.2";
    bool v6=ipv6_available();
    const char *required=getenv("DNSP_REQUIRE_IPV6");
    if(!v6) fprintf(stderr,"IPv6 loopback unavailable%s\n",required && !strcmp(required,"1")?" (required)":" (IPv6 exchanges skipped)");
    bool ok=exchange("127.0.0.1",true) && exchange("127.0.0.1",false) && exchange(second,false) &&
            scoped_addresses() && (v6 ? exchange6(true) && exchange6(false) : !(required && !strcmp(required,"1")));
    curl_global_cleanup();
    return ok?0:1;
}
