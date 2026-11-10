#define main dnsp_proxy_main
#include "../dnsp-modern.c"
#undef main

static bool udp_dispatch_is_bounded(void) {
    int fd[2];
    if(socketpair(AF_UNIX,SOCK_DGRAM,0,fd)<0) return false;
    /* Three invalid messages fit in the queue. Two cross the byte budget. */
    static const unsigned char datagram[UDP_BATCH_BYTES/2+1]={[2]=0x80};
    bool ok=nonblock(fd[1])==0;
    for(unsigned i=0;ok && i<3;i++)
        ok=send(fd[0],datagram,sizeof(datagram),MSG_DONTWAIT)==(ssize_t)sizeof(datagram);
    if(ok) {
        uint64_t before=metrics.invalid_queries;
        udp_io(fd[1]);
        ok=metrics.invalid_queries==before+2;
        udp_io(fd[1]);
        ok=ok && metrics.invalid_queries==before+3;
    }
    close(fd[0]);close(fd[1]);
    return ok;
}

static bool tcp_write_resumes_under_backpressure(void) {
    int fd[2];
    if(socketpair(AF_UNIX,SOCK_STREAM,0,fd)<0) return false;
    int send_buffer=4096;
    bool ok=setsockopt(fd[0],SOL_SOCKET,SO_SNDBUF,&send_buffer,sizeof(send_buffer))==0 &&
            nonblock(fd[0])==0 && nonblock(fd[1])==0;
    Client client={.fd=fd[0]};
    Query q={.client=&client};
    static unsigned char payload[TCP_MAX],wire[TCP_MAX+2];
    for(size_t i=0;i<sizeof(payload);i++) payload[i]=(unsigned char)(i^(i>>8));
    uint64_t satisfied=metrics.queries_satisfied;
    if(ok) {
        reply_dns(&q,payload,sizeof(payload),true);
        uint64_t deadline=client.write_deadline;
        tcp_io(&client,POLLOUT);
        size_t first_write=client.sent;
        tcp_io(&client,POLLOUT); /* No room in the socket until the peer reads. */
        ok=first_write>0 && first_write<sizeof(wire) && client.sent==first_write &&
           deadline && tcp_deadline(&client,TCP_IDLE_MS)==deadline && metrics.queries_satisfied==satisfied;

        size_t received=0;
        while(ok && received<sizeof(wire)) {
            ssize_t n=recv(fd[1],wire+received,sizeof(wire)-received,0);
            if(n<=0) {ok=false;break;}
            received+=(size_t)n;
            tcp_io(&client,POLLOUT);
        }
        ok=ok && !client.out && !client.write_deadline && metrics.queries_satisfied==satisfied+1 &&
           be16(wire)==sizeof(payload) && !memcmp(wire+2,payload,sizeof(payload));
    }
    if(ok) {
        reply_dns(&q,payload,sizeof(payload),true);
        ok=client.out!=NULL;
        close(fd[1]);fd[1]=-1;
        tcp_io(&client,POLLOUT);
        ok=ok && client.fd<0 && !client.out && metrics.queries_satisfied==satisfied+1;
    }
    close_client(&client);
    if(fd[1]>=0) close(fd[1]);
    return ok;
}

int main(void) {
    Query q={0};
    char body[]="dns";
    if(collect(body,1,0,&q)!=0 || q.response || q.resp_len) return 1;
    if(collect(body,1,3,&q)!=3 || q.resp_len!=3 || memcmp(q.response,body,3)) {
        free(q.response);
        return 2;
    }
    free(q.response);

    const curl_socket_t fd=5;
    if(on_curl_socket(NULL,fd,CURL_POLL_IN,NULL,NULL)) return 3;
    uint64_t old=curl_sockets[0].generation;
    if(!curl_socket_still_watched(fd,old)) return 4;
    if(on_curl_socket(NULL,fd,CURL_POLL_REMOVE,NULL,NULL) ||
       on_curl_socket(NULL,fd,CURL_POLL_IN,NULL,NULL)) return 5;
    if(curl_socket_still_watched(fd,old)) return 6;

    uint64_t current=curl_sockets[0].generation;
    if(!curl_socket_still_watched(fd,current) ||
       on_curl_socket(NULL,fd,CURL_POLL_OUT,NULL,NULL)) return 7;
    if(curl_socket_still_watched(fd,current)) return 8;

    if(select_http_version(0,0,false)!=CURL_HTTP_VERSION_1_1 ||
       select_http_version(CURL_VERSION_HTTP2,0,false)!=CURL_HTTP_VERSION_2TLS ||
       select_http_version(CURL_VERSION_HTTP2,0x075800,true)!=CURL_HTTP_VERSION_NONE) return 9;
#if LIBCURL_VERSION_NUM >= 0x074200
    const int h2h3=CURL_VERSION_HTTP2|CURL_VERSION_HTTP3;
    if(select_http_version(h2h3,0x075800,false)!=CURL_HTTP_VERSION_2TLS ||
       select_http_version(h2h3,0x075800,true)!=CURL_HTTP_VERSION_3 ||
       select_http_version(h2h3,0x075700,true)!=CURL_HTTP_VERSION_NONE) return 9;
#endif

    static Client client={.fd=1};
    const unsigned char request[]={
        0x12,0x34,1,0,0,1,0,0,0,0,0,0,0,0,1,0,1
    };
    active_count=MAX_ACTIVE;
    if(!submit(request,sizeof(request),&client,-1,NULL,0) || client.busy ||
       active_count!=MAX_ACTIVE || metrics.overload!=1) return 10;
    bool valid=client.out && client.out_len==sizeof(request)+2 && be16(client.out)==sizeof(request) &&
               be16(client.out+2)==0x1234 && (client.out[5]&15)==2;
    free(client.out);
    if(!valid) return 11;
    if(!udp_dispatch_is_bounded()) return 12;
    return tcp_write_resumes_under_backpressure()?0:13;
}
