#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

/* Experimental DNS/DoH forwarder. All descriptors and CURL handles are
 * owned by one event loop. Do not call libcurl from another thread. */
enum { DNS_MAX=4096, TCP_MAX=65535, MAX_ACTIVE=128, MAX_CLIENTS=128,
       MAX_METRICS_CLIENTS=16, MAX_CURL_SOCKETS=1024, TCP_IDLE_MS=15000,
       TCP_IO_MS=15000, METRICS_IDLE_MS=3000 };
static volatile sig_atomic_t stopping;
static void stop_now(int sig) { (void)sig; stopping=1; }
static int nonblock(int fd) { int f=fcntl(fd,F_GETFL,0); return f<0?-1:fcntl(fd,F_SETFL,f|O_NONBLOCK); }
static uint16_t be16(const unsigned char *p) { return (uint16_t)(((unsigned)p[0]<<8)|p[1]); }
static uint64_t clock_ms(void) {
    struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC,&t)!=0) return 0;
    return (uint64_t)t.tv_sec*1000u+(uint64_t)t.tv_nsec/1000000u;
}

/* Expand DNS names, rejecting out-of-bounds and forward compression pointers.
 * The expanded wire representation is case-folded for QNAME comparison only. */
static bool dns_name(const unsigned char *p,size_t n,size_t *offset,
                     unsigned char out[256],size_t *outlen,bool compression) {
    size_t at=*offset, end=0, used=0;
    bool jumped=false;
    for(unsigned hops=0;hops<128;hops++) {
        if(at>=n) return false;
        unsigned len=p[at];
        if((len&0xc0)==0xc0) {
            if(!compression || at+1>=n) return false;
            size_t target=((size_t)(len&0x3f)<<8)|p[at+1];
            if(target<12 || target>=at) return false; /* header or forward reference */
            if(!jumped) end=at+2;
            at=target; jumped=true;
            continue;
        }
        if(len&0xc0 || len>63 || at+1+len>n || used+1+len>255) return false;
        out[used++]=(unsigned char)len;
        for(unsigned k=0;k<len;k++) {
            unsigned char c=p[at+1+k];
            out[used++]=(c>='A' && c<='Z')?(unsigned char)(c+('a'-'A')):c;
        }
        at+=1+len;
        if(!len) { *offset=jumped?end:at; *outlen=used; return true; }
    }
    return false;
}
/* Check name fields in common RDATA formats. Keep unknown types opaque. */
static bool dns_rr_names(const unsigned char *p,size_t pos,size_t end,uint16_t type) {
    bool compression=true;
    size_t prefix=0,tail=0;
    unsigned names=1;
    switch(type) {
        case 2: case 5: case 12: break; /* NS, CNAME, PTR */
        case 6: names=2;tail=20;break; /* SOA */
        case 15: prefix=2;break; /* MX */
        case 33: prefix=6;break; /* SRV, accept older senders using compression */
        case 39: compression=false;break; /* DNAME */
        default: return true;
    }
    if(end-pos<prefix+tail) return false;
    pos+=prefix;
    end-=tail;
    unsigned char name[256];size_t name_len;
    for(unsigned i=0;i<names;i++) if(!dns_name(p,end,&pos,name,&name_len,compression)) return false;
    return pos==end;
}
static bool dns_opt_options(const unsigned char *p,size_t pos,size_t end) {
    while(pos<end) {
        if(end-pos<4) return false;
        size_t len=be16(p+pos+2);
        pos+=4;
        if(len>end-pos) return false;
        pos+=len;
    }
    return true;
}
typedef struct {
    size_t question_end;
    uint16_t udp_limit;
    uint16_t qtype,qclass;
    unsigned char qname[256]; size_t qname_len;
    unsigned char opcode,opt_ext_rcode;
    bool has_opt,opt_do;
} DnsInfo;
static bool dns_parse(const unsigned char *p,size_t n,bool response,
                      const DnsInfo *request,DnsInfo *info) {
    if(n<17 || (n>TCP_MAX) || !!(p[2]&0x80)!=response || be16(p+4)!=1 || (p[3]&0x40)) return false;
    if(!response && (be16(p+6)!=0 || be16(p+8)!=0)) return false;
    unsigned char opcode=(unsigned char)(p[2]&0x78);
    if(response && (!request || opcode!=request->opcode)) return false;
    if(!response && (opcode!=0 || (p[3]&0x0f)!=0)) return false; /* standard QUERY only */
    size_t pos=12;
    unsigned char name[256]; size_t name_len=0;
    if(!dns_name(p,n,&pos,name,&name_len,response) || pos+4>n) return false;
    uint16_t qt=be16(p+pos),qc=be16(p+pos+2);
    pos+=4;
    if(response && (name_len!=request->qname_len ||
        memcmp(name,request->qname,name_len)!=0 || qt!=request->qtype || qc!=request->qclass)) return false;
    info->question_end=pos; info->udp_limit=512;
    info->has_opt=info->opt_do=false;info->opt_ext_rcode=0;
    info->qtype=qt;info->qclass=qc;info->opcode=opcode;
    info->qname_len=name_len; memcpy(info->qname,name,name_len);
    size_t counts[3]={be16(p+6),be16(p+8),be16(p+10)};
    for(size_t section=0;section<3;section++) {
        for(size_t i=0;i<counts[section];i++) {
            size_t owner=pos;
            if(!dns_name(p,n,&pos,name,&name_len,true) || pos+10>n) return false;
            uint16_t type=be16(p+pos),klass=be16(p+pos+2),rdlen=be16(p+pos+8);
            unsigned char ext_rcode=p[pos+4];
            bool opt_do=(p[pos+6]&0x80)!=0;
            pos+=10;
            if(rdlen>n-pos) return false;
            size_t end=pos+rdlen;
            if(type==41) { /* EDNS OPT: one literal root owner in ADDITIONAL */
                if(section!=2 || info->has_opt || p[owner]!=0 || !dns_opt_options(p,pos,end)) return false;
                info->has_opt=true;
                info->opt_ext_rcode=ext_rcode;
                info->opt_do=opt_do;
                if(!response) {
                    unsigned sz=klass;
                    if(sz<512) sz=512;
                    info->udp_limit=(uint16_t)(sz>DNS_MAX?DNS_MAX:sz);
                }
            } else if(!dns_rr_names(p,pos,end,type)) return false;
            pos=end;
        }
    }
    return pos==n; /* reject trailing garbage and truncated RRs */
}

typedef struct Client Client;
typedef struct Query Query;
struct Client {
    int fd;size_t have,need,sent,out_len;
    unsigned char in[TCP_MAX+2],out[TCP_MAX+2];
    bool busy,read_eof;uint64_t generation,queries_started;
    uint64_t idle_since_ms,frame_deadline,write_deadline;
};
struct Query {
    CURL *easy;struct curl_slist *headers;
    unsigned char *request,*response;
    size_t req_len,resp_len,resp_cap;
    DnsInfo info;
    struct sockaddr_storage peer;socklen_t peer_len;
    Client *client;uint64_t generation;int udp_fd;
    Query *next;
};
typedef struct { curl_socket_t fd;int action; } CurlSocket;
typedef struct {
    uint64_t udp_queries,tcp_queries,invalid_queries,overload,upstream_requests,
      upstream_ok,upstream_failed,upstream_timeouts,invalid_responses,
      truncated,requests_new_connections,requests_reused_connections,
      http1,http2,http3,socket_callbacks,timer_callbacks,timer_fires,
      tcp_accepted,tcp_closed,tcp_keepalive_queries,tcp_pipeline_buffered,
      tcp_half_closes,tcp_idle_timeouts,tcp_io_timeouts,tcp_cancelled_upstream;
    double upstream_seconds;
} Metrics;
static Metrics metrics;
static Query *active;
static size_t active_count;
static CURLM *multi;
static const char *upstream;
static const char *ca_file; /* optional additional trusted CA bundle; TLS checks remain enabled */
static Client clients[MAX_CLIENTS];
static CurlSocket curl_sockets[MAX_CURL_SOCKETS];
static size_t curl_socket_count;
static int64_t curl_deadline=-1;
static uint64_t tcp_idle_ms=TCP_IDLE_MS,tcp_io_ms=TCP_IO_MS;

typedef struct {
    int fd;uint64_t generation,last_ms;
    char request[512];size_t have;
    char reply[4096];size_t reply_len,sent;
} MetricClient;
static MetricClient metric_clients[MAX_METRICS_CLIENTS];

static int on_curl_socket(CURL *easy,curl_socket_t fd,int what,void *user,void *socketp) {
    (void)easy;(void)user;(void)socketp;
    metrics.socket_callbacks++;
    size_t i=0;
    while(i<curl_socket_count && curl_sockets[i].fd!=fd) i++;
    if(what==CURL_POLL_REMOVE) {
        if(i<curl_socket_count) curl_sockets[i]=curl_sockets[--curl_socket_count];
        return 0;
    }
    if(i==curl_socket_count) {
        if(curl_socket_count==MAX_CURL_SOCKETS) return -1;
        curl_socket_count++;
        curl_sockets[i].fd=fd;
    }
    curl_sockets[i].action=what;
    return 0;
}
static int curl_timer_callback(CURLM *m,long timeout_ms,void *user) {
    (void)m;(void)user;
    metrics.timer_callbacks++;
    curl_deadline=timeout_ms<0?-1:(int64_t)clock_ms()+timeout_ms;
    return 0;
}
static bool curl_socket_still_watched(curl_socket_t fd) {
    for(size_t i=0;i<curl_socket_count;i++) if(curl_sockets[i].fd==fd) return true;
    return false;
}
static size_t collect(char *p,size_t sz,size_t nm,void *arg) {
    Query *q=arg;
    if(nm && sz>SIZE_MAX/nm) return 0;
    size_t n=sz*nm;
    if(n>TCP_MAX-q->resp_len) return 0;
    if(q->resp_len+n>q->resp_cap) {
        size_t cap=q->resp_cap?q->resp_cap:512;
        while(cap<q->resp_len+n) cap*=2;
        if(cap>TCP_MAX) cap=TCP_MAX;
        void *newp=realloc(q->response,cap);
        if(!newp) return 0;
        q->response=newp;q->resp_cap=cap;
    }
    memcpy(q->response+q->resp_len,p,n);q->resp_len+=n;
    return n;
}
static void remove_query(Query *q) {
    Query **it=&active;
    while(*it && *it!=q) it=&(*it)->next;
    if(*it) {*it=q->next;active_count--;}
    if(q->easy) {curl_multi_remove_handle(multi,q->easy);curl_easy_cleanup(q->easy);}
    curl_slist_free_all(q->headers);
    free(q->request);free(q->response);free(q);
}
static void close_client(Client *c) {
    uint64_t gen=c->generation;
    Query *q=active;
    while(q) {
        Query *next=q->next;
        if(q->client==c && q->generation==gen) {
            metrics.tcp_cancelled_upstream++;
            remove_query(q);
        }
        q=next;
    }
    if(c->fd>=0) {close(c->fd);metrics.tcp_closed++;}
    c->fd=-1;c->have=c->need=c->sent=c->out_len=0;
    c->busy=c->read_eof=false;c->generation++;c->queries_started=0;
    c->frame_deadline=c->write_deadline=0;
}
static void reply_dns(Query *q,const unsigned char *p,size_t n) {
    if(q->client) {
        Client *c=q->client;
        if(c->fd>=0 && c->generation==q->generation) {
            c->out[0]=(unsigned char)(n>>8);c->out[1]=(unsigned char)n;
            memcpy(c->out+2,p,n);c->out_len=n+2;c->sent=0;
            c->write_deadline=clock_ms()+tcp_io_ms;
        }
    } else sendto(q->udp_fd,p,n,0,(struct sockaddr*)&q->peer,q->peer_len);
}
enum { DNS_OPT_SIZE=11 };
static size_t append_local_opt(const Query *q,unsigned char *p,size_t n,unsigned char ext_rcode) {
    if(!q->info.has_opt) return n;
    unsigned char opt[DNS_OPT_SIZE]={
        0,0,41, DNS_MAX>>8,DNS_MAX&0xff, ext_rcode,0, q->info.opt_do?0x80:0,0, 0,0
    };
    p[11]=1; /* The local OPT is the only additional record. */
    memcpy(p+n,opt,sizeof(opt));
    return n+sizeof(opt);
}
static void send_error(Query *q,unsigned char rcode) {
    size_t length=q->info.question_end;
    if(length<17 || length>q->req_len) return;
    unsigned char p[512];
    if(length>sizeof(p)-DNS_OPT_SIZE) return;
    memcpy(p,q->request,length);
    p[2]=(unsigned char)((p[2]&0x79)|0x80); /* QR=1, clear TC/AA */
    p[3]=(unsigned char)((p[3]&0x10)|(rcode&0x0f));
    memset(p+6,0,6);
    reply_dns(q,p,append_local_opt(q,p,length,0));
}
static void send_truncated(Query *q,const DnsInfo *response) {
    size_t n=q->info.question_end;
    unsigned char p[512];
    if(n>sizeof(p)-DNS_OPT_SIZE) {send_error(q,2);return;}
    memcpy(p,q->response,12);
    p[2]|=0x02; /* TC: client can retry over TCP */
    p[4]=0;p[5]=1;
    memset(p+6,0,6);
    memcpy(p+12,q->request+12,n-12);
    reply_dns(q,p,append_local_opt(q,p,n,response->opt_ext_rcode));
    metrics.truncated++;
}
static void complete(Query *q,CURLcode code) {
    long status=0,version=0,connects=0;
    char *content_type=NULL;
    double seconds=0;
    curl_easy_getinfo(q->easy,CURLINFO_RESPONSE_CODE,&status);
    curl_easy_getinfo(q->easy,CURLINFO_HTTP_VERSION,&version);
    curl_easy_getinfo(q->easy,CURLINFO_NUM_CONNECTS,&connects);
    curl_easy_getinfo(q->easy,CURLINFO_TOTAL_TIME,&seconds);
    curl_easy_getinfo(q->easy,CURLINFO_CONTENT_TYPE,&content_type);
    if(seconds>0) metrics.upstream_seconds+=seconds;
    if(connects>0) metrics.requests_new_connections+=(uint64_t)connects;
    else if(code==CURLE_OK) metrics.requests_reused_connections++;
    if(version==CURL_HTTP_VERSION_1_0 || version==CURL_HTTP_VERSION_1_1) metrics.http1++;
    else if(version==CURL_HTTP_VERSION_2_0) metrics.http2++;
#ifdef CURL_HTTP_VERSION_3
    else if(version==CURL_HTTP_VERSION_3) metrics.http3++;
#endif
    DnsInfo response;
    bool ok=code==CURLE_OK && status==200 && content_type &&
            strncasecmp(content_type,"application/dns-message",23)==0 &&
            (content_type[23]==0 || content_type[23]==';') && q->resp_len>=12 &&
            q->response[0]==q->request[0] && q->response[1]==q->request[1] &&
            dns_parse(q->response,q->resp_len,true,&q->info,&response);
    if(ok) {
        metrics.upstream_ok++;
        if(!q->client && q->resp_len>q->info.udp_limit) send_truncated(q,&response);
        else reply_dns(q,q->response,q->resp_len);
    } else {
        metrics.upstream_failed++;
        if(code==CURLE_OPERATION_TIMEDOUT) metrics.upstream_timeouts++;
        if(code==CURLE_OK && status==200) metrics.invalid_responses++;
        send_error(q,2);
    }
    if(q->client && q->client->fd>=0 && q->client->generation==q->generation)
        q->client->busy=false;
    remove_query(q);
}
static bool submit(const unsigned char *data,size_t len,Client *client,int udp_fd,
                   const struct sockaddr_storage *peer,socklen_t peer_len) {
    DnsInfo info;
    if(!dns_parse(data,len,false,NULL,&info)) {metrics.invalid_queries++;return false;}
    if(active_count>=MAX_ACTIVE) {metrics.overload++;return false;}
    Query *q=calloc(1,sizeof(*q));if(!q) {metrics.overload++;return false;}
    q->request=malloc(len);
    if(!q->request) {free(q);metrics.overload++;return false;}
    memcpy(q->request,data,len);q->req_len=len;q->info=info;
    q->client=client;q->generation=client?client->generation:0;q->udp_fd=udp_fd;
    if(peer) {q->peer=*peer;q->peer_len=peer_len;}
    q->easy=curl_easy_init();
    if(!q->easy) goto fail;
    struct curl_slist *h=curl_slist_append(q->headers,"Content-Type: application/dns-message");
    if(!h) goto fail;
    q->headers=h;
    h=curl_slist_append(q->headers,"Accept: application/dns-message");
    if(!h) goto fail;
    q->headers=h;
#define OPT(key,val) do {if(curl_easy_setopt(q->easy,key,val)!=CURLE_OK) goto fail;}while(0)
    OPT(CURLOPT_URL,upstream);
    OPT(CURLOPT_HTTPHEADER,q->headers);
    OPT(CURLOPT_POSTFIELDS,q->request);
    OPT(CURLOPT_POSTFIELDSIZE_LARGE,(curl_off_t)len);
    OPT(CURLOPT_HTTP_VERSION,CURL_HTTP_VERSION_2TLS);
    OPT(CURLOPT_WRITEFUNCTION,collect);
    OPT(CURLOPT_WRITEDATA,q);
    OPT(CURLOPT_PRIVATE,q);
    OPT(CURLOPT_TIMEOUT_MS,3000L);
    OPT(CURLOPT_CONNECTTIMEOUT_MS,1500L);
    OPT(CURLOPT_SSL_VERIFYPEER,1L);
    OPT(CURLOPT_SSL_VERIFYHOST,2L);
    if(ca_file) OPT(CURLOPT_CAINFO,ca_file);
    OPT(CURLOPT_FOLLOWLOCATION,0L);
    OPT(CURLOPT_NOSIGNAL,1L);
#undef OPT
    if(curl_multi_add_handle(multi,q->easy)!=CURLM_OK) goto fail;
    q->next=active;active=q;active_count++;
    metrics.upstream_requests++;
    if(client) {
        if(client->queries_started++>0) metrics.tcp_keepalive_queries++;
        client->busy=true;metrics.tcp_queries++;
    }
    else metrics.udp_queries++;
    return true;
fail:
    if(q->easy) curl_easy_cleanup(q->easy);
    curl_slist_free_all(q->headers);free(q->request);free(q);
    metrics.overload++;return false;
}
static int listener(int type,const char *bindip,int port) {
    int fd=socket(AF_INET,type,0),yes=1;
    if(fd<0) return -1;
    setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes));
    struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons((uint16_t)port)};
    if(inet_pton(AF_INET,bindip,&a.sin_addr)!=1 || nonblock(fd)<0 ||
       bind(fd,(struct sockaddr*)&a,sizeof(a))<0 ||
       (type==SOCK_STREAM && listen(fd,128)<0)) {close(fd);return -1;}
    return fd;
}
/* At most one in-flight query and one fully buffered successor per TCP
 * connection. Framing reads stop exactly at a message boundary: further
 * pipelined messages stay in the kernel receive buffer (backpressure).
 * Responses are emitted in request order. */
static bool start_tcp_query(Client *c) {
    if(c->fd<0 || c->busy || c->out_len || !c->need || c->have!=c->need) return true;
    if(!submit(c->in+2,c->need-2,c,-1,NULL,0)) {
        close_client(c);
        return false;
    }
    c->have=c->need=0; /* submit() owns a copy of the complete wire request */
    return true;
}
static short tcp_events(const Client *c) {
    short ev=0;
    if(c->out_len) ev|=POLLOUT;
    /* No POLLIN when a complete successor frame is buffered: avoid spin. */
    if(!c->read_eof && (!c->need || c->have<c->need)) ev|=POLLIN;
    return ev;
}
static void tcp_io(Client *c,short events) {
    if(c->fd<0) return;
    if(c->out_len && (events&POLLOUT)) {
        ssize_t n=send(c->fd,c->out+c->sent,c->out_len-c->sent,MSG_NOSIGNAL);
        if(n>0) c->sent+=(size_t)n;
        else if(n<0 && (errno==EAGAIN || errno==EINTR)) return;
        else {close_client(c);return;}
        if(c->sent==c->out_len) {
            c->out_len=c->sent=0;
            c->write_deadline=0;
            c->idle_since_ms=clock_ms();
            if(c->need && c->have==c->need && !start_tcp_query(c)) return;
            if(c->read_eof && !c->busy) close_client(c);
        }
    }
    if(c->fd<0 || c->read_eof ||
       (c->need && c->have==c->need) || !(events&POLLIN)) return;
    size_t target=c->need?c->need:2;
    ssize_t n=recv(c->fd,c->in+c->have,target-c->have,0);
    if(n==0) {
        c->read_eof=true;
        metrics.tcp_half_closes++;
        /* A half-closed writer may still be waiting to read its replies. */
        if(c->have && (!c->need || c->have!=c->need)) {close_client(c);return;}
        if(!c->busy && !c->out_len) close_client(c);
        return;
    }
    if(n<0) {if(errno!=EAGAIN && errno!=EINTR) close_client(c);return;}
    if(!c->have) c->frame_deadline=clock_ms()+tcp_io_ms;
    c->have+=(size_t)n;
    if(c->have==2 && !c->need) {
        size_t length=be16(c->in);
        if(length<17 || length>TCP_MAX) {close_client(c);return;}
        c->need=length+2;
    }
    if(c->need && c->have==c->need) {
        c->frame_deadline=0;
        if(c->busy || c->out_len) metrics.tcp_pipeline_buffered++;
        else (void)start_tcp_query(c);
    }
}
static void udp_io(int fd) {
    unsigned char buf[DNS_MAX];
    for(int i=0;i<32;i++) {
        struct sockaddr_storage peer={0};
        struct iovec iov={.iov_base=buf,.iov_len=sizeof(buf)};
        struct msghdr msg={.msg_name=&peer,.msg_namelen=sizeof(peer),.msg_iov=&iov,.msg_iovlen=1};
        ssize_t n=recvmsg(fd,&msg,0);
        if(n<0) break;
        if(msg.msg_flags&MSG_TRUNC) {metrics.invalid_queries++;continue;}
        (void)submit(buf,(size_t)n,NULL,fd,&peer,msg.msg_namelen);
    }
}
static void drain_completions(void) {
    int remaining;CURLMsg *msg;
    while((msg=curl_multi_info_read(multi,&remaining))) {
        if(msg->msg==CURLMSG_DONE) {
            Query *q=NULL;
            curl_easy_getinfo(msg->easy_handle,CURLINFO_PRIVATE,&q);
            if(q) complete(q,msg->data.result);
        }
    }
}
static bool drive_curl(curl_socket_t fd,int events) {
    int running;
    if(curl_multi_socket_action(multi,fd,events,&running)!=CURLM_OK) return false;
    drain_completions();
    return true;
}
static void close_metric(MetricClient *c) {
    if(c->fd>=0) close(c->fd);
    c->fd=-1;c->have=c->reply_len=c->sent=0;c->generation++;
}
static size_t tcp_open_count(void) {
    size_t n=0;for(size_t i=0;i<MAX_CLIENTS;i++) if(clients[i].fd>=0) n++;
    return n;
}
static void metric_response(MetricClient *c) {
#define METRIC(...) do {int z=snprintf(c->reply+c->reply_len,sizeof(c->reply)-c->reply_len,__VA_ARGS__); \
    if(z<0 || (size_t)z>=sizeof(c->reply)-c->reply_len) {close_metric(c);return;} \
    c->reply_len+=(size_t)z;} while(0)
    char body[3072];int n=snprintf(body,sizeof(body),
        "# TYPE dnsp_queries_total counter\n"
        "dnsp_queries_total{transport=\"udp\"} %llu\n"
        "dnsp_queries_total{transport=\"tcp\"} %llu\n"
        "# TYPE dnsp_tcp_connections_accepted_total counter\n"
        "dnsp_tcp_connections_accepted_total %llu\n"
        "# TYPE dnsp_tcp_connections_closed_total counter\n"
        "dnsp_tcp_connections_closed_total %llu\n"
        "# TYPE dnsp_tcp_keepalive_queries_total counter\n"
        "dnsp_tcp_keepalive_queries_total %llu\n"
        "# TYPE dnsp_tcp_pipeline_buffered_total counter\n"
        "dnsp_tcp_pipeline_buffered_total %llu\n"
        "# TYPE dnsp_tcp_half_closes_total counter\n"
        "dnsp_tcp_half_closes_total %llu\n"
        "# TYPE dnsp_tcp_idle_timeouts_total counter\n"
        "dnsp_tcp_idle_timeouts_total %llu\n"
        "# TYPE dnsp_tcp_io_timeouts_total counter\n"
        "dnsp_tcp_io_timeouts_total %llu\n"
        "# TYPE dnsp_tcp_cancelled_upstream_total counter\n"
        "dnsp_tcp_cancelled_upstream_total %llu\n"
        "# TYPE dnsp_upstream_requests_total counter\n"
        "dnsp_upstream_requests_total %llu\n"
        "dnsp_upstream_success_total %llu\n"
        "dnsp_upstream_failures_total %llu\n"
        "dnsp_upstream_timeouts_total %llu\n"
        "dnsp_invalid_queries_total %llu\n"
        "dnsp_invalid_responses_total %llu\n"
        "dnsp_overload_total %llu\n"
        "dnsp_truncated_responses_total %llu\n"
        "dnsp_upstream_new_connections_total %llu\n"
        "dnsp_upstream_reused_requests_total %llu\n"
        "dnsp_upstream_http_responses_total{version=\"1\"} %llu\n"
        "dnsp_upstream_http_responses_total{version=\"2\"} %llu\n"
        "dnsp_upstream_http_responses_total{version=\"3\"} %llu\n"
        "dnsp_curl_socket_callbacks_total %llu\n"
        "dnsp_curl_timer_callbacks_total %llu\n"
        "dnsp_curl_timer_fires_total %llu\n"
        "# TYPE dnsp_upstream_duration_seconds_sum counter\n"
        "dnsp_upstream_duration_seconds_sum %.6f\n"
        "dnsp_upstream_duration_seconds_count %llu\n"
        "# TYPE dnsp_queries_inflight gauge\n"
        "dnsp_queries_inflight %zu\n"
        "dnsp_tcp_clients %zu\n"
        "dnsp_curl_socket_watches %zu\n",
        (unsigned long long)metrics.udp_queries,(unsigned long long)metrics.tcp_queries,
        (unsigned long long)metrics.tcp_accepted,(unsigned long long)metrics.tcp_closed,
        (unsigned long long)metrics.tcp_keepalive_queries,
        (unsigned long long)metrics.tcp_pipeline_buffered,
        (unsigned long long)metrics.tcp_half_closes,
        (unsigned long long)metrics.tcp_idle_timeouts,
        (unsigned long long)metrics.tcp_io_timeouts,
        (unsigned long long)metrics.tcp_cancelled_upstream,
        (unsigned long long)metrics.upstream_requests,(unsigned long long)metrics.upstream_ok,
        (unsigned long long)metrics.upstream_failed,(unsigned long long)metrics.upstream_timeouts,
        (unsigned long long)metrics.invalid_queries,(unsigned long long)metrics.invalid_responses,
        (unsigned long long)metrics.overload,(unsigned long long)metrics.truncated,
        (unsigned long long)metrics.requests_new_connections,
        (unsigned long long)metrics.requests_reused_connections,
        (unsigned long long)metrics.http1,(unsigned long long)metrics.http2,
        (unsigned long long)metrics.http3,(unsigned long long)metrics.socket_callbacks,
        (unsigned long long)metrics.timer_callbacks,(unsigned long long)metrics.timer_fires,
        metrics.upstream_seconds,
        (unsigned long long)(metrics.upstream_ok+metrics.upstream_failed),
        active_count,tcp_open_count(),curl_socket_count);
    if(n<0 || (size_t)n>=sizeof(body)) {close_metric(c);return;}
    METRIC("HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\n"
           "Connection: close\r\nContent-Length: %d\r\n\r\n",n);
    METRIC("%s",body);
#undef METRIC
}
static void metric_io(MetricClient *c,short events) {
    if(c->fd<0) return;
    if(!c->reply_len && (events&POLLIN)) {
        ssize_t n=recv(c->fd,c->request+c->have,sizeof(c->request)-c->have,0);
        if(n<=0) {if(n==0 || (errno!=EAGAIN && errno!=EINTR)) close_metric(c);return;}
        c->have+=(size_t)n;c->last_ms=clock_ms();
        if(c->have>=sizeof(c->request)) {close_metric(c);return;}
        c->request[c->have]=0;
        if(strstr(c->request,"\r\n\r\n")) {
            if(strncmp(c->request,"GET /metrics HTTP/1.",19)==0) metric_response(c);
            else close_metric(c); /* loopback-only diagnostic endpoint */
        }
    }
    if(c->fd>=0 && c->reply_len && (events&POLLOUT)) {
        ssize_t n=send(c->fd,c->reply+c->sent,c->reply_len-c->sent,MSG_NOSIGNAL);
        if(n>0) {c->sent+=(size_t)n;c->last_ms=clock_ms();}
        else if(n<0 && (errno==EAGAIN || errno==EINTR)) return;
        else {close_metric(c);return;}
        if(c->sent==c->reply_len) close_metric(c);
    }
}
static void accept_tcp(int server,bool is_metrics) {
    for(int i=0;i<16;i++) {
        int fd=accept(server,NULL,NULL);
        if(fd<0) break;
        if(nonblock(fd)<0) {close(fd);continue;}
        if(is_metrics) {
            size_t j=0;while(j<MAX_METRICS_CLIENTS && metric_clients[j].fd>=0) j++;
            if(j==MAX_METRICS_CLIENTS) close(fd);
            else {uint64_t g=metric_clients[j].generation+1;
                  metric_clients[j]=(MetricClient){.fd=fd,.generation=g,.last_ms=clock_ms()};}
        } else {
            size_t j=0;while(j<MAX_CLIENTS && clients[j].fd>=0) j++;
            if(j==MAX_CLIENTS) close(fd);
            else {uint64_t g=clients[j].generation+1;
                  clients[j]=(Client){.fd=fd,.generation=g,.idle_since_ms=clock_ms()};
                  metrics.tcp_accepted++;}
        }
    }
}
typedef enum {P_UDP,P_TCP_LISTEN,P_METRIC_LISTEN,P_TCP_CLIENT,P_METRIC_CLIENT,P_CURL} PollType;
typedef struct {struct pollfd p;PollType kind;size_t idx;uint64_t generation;} PollItem;
static uint64_t tcp_deadline(const Client *c) {
    if(c->frame_deadline && (!c->write_deadline || c->frame_deadline<c->write_deadline))
        return c->frame_deadline;
    if(c->write_deadline) return c->write_deadline;
    if(c->busy) return 0; /* libcurl owns the in-flight deadline */
    return c->idle_since_ms+tcp_idle_ms;
}
static void expire_clients(uint64_t now) {
    for(size_t i=0;i<MAX_CLIENTS;i++) if(clients[i].fd>=0) {
        Client *c=&clients[i];
        uint64_t deadline=tcp_deadline(c);
        if(!deadline || now<deadline) continue;
        if(c->frame_deadline || c->write_deadline) metrics.tcp_io_timeouts++;
        else metrics.tcp_idle_timeouts++;
        close_client(c);
    }
    for(size_t i=0;i<MAX_METRICS_CLIENTS;i++) if(metric_clients[i].fd>=0 &&
       now-metric_clients[i].last_ms>METRICS_IDLE_MS) close_metric(&metric_clients[i]);
}
static bool valid_upstream_url(const char *s) {
    CURLU *url=curl_url();
    char *scheme=NULL,*host=NULL;
    if(!url) return false;
    bool ok=curl_url_set(url,CURLUPART_URL,s,0)==CURLUE_OK &&
            curl_url_get(url,CURLUPART_SCHEME,&scheme,0)==CURLUE_OK &&
            curl_url_get(url,CURLUPART_HOST,&host,0)==CURLUE_OK;
    if(ok) ok=!strcasecmp(scheme,"https") ||
              (!strcasecmp(scheme,"http") && !strcmp(host,"127.0.0.1"));
    curl_free(scheme);curl_free(host);curl_url_cleanup(url);
    return ok;
}
static int parse_port(const char *s) {
    char *end=NULL;errno=0;long v=strtol(s,&end,10);
    return errno || end==s || *end || v<1 || v>65535 ? -1 : (int)v;
}
int main(int argc,char **argv) {
    const char *bindip="127.0.0.1";int port=5300,metrics_port=0;
    int max_host_connections=8;
    upstream="https://cloudflare-dns.com/dns-query";
    for(int i=1;i<argc;i++) {
        if(!strcmp(argv[i],"-l") && i+1<argc) bindip=argv[++i];
        else if(!strcmp(argv[i],"-p") && i+1<argc) port=parse_port(argv[++i]);
        else if(!strcmp(argv[i],"-s") && i+1<argc) upstream=argv[++i];
        else if(!strcmp(argv[i],"-m") && i+1<argc) metrics_port=parse_port(argv[++i]);
        else if(!strcmp(argv[i],"--ca-file") && i+1<argc) ca_file=argv[++i];
        else if((!strcmp(argv[i],"--tcp-idle-ms") || !strcmp(argv[i],"--tcp-io-ms")) && i+1<argc) {
            const char *option=argv[i],*raw=argv[++i];char *end=NULL;errno=0;
            unsigned long v=strtoul(raw,&end,10);
            if(errno || end==raw || *end || v<100 || v>600000) {
                fprintf(stderr,"invalid %s (100..600000)\n",option);return 2;
            }
            if(!strcmp(option,"--tcp-idle-ms")) tcp_idle_ms=v;
            else tcp_io_ms=v;
        }
        else if(!strcmp(argv[i],"--max-host-connections") && i+1<argc)
            max_host_connections=parse_port(argv[++i]);
        else {fprintf(stderr,"usage: %s [-l IPv4] [-p port] [-s https://DoH-URL] [-m loopback-metrics-port] [--ca-file PEM] [--max-host-connections 1..16] [--tcp-idle-ms 100..600000] [--tcp-io-ms 100..600000]\n",argv[0]);return 2;}
    }
    if(port<1 || port>65535 || metrics_port<0 || metrics_port>65535 || metrics_port==port ||
       max_host_connections<1 || max_host_connections>16) {
        fprintf(stderr,"invalid port\n");return 2;
    }
    if(curl_global_init(CURL_GLOBAL_DEFAULT)!=CURLE_OK) return 1;
    if(!valid_upstream_url(upstream)) {
        fprintf(stderr,"invalid upstream (only HTTPS or loopback HTTP test endpoint)\n");
        curl_global_cleanup();return 2;
    }
    signal(SIGINT,stop_now);signal(SIGTERM,stop_now);signal(SIGPIPE,SIG_IGN);
    for(size_t i=0;i<MAX_CLIENTS;i++) clients[i].fd=-1;
    for(size_t i=0;i<MAX_METRICS_CLIENTS;i++) metric_clients[i].fd=-1;
    multi=curl_multi_init();if(!multi) {curl_global_cleanup();return 1;}
    curl_multi_setopt(multi,CURLMOPT_MAX_TOTAL_CONNECTIONS,16L);
    curl_multi_setopt(multi,CURLMOPT_MAX_HOST_CONNECTIONS,(long)max_host_connections);
    curl_multi_setopt(multi,CURLMOPT_PIPELINING,CURLPIPE_MULTIPLEX);
    curl_multi_setopt(multi,CURLMOPT_SOCKETFUNCTION,on_curl_socket);
    curl_multi_setopt(multi,CURLMOPT_TIMERFUNCTION,curl_timer_callback);
    int udp=listener(SOCK_DGRAM,bindip,port);
    int tcp=listener(SOCK_STREAM,bindip,port);
    int mfd=metrics_port?listener(SOCK_STREAM,"127.0.0.1",metrics_port):-1;
    if(udp<0 || tcp<0 || (metrics_port && mfd<0)) {perror("listen");return 1;}
    fprintf(stderr,"DNSProxy modern listening %s:%d -> %s; metrics %s\n",
            bindip,port,upstream,metrics_port?"enabled on loopback":"disabled");
    int exitcode=0;
    const size_t cap=3+MAX_CLIENTS+MAX_METRICS_CLIENTS+MAX_CURL_SOCKETS;
    PollItem *items=calloc(cap,sizeof(*items));
    struct pollfd *pfds=calloc(cap,sizeof(*pfds));
    if(!items || !pfds) {free(items);free(pfds);return 1;}
    while(!stopping) {
        uint64_t now=clock_ms();
        if(curl_deadline>=0 && (int64_t)now>=curl_deadline) {
            metrics.timer_fires++;
            if(!drive_curl(CURL_SOCKET_TIMEOUT,0)) {exitcode=1;break;}
        }
        size_t n=0;
#define ADD(kind_,fd_,events_,idx_,gen_) do {items[n++]=(PollItem){.p={.fd=(fd_),.events=(events_)},.kind=(kind_),.idx=(idx_),.generation=(gen_)};}while(0)
        ADD(P_UDP,udp,POLLIN,0,0);
        ADD(P_TCP_LISTEN,tcp,POLLIN,0,0);
        if(mfd>=0) ADD(P_METRIC_LISTEN,mfd,POLLIN,0,0);
        for(size_t i=0;i<MAX_CLIENTS;i++) if(clients[i].fd>=0) {
            /* Even events=0 reports resets/errors while reads are paused. */
            ADD(P_TCP_CLIENT,clients[i].fd,tcp_events(&clients[i]),i,clients[i].generation);
        }
        for(size_t i=0;i<MAX_METRICS_CLIENTS;i++) if(metric_clients[i].fd>=0)
            ADD(P_METRIC_CLIENT,metric_clients[i].fd,metric_clients[i].reply_len?POLLOUT:POLLIN,i,metric_clients[i].generation);
        for(size_t i=0;i<curl_socket_count;i++) {
            short ev=0;
            if(curl_sockets[i].action&CURL_POLL_IN) ev|=POLLIN;
            if(curl_sockets[i].action&CURL_POLL_OUT) ev|=POLLOUT;
            ADD(P_CURL,curl_sockets[i].fd,ev,0,0);
        }
#undef ADD
        int timeout=1000; /* signals and client idle expiry */
        if(curl_deadline>=0) {
            int64_t left=curl_deadline-(int64_t)now;
            if(left<0) left=0;
            if(left<timeout) timeout=(int)left;
        }
        for(size_t i=0;i<MAX_CLIENTS;i++) if(clients[i].fd>=0) {
            uint64_t deadline=tcp_deadline(&clients[i]);
            if(!deadline) continue;
            uint64_t left=now>=deadline?0:deadline-now;
            if(left<(uint64_t)timeout) timeout=(int)left;
        }
        for(size_t i=0;i<n;i++) pfds[i]=items[i].p;
        int result=poll(pfds,n,timeout);
        for(size_t i=0;i<n;i++) items[i].p.revents=pfds[i].revents;
        if(result<0 && errno!=EINTR) {perror("poll");exitcode=1;break;}
        expire_clients(clock_ms());
        if(result>0) for(size_t i=0;i<n;i++) {
            short re=items[i].p.revents;
            if(!re) continue;
            switch(items[i].kind) {
                case P_UDP:if(re&POLLIN) udp_io(udp);break;
                case P_TCP_LISTEN:if(re&POLLIN) accept_tcp(tcp,false);break;
                case P_METRIC_LISTEN:if(re&POLLIN) accept_tcp(mfd,true);break;
                case P_TCP_CLIENT: {
                    Client *c=&clients[items[i].idx];
                    if(c->fd!=items[i].p.fd || c->generation!=items[i].generation) break;
                    if(re&(POLLERR|POLLNVAL|POLLHUP)) close_client(c);
                    else tcp_io(c,re); /* Peer SHUT_WR arrives as readable EOF. */
                    break;
                }
                case P_METRIC_CLIENT: {
                    MetricClient *c=&metric_clients[items[i].idx];
                    if(c->fd!=items[i].p.fd || c->generation!=items[i].generation) break;
                    if(re&(POLLERR|POLLHUP|POLLNVAL)) close_metric(c);
                    else metric_io(c,re);
                    break;
                }
                case P_CURL:
                    if(curl_socket_still_watched(items[i].p.fd)) {
                        int ev=0;
                        if(re&POLLIN) ev|=CURL_CSELECT_IN;
                        if(re&POLLOUT) ev|=CURL_CSELECT_OUT;
                        if(re&(POLLERR|POLLHUP|POLLNVAL)) ev|=CURL_CSELECT_ERR;
                        if(!drive_curl(items[i].p.fd,ev)) {exitcode=1;stopping=1;}
                    }
                    break;
            }
            if(stopping) break;
        }
    }
    free(items);free(pfds);
    for(size_t i=0;i<MAX_CLIENTS;i++) close_client(&clients[i]);
    for(size_t i=0;i<MAX_METRICS_CLIENTS;i++) close_metric(&metric_clients[i]);
    while(active) remove_query(active);
    close(udp);close(tcp);if(mfd>=0) close(mfd);
    curl_multi_cleanup(multi);curl_global_cleanup();
    return exitcode;
}
