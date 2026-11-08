#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdatomic.h>
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

/* DNS/DoH forwarder. All descriptors and CURL handles are
 * owned by one event loop. Do not call libcurl from another thread. */
enum { DNS_HEADER=12, UDP_RX_MAX=65507, UDP_REPLY_MAX=4096, TCP_MAX=65535,
       MAX_ACTIVE=128, MAX_CLIENTS=128,
       MAX_METRICS_CLIENTS=16, MAX_CURL_SOCKETS=1024, TCP_IDLE_MS=15000,
       TCP_IO_MS=15000, METRICS_IDLE_MS=3000, DOH_CONNECT_MS=1500, DOH_TIMEOUT_MS=3000 };
static volatile sig_atomic_t stopping;
/* A process signal can be delivered to a libcurl resolver thread. */
_Static_assert(ATOMIC_BOOL_LOCK_FREE==2,"SIGUSR1 requires a lock-free atomic flag");
static atomic_bool report_requested;
static void stop_now(int sig) { (void)sig; stopping=1; }
static void request_report(int sig) {
    (void)sig;
    atomic_store_explicit(&report_requested,true,memory_order_relaxed);
}
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
            if(target<DNS_HEADER || target>=at) return false; /* header or forward reference */
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
typedef enum { DNS_OK, DNS_DROP, DNS_FORMERR, DNS_NOTIMP } DnsResult;

/* Parse the DNS envelope without imposing a QTYPE or QCLASS allowlist.
 * Preserve a complete question for local errors, or use a header-only reply. */
static DnsResult dns_parse(const unsigned char *p,size_t n,const DnsInfo *request,DnsInfo *info) {
    bool response=request!=NULL;
    if(n<DNS_HEADER || n>TCP_MAX || !!(p[2]&0x80)!=response) return DNS_DROP;
    *info=(DnsInfo){.question_end=DNS_HEADER,.udp_limit=512,.opcode=(unsigned char)(p[2]&0x78)};
    if(response && info->opcode!=request->opcode) return DNS_FORMERR;
    if(!response && info->opcode!=0) return DNS_NOTIMP; /* single-exchange QUERY service */

    uint16_t questions=be16(p+4);
    if(questions>1 || (p[3]&0x40) || (!response && (p[3]&0x0f))) return DNS_FORMERR;
    size_t pos=DNS_HEADER;
    unsigned char name[256];size_t name_len=0;
    if(questions) {
        if(!dns_name(p,n,&pos,info->qname,&info->qname_len,response) || pos+4>n) return DNS_FORMERR;
        info->qtype=be16(p+pos);info->qclass=be16(p+pos+2);
        pos+=4;
        info->question_end=pos;
        if(response && (info->qname_len!=request->qname_len ||
           memcmp(info->qname,request->qname,info->qname_len)!=0 ||
           info->qtype!=request->qtype || info->qclass!=request->qclass)) return DNS_FORMERR;
    }

    size_t counts[3]={be16(p+6),be16(p+8),be16(p+10)};
    bool transfer=!response && (info->qtype==251 || info->qtype==252); /* IXFR, AXFR */
    if(!response && !transfer && (counts[0] || counts[1])) return DNS_FORMERR;
    for(size_t section=0;section<3;section++) {
        for(size_t i=0;i<counts[section];i++) {
            size_t owner=pos;
            if(!dns_name(p,n,&pos,name,&name_len,true) || pos+10>n) return DNS_FORMERR;
            uint16_t type=be16(p+pos),klass=be16(p+pos+2),rdlen=be16(p+pos+8);
            unsigned char ext_rcode=p[pos+4];
            bool opt_do=(p[pos+6]&0x80)!=0;
            pos+=10;
            if(type==41) {
                if(section!=2 || info->has_opt) return DNS_FORMERR;
                info->has_opt=true; /* retain a minimal OPT even for malformed option data */
                info->opt_ext_rcode=ext_rcode;info->opt_do=opt_do;
                if(!response) {
                    unsigned sz=klass<512?512:klass;
                    info->udp_limit=(uint16_t)(sz>UDP_REPLY_MAX?UDP_REPLY_MAX:sz);
                }
                if(p[owner]!=0 || rdlen>n-pos || !dns_opt_options(p,pos,pos+rdlen)) return DNS_FORMERR;
            } else if(rdlen>n-pos || !dns_rr_names(p,pos,pos+rdlen,type)) return DNS_FORMERR;
            pos+=rdlen;
        }
    }
    if(pos!=n) return DNS_FORMERR;
    if(response) {
        if(info->has_opt && !request->has_opt) return DNS_FORMERR;
        /* An upstream error or TC reply can omit the original question. */
        if(!questions && request->qname_len && !(p[2]&0x02) &&
           !(p[3]&0x0f) && !info->opt_ext_rcode) return DNS_FORMERR;
    }
    return transfer?DNS_NOTIMP:DNS_OK;
}

typedef struct Client Client;
typedef struct Query Query;
struct Client {
    int fd;size_t have,need,sent,out_len;
    unsigned char in[TCP_MAX+2],out[TCP_MAX+2];
    bool busy,read_eof,out_satisfies_query;uint64_t generation,queries_started;
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
typedef struct { curl_socket_t fd;int action;uint64_t generation; } CurlSocket;
typedef struct {
    uint64_t udp_queries,tcp_queries,queries_satisfied,invalid_queries,overload,upstream_requests,
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
static bool loopback_http;
static long upstream_http_version=CURL_HTTP_VERSION_1_1;
static struct curl_slist *bootstrap_hosts;
static const char *ca_file; /* optional additional trusted CA bundle; TLS checks remain enabled */
static Client clients[MAX_CLIENTS];
static CurlSocket curl_sockets[MAX_CURL_SOCKETS];
static size_t curl_socket_count;
static uint64_t curl_socket_generation;
static int64_t curl_deadline=-1;
static uint64_t tcp_idle_ms=TCP_IDLE_MS,tcp_io_ms=TCP_IO_MS;

typedef struct {
    int fd;uint64_t generation,last_ms;
    char request[512];size_t have;
    char reply[4096];size_t reply_len,sent;
} MetricClient;
static MetricClient metric_clients[MAX_METRICS_CLIENTS];

typedef enum {
    LOG_CAPACITY,LOG_SETUP,LOG_TIMEOUT,LOG_TRANSPORT,LOG_STATUS,LOG_CONTENT,LOG_DNS,LOG_COUNT
} Failure;
static void log_failure(Failure event,bool tcp,CURLcode code,long status) {
    static const char *const names[LOG_COUNT]={
        "capacity","upstream_setup","upstream_timeout","upstream_transport",
        "upstream_http_status","upstream_content_type","upstream_dns_response"
    };
    static struct {uint64_t next,suppressed;} rate[LOG_COUNT];
    uint64_t now=clock_ms();
    if(now<rate[event].next) {rate[event].suppressed++;return;}
    fprintf(stderr,"level=warning event=%s transport=%s curl_code=%d http_status=%ld suppressed=%llu\n",
            names[event],tcp?"tcp":"udp",(int)code,status,(unsigned long long)rate[event].suppressed);
    rate[event].next=now+10000;
    rate[event].suppressed=0;
}
static long select_http_version(int features) {
    return features&CURL_VERSION_HTTP2?CURL_HTTP_VERSION_2TLS:CURL_HTTP_VERSION_1_1;
}

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
    } else if(curl_sockets[i].action==what) return 0;
    curl_sockets[i]=(CurlSocket){.fd=fd,.action=what,.generation=++curl_socket_generation};
    return 0;
}
static int curl_timer_callback(CURLM *m,long timeout_ms,void *user) {
    (void)m;(void)user;
    metrics.timer_callbacks++;
    curl_deadline=timeout_ms<0?-1:(int64_t)clock_ms()+timeout_ms;
    return 0;
}
static bool curl_socket_still_watched(curl_socket_t fd,uint64_t generation) {
    for(size_t i=0;i<curl_socket_count;i++)
        if(curl_sockets[i].fd==fd) return curl_sockets[i].generation==generation;
    return false;
}
static size_t collect(char *p,size_t sz,size_t nm,void *arg) {
    Query *q=arg;
    if(nm && sz>SIZE_MAX/nm) return 0;
    size_t n=sz*nm;
    if(!n || n>TCP_MAX-q->resp_len) return 0;
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
    c->busy=c->read_eof=c->out_satisfies_query=false;c->generation++;c->queries_started=0;
    c->frame_deadline=c->write_deadline=0;
}
static void reply_dns(Query *q,const unsigned char *p,size_t n,bool satisfies_query) {
    if(q->client) {
        Client *c=q->client;
        if(c->fd>=0 && c->generation==q->generation) {
            c->out[0]=(unsigned char)(n>>8);c->out[1]=(unsigned char)n;
            memcpy(c->out+2,p,n);c->out_len=n+2;c->sent=0;
            c->out_satisfies_query=satisfies_query;
            c->write_deadline=clock_ms()+tcp_io_ms;
        }
    } else {
        ssize_t written=sendto(q->udp_fd,p,n,0,(struct sockaddr*)&q->peer,q->peer_len);
        if(satisfies_query && written==(ssize_t)n) metrics.queries_satisfied++;
    }
}
enum { DNS_OPT_SIZE=11 };
static size_t append_local_opt(const Query *q,unsigned char *p,size_t n,unsigned char ext_rcode) {
    if(!q->info.has_opt) return n;
    unsigned char opt[DNS_OPT_SIZE]={
        0,0,41, UDP_REPLY_MAX>>8,UDP_REPLY_MAX&0xff, ext_rcode,0, q->info.opt_do?0x80:0,0, 0,0
    };
    p[11]=1; /* The local OPT is the only additional record. */
    memcpy(p+n,opt,sizeof(opt));
    return n+sizeof(opt);
}
static void send_error(Query *q,const unsigned char *request,unsigned char rcode) {
    size_t length=q->info.question_end;
    if(length<DNS_HEADER || length>q->req_len) return;
    unsigned char p[512];
    if(length>sizeof(p)-DNS_OPT_SIZE) return;
    memcpy(p,request,length);
    p[2]=(unsigned char)((p[2]&0x79)|0x80); /* QR=1, clear TC/AA */
    p[3]=(unsigned char)((p[3]&0x10)|(rcode&0x0f));
    if(length==DNS_HEADER) p[4]=p[5]=0;
    memset(p+6,0,6);
    reply_dns(q,p,append_local_opt(q,p,length,0),false);
}
static void send_truncated(Query *q,const DnsInfo *response) {
    size_t n=q->info.question_end;
    unsigned char p[512];
    if(n>sizeof(p)-DNS_OPT_SIZE) {send_error(q,q->request,2);return;}
    memcpy(p,q->response,DNS_HEADER);
    p[2]|=0x02; /* TC: client can retry over TCP */
    p[3]&=(unsigned char)~0x20; /* no AD claim in a synthetic reply */
    p[4]=0;p[5]=n>DNS_HEADER;
    memset(p+6,0,6);
    memcpy(p+DNS_HEADER,q->request+DNS_HEADER,n-DNS_HEADER);
    reply_dns(q,p,append_local_opt(q,p,n,response->opt_ext_rcode),false);
    metrics.truncated++;
}
static bool dns_content_type(const char *type) {
    static const char media[]="application/dns-message";
    if(!type || strncasecmp(type,media,sizeof(media)-1)!=0) return false;
    type+=sizeof(media)-1;
    type+=strspn(type," \t");
    return *type==0 || *type==';';
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
    bool success_status=status>=200 && status<300;
    Failure failure=LOG_COUNT;
    if(code==CURLE_OPERATION_TIMEDOUT) failure=LOG_TIMEOUT;
    else if(code!=CURLE_OK) failure=LOG_TRANSPORT;
    else if(!success_status) failure=LOG_STATUS;
    else if(!dns_content_type(content_type)) failure=LOG_CONTENT;
    else if(q->resp_len<DNS_HEADER || be16(q->response)!=be16(q->request) ||
            dns_parse(q->response,q->resp_len,&q->info,&response)!=DNS_OK) failure=LOG_DNS;
    if(failure==LOG_COUNT) {
        metrics.upstream_ok++;
        if(!q->client && q->resp_len>q->info.udp_limit) send_truncated(q,&response);
        else {
            unsigned rcode=q->response[3]&0x0f;
            bool satisfies_query=!(q->response[2]&0x02) && !response.opt_ext_rcode &&
                                 (rcode==0 || rcode==3); /* Complete NOERROR or NXDOMAIN. */
            reply_dns(q,q->response,q->resp_len,satisfies_query);
        }
    } else {
        metrics.upstream_failed++;
        if(failure==LOG_TIMEOUT) metrics.upstream_timeouts++;
        if(failure==LOG_CONTENT || failure==LOG_DNS) metrics.invalid_responses++;
        log_failure(failure,q->client!=NULL,code,status);
        send_error(q,q->request,2);
    }
    if(q->client && q->client->fd>=0 && q->client->generation==q->generation)
        q->client->busy=false;
    remove_query(q);
}
static bool submit(const unsigned char *data,size_t len,Client *client,int udp_fd,
                   const struct sockaddr_storage *peer,socklen_t peer_len) {
    DnsInfo info;
    DnsResult result=dns_parse(data,len,NULL,&info);
    if(result==DNS_DROP) {metrics.invalid_queries++;return false;}
    Query pending={.req_len=len,.info=info,.client=client,.generation=client?client->generation:0,
                   .udp_fd=udp_fd,.peer_len=peer_len};
    if(peer) pending.peer=*peer;
    if(result!=DNS_OK) {
        if(result==DNS_FORMERR) metrics.invalid_queries++;
        send_error(&pending,data,result==DNS_NOTIMP?4:1);
        return true;
    }
    if(active_count>=MAX_ACTIVE) {
        log_failure(LOG_CAPACITY,client!=NULL,CURLE_OK,0);
        goto reject;
    }

    CURLcode setup_code=CURLE_OUT_OF_MEMORY;
    Query *q=malloc(sizeof(*q));
    if(!q) goto setup_failure;
    *q=pending;
    q->request=malloc(len);
    if(!q->request) goto fail;
    memcpy(q->request,data,len);
    q->easy=curl_easy_init();
    if(!q->easy) goto fail;
    struct curl_slist *h=curl_slist_append(q->headers,"Content-Type: application/dns-message");
    if(!h) goto fail;
    q->headers=h;
    h=curl_slist_append(q->headers,"Accept: application/dns-message");
    if(!h) goto fail;
    q->headers=h;
#define OPT(key,val) do {setup_code=curl_easy_setopt(q->easy,key,val);if(setup_code!=CURLE_OK) goto fail;}while(0)
    OPT(CURLOPT_URL,upstream);
    if(loopback_http || bootstrap_hosts) OPT(CURLOPT_PROXY,"");
    if(bootstrap_hosts) OPT(CURLOPT_RESOLVE,bootstrap_hosts);
    OPT(CURLOPT_HTTPHEADER,q->headers);
    OPT(CURLOPT_POSTFIELDS,q->request);
    OPT(CURLOPT_POSTFIELDSIZE_LARGE,(curl_off_t)len);
    OPT(CURLOPT_HTTP_VERSION,upstream_http_version);
    OPT(CURLOPT_WRITEFUNCTION,collect);
    OPT(CURLOPT_WRITEDATA,q);
    OPT(CURLOPT_PRIVATE,q);
    OPT(CURLOPT_TIMEOUT_MS,(long)DOH_TIMEOUT_MS);
    OPT(CURLOPT_CONNECTTIMEOUT_MS,(long)DOH_CONNECT_MS);
    OPT(CURLOPT_SSL_VERIFYPEER,1L);
    OPT(CURLOPT_SSL_VERIFYHOST,2L);
    if(ca_file) OPT(CURLOPT_CAINFO,ca_file);
    OPT(CURLOPT_FOLLOWLOCATION,0L);
    OPT(CURLOPT_NOSIGNAL,1L);
#undef OPT
    if(curl_multi_add_handle(multi,q->easy)!=CURLM_OK) {
        setup_code=CURLE_FAILED_INIT;
        goto fail;
    }
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
setup_failure:
    log_failure(LOG_SETUP,client!=NULL,setup_code,0);
reject:
    metrics.overload++;
    send_error(&pending,data,2);
    return true; /* A local reply is queued for a valid TCP query. */
}
static int listener(const char *role,int type,const char *bindip,int port) {
    struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons((uint16_t)port)};
    if(inet_pton(AF_INET,bindip,&a.sin_addr)!=1) {
        fprintf(stderr,"level=error event=listener_address role=%s port=%d\n",role,port);
        return -1;
    }
    int fd=socket(AF_INET,type,0),yes=1;
    if(fd>=0) {
        setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes));
        if(nonblock(fd)==0 && bind(fd,(struct sockaddr*)&a,sizeof(a))==0 &&
           (type!=SOCK_STREAM || listen(fd,128)==0)) return fd;
    }
    int error=errno;
    if(fd>=0) close(fd);
    fprintf(stderr,"level=error event=listener_failed role=%s port=%d errno=%d message=%s\n",
            role,port,error,strerror(error));
    return -1;
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
            if(c->out_satisfies_query) metrics.queries_satisfied++;
            c->out_satisfies_query=false;
            c->out_len=c->sent=0;
            c->write_deadline=0;
            c->idle_since_ms=clock_ms();
            if(c->need && c->have==c->need && !start_tcp_query(c)) return;
            if(c->read_eof && !c->busy && !c->out_len) close_client(c);
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
        if(length<DNS_HEADER) {close_client(c);return;}
        c->need=length+2;
    }
    if(c->need && c->have==c->need) {
        c->frame_deadline=0;
        if(c->busy || c->out_len) metrics.tcp_pipeline_buffered++;
        else (void)start_tcp_query(c);
    }
}
static void udp_io(int fd) {
    static unsigned char buf[UDP_RX_MAX]; /* maximum IPv4 UDP payload */
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
    CURLMcode code=curl_multi_socket_action(multi,fd,events,&running);
    if(code!=CURLM_OK) {
        fprintf(stderr,"level=error event=curl_multi_action code=%d message=%s\n",
                (int)code,curl_multi_strerror(code));
        return false;
    }
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
static void report_status(uint64_t uptime_ms,const char *bindip,int port,int metrics_port,
                          const char *http_preference,int max_host_connections) {
    fprintf(stderr,"level=info event=stats uptime_ms=%" PRIu64
            " address=%s port=%d metrics_port=%d upstream_scheme=%s http_preference=%s bootstrap=%s"
            " max_host_connections=%d doh_connect_ms=%d doh_timeout_ms=%d"
            " tcp_idle_ms=%" PRIu64 " tcp_io_ms=%" PRIu64
            " queries_satisfied=%" PRIu64 " udp_queries=%" PRIu64 " tcp_queries=%" PRIu64
            " upstream_ok=%" PRIu64 " upstream_failed=%" PRIu64 " upstream_timeouts=%" PRIu64
            " invalid_queries=%" PRIu64 " invalid_responses=%" PRIu64 " overload=%" PRIu64
            " udp_truncated=%" PRIu64 " tcp_cancelled_upstream=%" PRIu64
            " http1_responses=%" PRIu64 " http2_responses=%" PRIu64
            " new_connections=%" PRIu64 " reused_requests=%" PRIu64
            " inflight=%zu max_inflight=%d tcp_clients=%zu max_tcp_clients=%d\n",
            uptime_ms,bindip,port,metrics_port,loopback_http?"http":"https",http_preference,
            bootstrap_hosts?"enabled":"disabled",max_host_connections,DOH_CONNECT_MS,DOH_TIMEOUT_MS,
            tcp_idle_ms,tcp_io_ms,metrics.queries_satisfied,metrics.udp_queries,metrics.tcp_queries,
            metrics.upstream_ok,metrics.upstream_failed,metrics.upstream_timeouts,
            metrics.invalid_queries,metrics.invalid_responses,metrics.overload,metrics.truncated,
            metrics.tcp_cancelled_upstream,metrics.http1,metrics.http2,metrics.requests_new_connections,
            metrics.requests_reused_connections,active_count,MAX_ACTIVE,tcp_open_count(),MAX_CLIENTS);
}
static void metric_response(MetricClient *c) {
#define METRIC(...) do {int z=snprintf(c->reply+c->reply_len,sizeof(c->reply)-c->reply_len,__VA_ARGS__); \
    if(z<0 || (size_t)z>=sizeof(c->reply)-c->reply_len) {close_metric(c);return;} \
    c->reply_len+=(size_t)z;} while(0)
    char body[3072];int n=snprintf(body,sizeof(body),
        "# TYPE dnsp_queries_total counter\n"
        "dnsp_queries_total{transport=\"udp\"} %llu\n"
        "dnsp_queries_total{transport=\"tcp\"} %llu\n"
        "# TYPE dnsp_queries_satisfied_total counter\n"
        "dnsp_queries_satisfied_total %" PRIu64 "\n"
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
        metrics.queries_satisfied,
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
static bool configure_bootstrap(CURLU *url,const char *host,const char *address) {
    struct in_addr addr4;
    struct in6_addr addr6;
    bool ipv6=inet_pton(AF_INET6,address,&addr6)==1;
    if(!ipv6 && inet_pton(AF_INET,address,&addr4)!=1) return false;
    if(host[0]=='[' || inet_pton(AF_INET,host,&addr4)==1) return false;

    char *port=NULL;
    if(curl_url_get(url,CURLUPART_PORT,&port,CURLU_DEFAULT_PORT)!=CURLUE_OK) return false;
    char entry[512];
    int n=snprintf(entry,sizeof(entry),"%s:%s:%s%s%s",host,port,
                   ipv6?"[":"",address,ipv6?"]":"");
    curl_free(port);
    if(n<0 || (size_t)n>=sizeof(entry)) return false;

    bootstrap_hosts=curl_slist_append(NULL,entry);
    return bootstrap_hosts!=NULL;
}
static bool configure_upstream(const char *s,const char *bootstrap_address) {
    CURLU *url=curl_url();
    char *scheme=NULL,*host=NULL;
    if(!url) return false;
    bool ok=curl_url_set(url,CURLUPART_URL,s,0)==CURLUE_OK &&
            curl_url_get(url,CURLUPART_SCHEME,&scheme,0)==CURLUE_OK &&
            curl_url_get(url,CURLUPART_HOST,&host,0)==CURLUE_OK;
    if(ok && !strcasecmp(scheme,"https")) {
        if(bootstrap_address) ok=configure_bootstrap(url,host,bootstrap_address);
    } else {
        loopback_http=ok && !strcasecmp(scheme,"http") && !strcmp(host,"127.0.0.1");
        ok=loopback_http && !bootstrap_address;
    }
    curl_free(scheme);curl_free(host);curl_url_cleanup(url);
    return ok;
}
static int parse_port(const char *s) {
    char *end=NULL;errno=0;long v=strtol(s,&end,10);
    return errno || end==s || *end || v<1 || v>65535 ? -1 : (int)v;
}
int main(int argc,char **argv) {
    const char *bindip="127.0.0.1",*bootstrap_address=NULL;
    int port=5300,metrics_port=0;
    int max_host_connections=8;
    upstream="https://cloudflare-dns.com/dns-query";
    for(int i=1;i<argc;i++) {
        if(!strcmp(argv[i],"-l") && i+1<argc) bindip=argv[++i];
        else if(!strcmp(argv[i],"-p") && i+1<argc) port=parse_port(argv[++i]);
        else if(!strcmp(argv[i],"-s") && i+1<argc) upstream=argv[++i];
        else if(!strcmp(argv[i],"--bootstrap-address")) {
            if(i+1==argc) {fprintf(stderr,"--bootstrap-address requires an IPv4 or IPv6 address\n");return 2;}
            bootstrap_address=argv[++i];
        }
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
    struct sigaction report_action={.sa_handler=request_report,.sa_flags=SA_RESTART};
    sigemptyset(&report_action.sa_mask);
    if(sigaction(SIGUSR1,&report_action,NULL)<0) {
        perror("sigaction SIGUSR1");return 1;
    }
    CURLcode global_code=curl_global_init(CURL_GLOBAL_DEFAULT);
    if(global_code!=CURLE_OK) {
        fprintf(stderr,"level=error event=curl_global_init code=%d\n",(int)global_code);
        return 1;
    }
    const curl_version_info_data *curl_info=curl_version_info(CURLVERSION_NOW);
    if(curl_info) upstream_http_version=select_http_version(curl_info->features);
    if(!configure_upstream(upstream,bootstrap_address)) {
        if(bootstrap_address) fprintf(stderr,"--bootstrap-address requires a numeric IP and an HTTPS upstream hostname\n");
        else fprintf(stderr,"invalid upstream (only HTTPS or loopback HTTP test endpoint)\n");
        curl_global_cleanup();return 2;
    }
    signal(SIGINT,stop_now);signal(SIGTERM,stop_now);signal(SIGPIPE,SIG_IGN);
    for(size_t i=0;i<MAX_CLIENTS;i++) clients[i].fd=-1;
    for(size_t i=0;i<MAX_METRICS_CLIENTS;i++) metric_clients[i].fd=-1;
    multi=curl_multi_init();
    if(!multi) {
        fprintf(stderr,"level=error event=curl_multi_init\n");
        curl_slist_free_all(bootstrap_hosts);
        curl_global_cleanup();
        return 1;
    }
    int udp=-1,tcp=-1,mfd=-1,exitcode=1;
    PollItem *items=NULL;
    struct pollfd *pfds=NULL;
#define MULTI_OPT(key,val) do { \
    CURLMcode code=curl_multi_setopt(multi,key,val); \
    if(code!=CURLM_OK) { \
        fprintf(stderr,"level=error event=curl_multi_setopt option=%s code=%d\n",#key,(int)code); \
        goto cleanup; \
    } \
} while(0)
    MULTI_OPT(CURLMOPT_MAX_TOTAL_CONNECTIONS,16L);
    MULTI_OPT(CURLMOPT_MAX_HOST_CONNECTIONS,(long)max_host_connections);
    MULTI_OPT(CURLMOPT_PIPELINING,upstream_http_version==CURL_HTTP_VERSION_2TLS?CURLPIPE_MULTIPLEX:CURLPIPE_NOTHING);
    MULTI_OPT(CURLMOPT_SOCKETFUNCTION,on_curl_socket);
    MULTI_OPT(CURLMOPT_TIMERFUNCTION,curl_timer_callback);
#undef MULTI_OPT
    udp=listener("dns_udp",SOCK_DGRAM,bindip,port);
    if(udp<0) goto cleanup;
    tcp=listener("dns_tcp",SOCK_STREAM,bindip,port);
    if(tcp<0) goto cleanup;
    if(metrics_port) {
        mfd=listener("metrics",SOCK_STREAM,"127.0.0.1",metrics_port);
        if(mfd<0) goto cleanup;
    }
    const size_t cap=3+MAX_CLIENTS+MAX_METRICS_CLIENTS+MAX_CURL_SOCKETS;
    items=calloc(cap,sizeof(*items));
    pfds=calloc(cap,sizeof(*pfds));
    if(!items || !pfds) {
        fprintf(stderr,"level=error event=poll_allocation\n");
        goto cleanup;
    }
    const char *http_preference=upstream_http_version==CURL_HTTP_VERSION_2TLS && !loopback_http?"h2":"http/1.1";
    uint64_t started_ms=clock_ms();
    fprintf(stderr,"level=info event=listening address=%s port=%d metrics_port=%d upstream_scheme=%s http_preference=%s\n",
            bindip,port,metrics_port,loopback_http?"http":"https",http_preference);
    exitcode=0;
    while(!stopping) {
        uint64_t now=clock_ms();
        if(atomic_load_explicit(&report_requested,memory_order_relaxed)) {
            atomic_store_explicit(&report_requested,false,memory_order_relaxed);
            report_status(now-started_ms,bindip,port,metrics_port,http_preference,max_host_connections);
        }
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
            ADD(P_CURL,curl_sockets[i].fd,ev,0,curl_sockets[i].generation);
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
                    if(curl_socket_still_watched(items[i].p.fd,items[i].generation)) {
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
cleanup:
    free(items);free(pfds);
    for(size_t i=0;i<MAX_CLIENTS;i++) close_client(&clients[i]);
    for(size_t i=0;i<MAX_METRICS_CLIENTS;i++) close_metric(&metric_clients[i]);
    while(active) remove_query(active);
    if(udp>=0) close(udp);
    if(tcp>=0) close(tcp);
    if(mfd>=0) close(mfd);
    curl_multi_cleanup(multi);
    curl_slist_free_all(bootstrap_hosts);
    curl_global_cleanup();
    return exitcode;
}
