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
enum { DNS_HEADER=12, UDP_RX_MAX=65507, UDP_REPLY_MAX=4096, UDP_REPLY_DEFAULT=1232, TCP_MAX=65535,
       MAX_ACTIVE=128, MAX_CLIENTS=128, MAX_UDP_WAITERS=8,
       MAX_METRICS_CLIENTS=16, MAX_CURL_SOCKETS=1024, TCP_IDLE_MS=15000,
       TCP_IO_MS=15000, METRICS_IDLE_MS=3000, DOH_CONNECT_MS=1500, DOH_TIMEOUT_MS=3000,
       MIN_TIMEOUT_MS=100, MAX_DOH_TIMEOUT_MS=60000, MAX_TCP_TIMEOUT_MS=600000,
       DNS_OPT_SIZE=11, CACHE_MAX_ENTRIES=1024, CACHE_MAX_QUERY=DNS_HEADER+255+4+DNS_OPT_SIZE,
       CACHE_MAX_REPLY=4096, CACHE_MAX_ANSWERS=128, CACHE_MAX_TTL=3600 };
enum { MAX_IDLE_EASIES=16 };
static unsigned udp_reply_max=UDP_REPLY_DEFAULT;
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
static uint32_t be32(const unsigned char *p) { return ((uint32_t)be16(p)<<16)|be16(p+2); }
static uint64_t read_clock_ms(clockid_t clock_id) {
    struct timespec t;
    if(clock_gettime(clock_id,&t)!=0) return 0;
    return (uint64_t)t.tv_sec*1000u+(uint64_t)t.tv_nsec/1000000u;
}
static uint64_t clock_ms(void) { return read_clock_ms(CLOCK_MONOTONIC); }

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
    size_t final_opt_rdlen;
    uint16_t udp_limit;
    uint16_t qtype,qclass;
    unsigned char qname[256]; size_t qname_len;
    unsigned char opcode,opt_ext_rcode;
    bool has_opt,opt_do,message_signature;
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
            if(section==2 && (type==24 || type==250)) info->message_signature=true;
            unsigned char ext_rcode=p[pos+4];
            bool opt_do=(p[pos+6]&0x80)!=0;
            pos+=10;
            if(type==41) {
                if(section!=2 || info->has_opt) return DNS_FORMERR;
                info->has_opt=true; /* retain a minimal OPT even for malformed option data */
                info->opt_ext_rcode=ext_rcode;info->opt_do=opt_do;
                if(!response) {
                    unsigned sz=klass<512?512:klass;
                    info->udp_limit=(uint16_t)(sz>udp_reply_max?udp_reply_max:sz);
                }
                if(i+1==counts[2] && !p[pos-5] && (response || !ext_rcode))
                    info->final_opt_rdlen=pos-2;
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
typedef struct {struct sockaddr_in peer;uint16_t id;uint64_t deadline_ms;} UdpWaiter;
typedef struct {
    size_t count;
    uint16_t offset[CACHE_MAX_ANSWERS];
    uint32_t min_ttl;
} CacheTtls;
typedef struct {
    size_t key_len,reply_len;
    uint64_t received_ms,age_ms,expires_ms;
    CacheTtls ttls;
    unsigned char key[CACHE_MAX_QUERY-2],reply[CACHE_MAX_REPLY];
} CacheEntry;
typedef struct {
    uint32_t age,max_age;
    time_t date;
    bool age_seen,date_seen,blocked;
} CacheHeaders;
struct Client {
    int fd;size_t have,need,sent,out_len;
    unsigned char length[2];
    unsigned char *in,*out;
    bool busy,read_eof,out_satisfies_query;uint64_t generation,queries_started;
    uint64_t idle_since_ms,frame_deadline,write_deadline;
};
struct Query {
    CURL *easy;
    unsigned char *request,*response;
    size_t req_len,resp_len,resp_cap;
    DnsInfo info;
    struct sockaddr_storage peer;socklen_t peer_len;
    Client *client;uint64_t generation;int udp_fd;
    bool shareable_udp,added_padding;
    size_t udp_waiter_count;
    UdpWaiter udp_waiters[MAX_UDP_WAITERS];
    CacheEntry *cache_slot;
    CacheHeaders cache_headers;
    Query *next;
};
typedef struct { curl_socket_t fd;int action;uint64_t generation; } CurlSocket;
typedef enum { PHASE_QUEUE, PHASE_TLS, PHASE_FIRST_BYTE, PHASE_COUNT } TimingPhase;
typedef struct {uint64_t usec,count;} PhaseTiming;
typedef struct {
    uint64_t udp_queries,tcp_queries,queries_satisfied,invalid_queries,overload,upstream_requests,
      upstream_ok,upstream_failed,upstream_timeouts,invalid_responses,
      truncated,requests_new_connections,requests_reused_connections,easy_handles_reused,
      http1,http2,http3,socket_callbacks,timer_callbacks,timer_fires,
      tcp_accepted,tcp_closed,tcp_keepalive_queries,tcp_pipeline_buffered,
      tcp_half_closes,tcp_idle_timeouts,tcp_io_timeouts,tcp_cancelled_upstream,cache_hits,cache_misses;
    uint64_t udp_queries_coalesced;
    double upstream_seconds;
    PhaseTiming upstream_phase[PHASE_COUNT];
} Metrics;
static Metrics metrics;
static Query *active;
static size_t active_count;
static CURLM *multi;
static CURL *idle_easies[MAX_IDLE_EASIES];
static size_t idle_easy_count;
static const char *upstream;
static bool loopback_http;
static bool edns_padding;
static long upstream_http_version=CURL_HTTP_VERSION_1_1;
static struct curl_slist *bootstrap_hosts;
static struct curl_slist *doh_headers;
static const char *ca_file; /* custom CA bundle for upstream TLS verification */
static Client clients[MAX_CLIENTS];
static CurlSocket curl_sockets[MAX_CURL_SOCKETS];
static size_t curl_socket_count;
static uint64_t curl_socket_generation;
static int64_t curl_deadline=-1;
static uint64_t tcp_idle_ms=TCP_IDLE_MS,tcp_io_ms=TCP_IO_MS;
static long doh_connect_ms=DOH_CONNECT_MS,doh_timeout_ms=DOH_TIMEOUT_MS;
static CacheEntry *answer_cache;
static size_t cache_entries;

typedef struct {
    int fd;uint64_t generation,last_ms;
    char request[512];size_t have;
    char reply[4608];size_t reply_len,sent;
} MetricClient;
static MetricClient metric_clients[MAX_METRICS_CLIENTS];

typedef enum {
    LOG_CAPACITY,LOG_SETUP,LOG_TIMEOUT,LOG_TRANSPORT,LOG_STATUS,LOG_CONTENT,LOG_DNS,
    LOG_TCP_BUFFER,LOG_COUNT
} Failure;
static void log_failure(Failure event,bool tcp,CURLcode code,long status) {
    static const char *const names[LOG_COUNT]={
        "capacity","upstream_setup","upstream_timeout","upstream_transport",
        "upstream_http_status","upstream_content_type","upstream_dns_response","tcp_buffer_allocation"
    };
    static struct {uint64_t next,suppressed;} rate[LOG_COUNT];
    uint64_t now=clock_ms();
    if(now<rate[event].next) {rate[event].suppressed++;return;}
    fprintf(stderr,"level=warning event=%s transport=%s curl_code=%d http_status=%ld suppressed=%llu\n",
            names[event],tcp?"tcp":"udp",(int)code,status,(unsigned long long)rate[event].suppressed);
    rate[event].next=now+10000;
    rate[event].suppressed=0;
}
static long select_http_version(int features,bool prefer_h3) {
    if(prefer_h3) {
#if LIBCURL_VERSION_NUM >= 0x074200 /* 7.66.0 */
        if(features&CURL_VERSION_HTTP3) return CURL_HTTP_VERSION_3;
#endif
        return CURL_HTTP_VERSION_NONE;
    }
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
static CURL *acquire_easy(void) {
    if(!idle_easy_count) return curl_easy_init();
    metrics.easy_handles_reused++;
    return idle_easies[--idle_easy_count];
}
static void recycle_easy(CURL *easy) {
    if(idle_easy_count==MAX_IDLE_EASIES) {
        curl_easy_cleanup(easy);
        return;
    }
    /* Clear request pointers and callbacks before their Query is freed. */
    curl_easy_reset(easy);
    idle_easies[idle_easy_count++]=easy;
}
static void detach_query(Query *q) {
    Query **it=&active;
    while(*it && *it!=q) it=&(*it)->next;
    if(*it) {*it=q->next;active_count--;}
    if(q->easy) {
        if(curl_multi_remove_handle(multi,q->easy)==CURLM_OK) recycle_easy(q->easy);
        else curl_easy_cleanup(q->easy);
    }
}
static void free_query(Query *q) {
    free(q->request);free(q->response);free(q);
}
static void remove_query(Query *q) {
    detach_query(q);
    free_query(q);
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
    free(c->in);free(c->out);c->in=c->out=NULL;
    c->fd=-1;c->have=c->need=c->sent=c->out_len=0;
    c->busy=c->read_eof=c->out_satisfies_query=false;c->generation++;c->queries_started=0;
    c->frame_deadline=c->write_deadline=0;
}
static void reply_dns(Query *q,const unsigned char *p,size_t n,bool satisfies_query) {
    if(q->client) {
        Client *c=q->client;
        if(c->fd>=0 && c->generation==q->generation) {
            c->out=malloc(n+2);
            if(!c->out) {
                log_failure(LOG_TCP_BUFFER,true,CURLE_OUT_OF_MEMORY,0);
                return;
            }
            c->out[0]=(unsigned char)(n>>8);c->out[1]=(unsigned char)n;
            memcpy(c->out+2,p,n);c->out_len=n+2;c->sent=0;
            c->out_satisfies_query=satisfies_query;
            c->write_deadline=clock_ms()+tcp_io_ms;
        }
    } else {
        ssize_t written=sendto(q->udp_fd,p,n,0,(struct sockaddr*)&q->peer,q->peer_len);
        if(satisfies_query && written==(ssize_t)n) metrics.queries_satisfied++;
        for(size_t i=0;i<q->udp_waiter_count;i++) {
            UdpWaiter *waiter=&q->udp_waiters[i];
            unsigned char id[]={ (unsigned char)(waiter->id>>8),(unsigned char)waiter->id };
            struct iovec parts[]={ {.iov_base=id,.iov_len=sizeof(id)},
                                   {.iov_base=(void*)(p+2),.iov_len=n-2} };
            struct msghdr message={.msg_name=&waiter->peer,.msg_namelen=sizeof(waiter->peer),
                                   .msg_iov=parts,.msg_iovlen=2};
            written=sendmsg(q->udp_fd,&message,0);
            if(satisfies_query && written==(ssize_t)n) metrics.queries_satisfied++;
        }
    }
}
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

/* Cache only ordinary IN A/AAAA queries with no options beyond an empty OPT.
 * The exact wire key retains case, flags and EDNS size. Only the ID is omitted. */
static bool cache_empty_opt(const unsigned char *p,size_t n) {
    return n==DNS_OPT_SIZE && p[0]==0 && be16(p+1)==41 && be32(p+5)==0 && be16(p+9)==0;
}
static bool plain_address_query(const unsigned char *p,const DnsInfo *info) {
    return be16(p+4)==1 && info->qclass==1 && (info->qtype==1 || info->qtype==28) &&
           p[2]==1 && !(p[3]&~0x20);
}
static CacheEntry *cache_slot_for(const unsigned char *p,size_t n,const DnsInfo *info) {
    if(!cache_entries || n>CACHE_MAX_QUERY || !plain_address_query(p,info)) return NULL;
    uint16_t additional=be16(p+10);
    if(additional && (additional!=1 || !cache_empty_opt(p+info->question_end,n-info->question_end))) return NULL;
    uint32_t hash=2166136261u;
    for(size_t i=2;i<n;i++) hash=(hash^p[i])*16777619u;
    return &answer_cache[hash%cache_entries];
}
static bool span_is(const char *p,size_t n,const char *literal) {
    return n==strlen(literal) && strncasecmp(p,literal,n)==0;
}
static bool header_uint(const char *p,size_t n,uint32_t *result) {
    uint32_t value=0;
    if(!n) return false;
    for(size_t i=0;i<n;i++) {
        if(p[i]<'0' || p[i]>'9') return false;
        unsigned digit=(unsigned)(p[i]-'0');
        if(value>(UINT32_MAX-digit)/10u) return false;
        value=value*10u+digit;
    }
    *result=value;
    return true;
}
static void cache_control(CacheHeaders *headers,const char *p,const char *end) {
    if(p==end) headers->blocked=true;
    while(p<end) {
        const char *comma=memchr(p,',',(size_t)(end-p));
        const char *last=comma?comma:end;
        while(p<last && (*p==' ' || *p=='\t')) p++;
        while(last>p && (last[-1]==' ' || last[-1]=='\t')) last--;
        size_t len=(size_t)(last-p),prefix=0;
        if(len>8 && strncasecmp(p,"max-age=",8)==0) prefix=8;
        else if(len>9 && strncasecmp(p,"s-maxage=",9)==0) prefix=9;
        uint32_t limit;
        if(prefix && header_uint(p+prefix,len-prefix,&limit)) {
            if(limit<headers->max_age) headers->max_age=limit;
        } else if(!span_is(p,len,"public")) {
            /* Includes no-store, no-cache, private and unsupported directives. */
            headers->blocked=true;
        }
        p=comma?comma+1:end;
    }
}
static size_t collect_doh_header(char *p,size_t size,size_t count,void *arg) {
    Query *q=arg;
    CacheHeaders *headers=&q->cache_headers;
    size_t n=size*count; /* libcurl supplies size=1 for header callbacks. */
    if(n>=5 && memcmp(p,"HTTP/",5)==0) {
        *headers=(CacheHeaders){.max_age=UINT32_MAX};
        return n; /* Replace interim or proxy header blocks. */
    }
    const char *colon=memchr(p,':',n);
    if(!colon) return n;
    size_t name_len=(size_t)(colon-p);
    const char *value=colon+1,*end=p+n;
    while(value<end && (*value==' ' || *value=='\t')) value++;
    while(end>value && (end[-1]=='\r' || end[-1]=='\n' || end[-1]==' ' || end[-1]=='\t')) end--;
    size_t len=(size_t)(end-value);
    if(span_is(p,name_len,"Age")) {
        if(headers->age_seen || !header_uint(value,len,&headers->age)) headers->blocked=true;
        headers->age_seen=true;
    } else if(span_is(p,name_len,"Cache-Control")) cache_control(headers,value,end);
    else if(span_is(p,name_len,"Date")) {
        char date[64];
        if(headers->date_seen || len>=sizeof(date)) headers->blocked=true;
        else {
            memcpy(date,value,len);date[len]=0;
            headers->date=curl_getdate(date,NULL);
            if(headers->date==(time_t)-1) headers->blocked=true;
        }
        headers->date_seen=true;
    } else if(span_is(p,name_len,"Vary")) {
        /* Every upstream request sends the same application/dns-message Accept. */
        if(!span_is(value,len,"Accept")) headers->blocked=true;
    } else if(span_is(p,name_len,"Expires") || span_is(p,name_len,"Pragma") ||
              span_is(p,name_len,"Set-Cookie")) headers->blocked=true;
    return n;
}
/* The normal DNS parser has already checked all wire bounds. Narrow reuse to
 * complete positive address answers and record every TTL that will be aged. */
static bool cache_ttls(const Query *q,const DnsInfo *info,CacheTtls *ttls) {
    const unsigned char *p=q->response;
    size_t n=q->resp_len,pos=info->question_end,answers=be16(p+6);
    if(n>CACHE_MAX_REPLY || (p[2]&2) || (p[3]&15) || be16(p+4)!=1 || be16(p+8) ||
       !answers || answers>CACHE_MAX_ANSWERS) return false;
    *ttls=(CacheTtls){.count=answers,.min_ttl=UINT32_MAX};
    bool has_address=false;
    for(size_t i=0;i<answers;i++) {
        unsigned char name[256];size_t name_len;
        if(!dns_name(p,n,&pos,name,&name_len,true) || n-pos<10) return false;
        uint16_t type=be16(p+pos),rdlen=be16(p+pos+8);
        if(rdlen>n-pos-10 || be16(p+pos+2)!=1 || (type!=5 && type!=info->qtype)) return false;
        if(type==info->qtype) {
            if(rdlen!=(type==1?4:16)) return false;
            has_address=true;
        }
        uint32_t ttl=be32(p+pos+4);
        if(ttl>INT32_MAX) ttl=0;
        if(ttl<ttls->min_ttl) ttls->min_ttl=ttl;
        ttls->offset[i]=(uint16_t)(pos+4);
        pos+=10+rdlen;
    }
    return has_address && (pos==n || (be16(p+10)==1 && cache_empty_opt(p+pos,n-pos)));
}
static void age_ttl(unsigned char *field,uint64_t age) {
    uint32_t ttl=be32(field);
    ttl=ttl<=INT32_MAX && ttl>age?ttl-(uint32_t)age:0;
    field[0]=(unsigned char)(ttl>>24);field[1]=(unsigned char)(ttl>>16);
    field[2]=(unsigned char)(ttl>>8);field[3]=(unsigned char)ttl;
}
static void age_forwarded_ttls(Query *q,const DnsInfo *info,uint32_t age) {
    if(!age || info->message_signature) return;
    unsigned char *p=q->response;
    size_t pos=info->question_end;
    size_t records=(size_t)be16(p+6)+be16(p+8)+be16(p+10);
    for(size_t i=0;i<records;i++) {
        /* Validation already checked each owner. Skip its wire form without
         * following pointers through TTL fields that may have been changed. */
        while(p[pos] && !(p[pos]&0xc0)) pos+=(size_t)p[pos]+1;
        pos+=(p[pos]&0xc0)?2:1;
        if(be16(p+pos)!=41) age_ttl(p+pos+4,age); /* OPT has flags here. */
        pos+=10+be16(p+pos+8);
    }
}
static uint64_t doh_response_age_ms(const CacheHeaders *headers,double transfer_seconds) {
    uint64_t age_ms=(uint64_t)headers->age*1000u+(uint64_t)(transfer_seconds*1000.0);
    if(headers->date_seen && headers->date!=(time_t)-1) {
        double apparent=difftime(time(NULL),headers->date);
        if(apparent>UINT32_MAX) apparent=UINT32_MAX;
        if(apparent>(double)age_ms/1000.0) age_ms=(uint64_t)apparent*1000u;
    }
    return age_ms;
}
static void cache_store(Query *q,const DnsInfo *info,uint64_t age_ms) {
    CacheTtls ttls;
    if(!q->cache_slot || !cache_ttls(q,info,&ttls)) return;
    const CacheHeaders *headers=&q->cache_headers;
    uint32_t limit=ttls.min_ttl<CACHE_MAX_TTL?ttls.min_ttl:CACHE_MAX_TTL;
    if(headers->max_age<limit) limit=headers->max_age;
    uint64_t lifetime=(uint64_t)limit*1000u;
    uint64_t now=read_clock_ms(CLOCK_BOOTTIME);
    if(now && age_ms<lifetime) {
        CacheEntry *entry=q->cache_slot;
        entry->key_len=q->req_len-2;
        entry->reply_len=q->resp_len;
        entry->ttls=ttls;
        entry->received_ms=now;
        entry->age_ms=age_ms;
        entry->expires_ms=now+lifetime-age_ms;
        memcpy(entry->key,q->request+2,entry->key_len);
        memcpy(entry->reply,q->response,q->resp_len);
    }
}
static bool cache_reply(Query *q,const unsigned char *request) {
    const CacheEntry *entry=q->cache_slot;
    if(!entry || entry->key_len!=q->req_len-2 ||
       memcmp(entry->key,request+2,entry->key_len)!=0 ||
       (!q->client && entry->reply_len>q->info.udp_limit)) return false;
    uint64_t now=read_clock_ms(CLOCK_BOOTTIME);
    if(now<entry->received_ms || now>=entry->expires_ms) return false;
    unsigned char reply[CACHE_MAX_REPLY];
    memcpy(reply,entry->reply,entry->reply_len);
    memcpy(reply,request,2);
    uint64_t age_ms=entry->age_ms+(now-entry->received_ms);
    for(size_t i=0;i<entry->ttls.count;i++) age_ttl(reply+entry->ttls.offset[i],(age_ms+999u)/1000u);
    reply_dns(q,reply,entry->reply_len,true);
    return true;
}
static void record_client_query(Client *client) {
    if(client) {
        if(client->queries_started++>0) metrics.tcp_keepalive_queries++;
        metrics.tcp_queries++;
    } else metrics.udp_queries++;
}
static bool same_udp_peer(const struct sockaddr_in *a,const struct sockaddr_in *b) {
    return a->sin_port==b->sin_port && a->sin_addr.s_addr==b->sin_addr.s_addr;
}
enum { EDNS_PADDING_BLOCK=128, EDNS_PADDING_CODE=12 };
static size_t edns_padding_size(const unsigned char *p,size_t n,const DnsInfo *info) {
    if(!info->final_opt_rdlen || info->message_signature) return 0;
    for(size_t pos=info->final_opt_rdlen+2;pos<n;pos+=4+be16(p+pos+2)) {
        if(be16(p+pos)==EDNS_PADDING_CODE) return 0;
    }
    /* Include the option header in the padded DNS wire length. */
    size_t extra=4+(EDNS_PADDING_BLOCK-(n+4)%EDNS_PADDING_BLOCK)%EDNS_PADDING_BLOCK;
    return extra<=TCP_MAX-n?extra:0;
}
static void write_padded_query(unsigned char *out,const unsigned char *p,size_t n,
                               const DnsInfo *info,size_t extra) {
    memcpy(out,p,n);
    memset(out+n,0,extra);
    size_t rdlen=be16(p+info->final_opt_rdlen)+extra;
    out[info->final_opt_rdlen]=(unsigned char)(rdlen>>8);
    out[info->final_opt_rdlen+1]=(unsigned char)rdlen;
    out[n+1]=EDNS_PADDING_CODE;
    out[n+3]=(unsigned char)(extra-4);
}
/* A proxy-added request option is local to the upstream HTTPS exchange. */
static void strip_doh_padding(Query *q,const DnsInfo *info) {
    if(!q->added_padding || !info->final_opt_rdlen || info->message_signature) return;
    unsigned char *p=q->response;
    size_t start=info->final_opt_rdlen+2,write_pos=start;
    for(size_t pos=start;pos<q->resp_len;) {
        size_t len=4+be16(p+pos+2);
        if(be16(p+pos)!=EDNS_PADDING_CODE) {
            if(write_pos!=pos) memmove(p+write_pos,p+pos,len);
            write_pos+=len;
        }
        pos+=len;
    }
    size_t rdlen=write_pos-start;
    p[start-2]=(unsigned char)(rdlen>>8);
    p[start-1]=(unsigned char)rdlen;
    q->resp_len=write_pos;
}
static bool join_udp_query(const Query *pending,const unsigned char *data) {
    UdpWaiter incoming={.id=be16(data),.deadline_ms=clock_ms()+(uint64_t)doh_timeout_ms};
    memcpy(&incoming.peer,&pending->peer,sizeof(incoming.peer));
    Query *available=NULL;
    for(Query *q=active;q;q=q->next) {
        if(!q->shareable_udp || q->udp_fd!=pending->udp_fd || q->req_len!=pending->req_len ||
           memcmp(q->request+2,data+2,q->req_len-2)!=0) continue;
        struct sockaddr_in leader;
        memcpy(&leader,&q->peer,sizeof(leader));
        if(incoming.id==be16(q->request) && same_udp_peer(&incoming.peer,&leader)) return true;
        for(size_t i=0;i<q->udp_waiter_count;i++) {
            UdpWaiter *waiter=&q->udp_waiters[i];
            if(incoming.id==waiter->id && same_udp_peer(&incoming.peer,&waiter->peer)) return true;
        }
        if(!available && q->udp_waiter_count<MAX_UDP_WAITERS) available=q;
    }
    if(!available) return false;
    available->udp_waiters[available->udp_waiter_count++]=incoming;
    return true;
}
static bool submit_until(const unsigned char *data,size_t len,Client *client,int udp_fd,
                         const struct sockaddr_storage *peer,socklen_t peer_len,uint64_t deadline_ms);
static void retry_udp_waiters(const Query *q,size_t count) {
    /* Coalescing accepts only plain, single-question address queries. */
    unsigned char request[CACHE_MAX_QUERY];
    memcpy(request,q->request,q->req_len);
    for(size_t i=0;i<count;i++) {
        const UdpWaiter *waiter=&q->udp_waiters[i];
        struct sockaddr_storage peer={0};
        memcpy(&peer,&waiter->peer,sizeof(waiter->peer));
        request[0]=(unsigned char)(waiter->id>>8);
        request[1]=(unsigned char)waiter->id;
        (void)submit_until(request,q->req_len,NULL,q->udp_fd,&peer,sizeof(waiter->peer),waiter->deadline_ms);
    }
}
static void record_phase(TimingPhase phase,curl_off_t usec) {
    metrics.upstream_phase[phase].usec+=(uint64_t)usec;
    metrics.upstream_phase[phase].count++;
}
static void record_upstream_phases(CURL *easy,long connects) {
    curl_off_t ready=0,first_byte=0;
#if LIBCURL_VERSION_NUM >= 0x080600
    curl_off_t queue=0;
    if(curl_easy_getinfo(easy,CURLINFO_QUEUE_TIME_T,&queue)==CURLE_OK && queue>=0)
        record_phase(PHASE_QUEUE,queue);
#endif
    if(connects>0) {
        curl_off_t connected=0,handshake=0;
        if(curl_easy_getinfo(easy,CURLINFO_CONNECT_TIME_T,&connected)==CURLE_OK &&
           curl_easy_getinfo(easy,CURLINFO_APPCONNECT_TIME_T,&handshake)==CURLE_OK &&
           connected>0 && handshake>=connected)
            record_phase(PHASE_TLS,handshake-connected);
    }
    if(curl_easy_getinfo(easy,CURLINFO_PRETRANSFER_TIME_T,&ready)==CURLE_OK &&
       curl_easy_getinfo(easy,CURLINFO_STARTTRANSFER_TIME_T,&first_byte)==CURLE_OK &&
       ready>0 && first_byte>=ready)
        record_phase(PHASE_FIRST_BYTE,first_byte-ready);
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
    record_upstream_phases(q->easy,connects);
    if(seconds>0) metrics.upstream_seconds+=seconds;
    if(connects>0) metrics.requests_new_connections+=(uint64_t)connects;
    else if(code==CURLE_OK) metrics.requests_reused_connections++;
    if(version==CURL_HTTP_VERSION_1_0 || version==CURL_HTTP_VERSION_1_1) metrics.http1++;
    else if(version==CURL_HTTP_VERSION_2_0) metrics.http2++;
#if LIBCURL_VERSION_NUM >= 0x074200 /* 7.66.0 */
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
    size_t retries=0;
    if(failure==LOG_COUNT) {
        strip_doh_padding(q,&response);
        metrics.upstream_ok++;
        uint64_t age_ms=doh_response_age_ms(&q->cache_headers,seconds);
        bool reusable=status==200 && !q->cache_headers.blocked && !response.message_signature &&
                      age_ms<(uint64_t)q->cache_headers.max_age*1000u;
        if(reusable) cache_store(q,&response,age_ms);
        else {retries=q->udp_waiter_count;q->udp_waiter_count=0;}
        age_forwarded_ttls(q,&response,q->cache_headers.age);
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
    Client *client=q->client;
    bool attached=client && client->fd>=0 && client->generation==q->generation;
    if(attached) client->busy=false;
    detach_query(q);
    if(attached && !client->out_len) close_client(client);
    if(retries) retry_udp_waiters(q,retries);
    free_query(q);
}
static bool submit_until(const unsigned char *data,size_t len,Client *client,int udp_fd,
                         const struct sockaddr_storage *peer,socklen_t peer_len,uint64_t deadline_ms) {
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
    long timeout_ms=doh_timeout_ms;
    if(deadline_ms) {
        uint64_t now=clock_ms();
        if(now>=deadline_ms) {send_error(&pending,data,2);return true;}
        if(deadline_ms-now<(uint64_t)timeout_ms) timeout_ms=(long)(deadline_ms-now);
    } else pending.cache_slot=cache_slot_for(data,len,&info);
    if(pending.cache_slot) {
        if(cache_reply(&pending,data)) {
            metrics.cache_hits++;
            record_client_query(client);
            return true;
        }
        metrics.cache_misses++;
    }
    /* Share only unsigned UDP address queries without additional records. */
    pending.shareable_udp=!deadline_ms && !client && peer_len==sizeof(struct sockaddr_in) &&
                          pending.peer.ss_family==AF_INET && !be16(data+10) && plain_address_query(data,&info);
    if(pending.shareable_udp && join_udp_query(&pending,data)) {
        metrics.udp_queries_coalesced++;
        record_client_query(NULL);
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
    size_t extra=edns_padding && !loopback_http?edns_padding_size(data,len,&info):0;
    q->request=malloc(len+(extra?len+extra:0));
    if(!q->request) goto fail;
    memcpy(q->request,data,len);
    const unsigned char *post=q->request;
    if(extra) {
        /* Keep the original wire key and question for cache and reply handling. */
        write_padded_query(q->request+len,data,len,&info,extra);
        q->added_padding=true;
        post=q->request+len;
    }
    q->easy=acquire_easy();
    if(!q->easy) goto fail;
#define OPT(key,val) do {setup_code=curl_easy_setopt(q->easy,key,val);if(setup_code!=CURLE_OK) goto fail;}while(0)
    OPT(CURLOPT_URL,upstream);
    if(loopback_http || bootstrap_hosts) OPT(CURLOPT_PROXY,"");
    if(bootstrap_hosts) OPT(CURLOPT_RESOLVE,bootstrap_hosts);
    OPT(CURLOPT_HTTPHEADER,doh_headers);
    OPT(CURLOPT_POSTFIELDS,post);
    OPT(CURLOPT_POSTFIELDSIZE_LARGE,(curl_off_t)(len+extra));
    OPT(CURLOPT_HTTP_VERSION,upstream_http_version);
    if(upstream_http_version!=CURL_HTTP_VERSION_1_1)
        OPT(CURLOPT_PIPEWAIT,1L);
    OPT(CURLOPT_TCP_KEEPALIVE,1L);
    OPT(CURLOPT_WRITEFUNCTION,collect);
    OPT(CURLOPT_WRITEDATA,q);
    q->cache_headers.max_age=UINT32_MAX;
    OPT(CURLOPT_HEADERFUNCTION,collect_doh_header);
    OPT(CURLOPT_HEADERDATA,q);
    OPT(CURLOPT_PRIVATE,q);
    OPT(CURLOPT_TIMEOUT_MS,timeout_ms);
    OPT(CURLOPT_CONNECTTIMEOUT_MS,doh_connect_ms);
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
    if(client) client->busy=true;
    if(!deadline_ms) record_client_query(client);
    return true;
fail:
    if(q->easy) curl_easy_cleanup(q->easy);
    free(q->request);free(q);
setup_failure:
    log_failure(LOG_SETUP,client!=NULL,setup_code,0);
reject:
    metrics.overload++;
    send_error(&pending,data,2);
    return true; /* A local reply is queued for a valid TCP query. */
}
static bool submit(const unsigned char *data,size_t len,Client *client,int udp_fd,
                   const struct sockaddr_storage *peer,socklen_t peer_len) {
    return submit_until(data,len,client,udp_fd,peer,peer_len,0);
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
    if(!submit(c->in,c->need,c,-1,NULL,0) || (!c->busy && !c->out_len)) {
        close_client(c);
        return false;
    }
    free(c->in);c->in=NULL;
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
            free(c->out);c->out=NULL;
            c->out_len=c->sent=0;
            c->write_deadline=0;
            c->idle_since_ms=clock_ms();
            if(c->need && c->have==c->need && !start_tcp_query(c)) return;
            if(c->read_eof && !c->busy && !c->out_len) close_client(c);
        }
    }
    if(c->fd<0 || c->read_eof ||
       (c->need && c->have==c->need) || !(events&POLLIN)) return;
    unsigned char *frame=c->need?c->in:c->length;
    size_t target=c->need?c->need:sizeof(c->length);
    ssize_t n=recv(c->fd,frame+c->have,target-c->have,0);
    if(n==0) {
        c->read_eof=true;
        metrics.tcp_half_closes++;
        /* A half-closed writer may still be waiting to read its replies. */
        if(c->have || c->need) {close_client(c);return;}
        if(!c->busy && !c->out_len) close_client(c);
        return;
    }
    if(n<0) {if(errno!=EAGAIN && errno!=EINTR) close_client(c);return;}
    if(!c->have && !c->need) c->frame_deadline=clock_ms()+tcp_io_ms;
    c->have+=(size_t)n;
    if(!c->need && c->have==sizeof(c->length)) {
        size_t length=be16(c->length);
        if(length<DNS_HEADER) {close_client(c);return;}
        c->in=malloc(length);
        if(!c->in) {
            log_failure(LOG_TCP_BUFFER,true,CURLE_OUT_OF_MEMORY,0);
            close_client(c);
            return;
        }
        c->need=length;c->have=0;
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
            " max_host_connections=%d doh_connect_ms=%ld doh_timeout_ms=%ld"
            " tcp_idle_ms=%" PRIu64 " tcp_io_ms=%" PRIu64
            " queries_satisfied=%" PRIu64 " udp_queries=%" PRIu64 " tcp_queries=%" PRIu64
            " udp_queries_coalesced=%" PRIu64
            " upstream_ok=%" PRIu64 " upstream_failed=%" PRIu64 " upstream_timeouts=%" PRIu64
            " invalid_queries=%" PRIu64 " invalid_responses=%" PRIu64 " overload=%" PRIu64
            " udp_truncated=%" PRIu64 " tcp_cancelled_upstream=%" PRIu64
            " http1_responses=%" PRIu64 " http2_responses=%" PRIu64
            " new_connections=%" PRIu64 " reused_requests=%" PRIu64 " easy_handles_reused=%" PRIu64
            " cache_entries=%zu cache_hits=%" PRIu64 " cache_misses=%" PRIu64
            " inflight=%zu max_inflight=%d tcp_clients=%zu max_tcp_clients=%d\n",
            uptime_ms,bindip,port,metrics_port,loopback_http?"http":"https",http_preference,
            bootstrap_hosts?"enabled":"disabled",max_host_connections,doh_connect_ms,doh_timeout_ms,
            tcp_idle_ms,tcp_io_ms,metrics.queries_satisfied,metrics.udp_queries,metrics.tcp_queries,
            metrics.udp_queries_coalesced,
            metrics.upstream_ok,metrics.upstream_failed,metrics.upstream_timeouts,
            metrics.invalid_queries,metrics.invalid_responses,metrics.overload,metrics.truncated,
            metrics.tcp_cancelled_upstream,metrics.http1,metrics.http2,metrics.requests_new_connections,
            metrics.requests_reused_connections,metrics.easy_handles_reused,
            cache_entries,metrics.cache_hits,metrics.cache_misses,
            active_count,MAX_ACTIVE,tcp_open_count(),MAX_CLIENTS);
}
static void metric_response(MetricClient *c) {
#define METRIC(...) do {int z=snprintf(c->reply+c->reply_len,sizeof(c->reply)-c->reply_len,__VA_ARGS__); \
    if(z<0 || (size_t)z>=sizeof(c->reply)-c->reply_len) {close_metric(c);return;} \
    c->reply_len+=(size_t)z;} while(0)
    char body[4096];int n=snprintf(body,sizeof(body),
        "# TYPE dnsp_queries_total counter\n"
        "dnsp_queries_total{transport=\"udp\"} %llu\n"
        "dnsp_queries_total{transport=\"tcp\"} %llu\n"
        "# TYPE dnsp_queries_satisfied_total counter\n"
        "dnsp_queries_satisfied_total %" PRIu64 "\n"
        "# TYPE dnsp_cache_hits_total counter\n"
        "dnsp_cache_hits_total %" PRIu64 "\n"
        "# TYPE dnsp_cache_misses_total counter\n"
        "dnsp_cache_misses_total %" PRIu64 "\n"
        "# TYPE dnsp_udp_queries_coalesced_total counter\n"
        "dnsp_udp_queries_coalesced_total %" PRIu64 "\n"
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
        "# TYPE dnsp_upstream_easy_handles_reused_total counter\n"
        "dnsp_upstream_easy_handles_reused_total %" PRIu64 "\n"
        "dnsp_upstream_http_responses_total{version=\"1\"} %llu\n"
        "dnsp_upstream_http_responses_total{version=\"2\"} %llu\n"
        "dnsp_upstream_http_responses_total{version=\"3\"} %llu\n"
        "dnsp_curl_socket_callbacks_total %llu\n"
        "dnsp_curl_timer_callbacks_total %llu\n"
        "dnsp_curl_timer_fires_total %llu\n"
        "# TYPE dnsp_upstream_duration_seconds_sum counter\n"
        "dnsp_upstream_duration_seconds_sum %.6f\n"
        "dnsp_upstream_duration_seconds_count %llu\n"
        "# HELP dnsp_upstream_phase_duration_seconds Time spent in observed upstream transfer phases.\n"
        "# TYPE dnsp_upstream_phase_duration_seconds summary\n"
        "dnsp_upstream_phase_duration_seconds_sum{phase=\"queue\"} %.6f\n"
        "dnsp_upstream_phase_duration_seconds_count{phase=\"queue\"} %" PRIu64 "\n"
        "dnsp_upstream_phase_duration_seconds_sum{phase=\"tls\"} %.6f\n"
        "dnsp_upstream_phase_duration_seconds_count{phase=\"tls\"} %" PRIu64 "\n"
        "dnsp_upstream_phase_duration_seconds_sum{phase=\"first_byte\"} %.6f\n"
        "dnsp_upstream_phase_duration_seconds_count{phase=\"first_byte\"} %" PRIu64 "\n"
        "# TYPE dnsp_queries_inflight gauge\n"
        "dnsp_queries_inflight %zu\n"
        "dnsp_tcp_clients %zu\n"
        "dnsp_curl_socket_watches %zu\n",
        (unsigned long long)metrics.udp_queries,(unsigned long long)metrics.tcp_queries,
        metrics.queries_satisfied,metrics.cache_hits,metrics.cache_misses,metrics.udp_queries_coalesced,
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
        metrics.easy_handles_reused,
        (unsigned long long)metrics.http1,(unsigned long long)metrics.http2,
        (unsigned long long)metrics.http3,(unsigned long long)metrics.socket_callbacks,
        (unsigned long long)metrics.timer_callbacks,(unsigned long long)metrics.timer_fires,
        metrics.upstream_seconds,
        (unsigned long long)(metrics.upstream_ok+metrics.upstream_failed),
        (double)metrics.upstream_phase[PHASE_QUEUE].usec/1e6,metrics.upstream_phase[PHASE_QUEUE].count,
        (double)metrics.upstream_phase[PHASE_TLS].usec/1e6,metrics.upstream_phase[PHASE_TLS].count,
        (double)metrics.upstream_phase[PHASE_FIRST_BYTE].usec/1e6,metrics.upstream_phase[PHASE_FIRST_BYTE].count,
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
typedef struct {PollType kind;size_t idx;uint64_t generation;} PollItem;
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
static long parse_range(const char *s,long min,long max) {
    char *end=NULL;errno=0;long v=strtol(s,&end,10);
    return errno || end==s || *end || v<min || v>max ? -1 : v;
}
static void usage(FILE *stream,const char *program) {
    fprintf(stream,"Usage: %s [options]\n"
            "  -l IPv4                     DNS bind address (default 127.0.0.1)\n"
            "  -p PORT                     UDP/TCP DNS port, 1..65535 (default 5300)\n"
            "  -s URL                      Upstream DoH URL (default https://cloudflare-dns.com/dns-query)\n"
            "  -m PORT                     Loopback metrics port, 1..65535 (default disabled)\n"
            "  --bootstrap-address IP      Numeric IPv4 or IPv6 address for the HTTPS upstream\n"
            "  --edns-padding               Pad eligible upstream HTTPS DNS queries to 128-byte blocks\n"
            "  --ca-file PEM                CA bundle for upstream TLS verification\n"
            "  --upstream-http MODE          auto (default) or prefer-h3 (HTTPS with fallback)\n"
            "  --max-host-connections N     Upstream connections, 1..16 (default 8)\n"
            "  --tcp-idle-ms MS             Idle TCP session, %d..%d (default %d)\n"
            "  --tcp-io-ms MS               TCP frame read/write deadline, %d..%d (default %d)\n"
            "  --doh-connect-ms MS          Upstream connection deadline, %d..%d (default %d)\n"
            "  --doh-timeout-ms MS          Total upstream deadline, %d..%d (default %d)\n"
            "  --cache-entries N            In-memory DNS cache slots, 0..%d (default disabled)\n"
            "  --udp-reply-max BYTES        UDP reply cap, 512..%d (default %d)\n"
            "  -h, --help                   Show this help\n",
            program,MIN_TIMEOUT_MS,MAX_TCP_TIMEOUT_MS,TCP_IDLE_MS,
            MIN_TIMEOUT_MS,MAX_TCP_TIMEOUT_MS,TCP_IO_MS,
            MIN_TIMEOUT_MS,MAX_DOH_TIMEOUT_MS,DOH_CONNECT_MS,
            MIN_TIMEOUT_MS,MAX_DOH_TIMEOUT_MS,DOH_TIMEOUT_MS,CACHE_MAX_ENTRIES,UDP_REPLY_MAX,UDP_REPLY_DEFAULT);
}
int main(int argc,char **argv) {
    const char *bindip="127.0.0.1",*bootstrap_address=NULL;
    bool prefer_h3=false;
    int port=5300,metrics_port=0;
    int max_host_connections=8;
    upstream="https://cloudflare-dns.com/dns-query";
    for(int i=1;i<argc;i++) {
        if(!strcmp(argv[i],"--help") || !strcmp(argv[i],"-h")) {usage(stdout,argv[0]);return 0;}
        else if(!strcmp(argv[i],"-l") && i+1<argc) bindip=argv[++i];
        else if(!strcmp(argv[i],"-p") && i+1<argc) port=(int)parse_range(argv[++i],1,65535);
        else if(!strcmp(argv[i],"-s") && i+1<argc) upstream=argv[++i];
        else if(!strcmp(argv[i],"--bootstrap-address")) {
            if(i+1==argc) {fprintf(stderr,"--bootstrap-address requires an IPv4 or IPv6 address\n");return 2;}
            bootstrap_address=argv[++i];
        }
        else if(!strcmp(argv[i],"-m") && i+1<argc) metrics_port=(int)parse_range(argv[++i],1,65535);
        else if(!strcmp(argv[i],"--ca-file") && i+1<argc) ca_file=argv[++i];
        else if(!strcmp(argv[i],"--edns-padding")) edns_padding=true;
        else if(!strcmp(argv[i],"--upstream-http") ||
                !strncmp(argv[i],"--upstream-http=",sizeof("--upstream-http=")-1)) {
            const char *mode=strchr(argv[i],'=');
            if(mode) mode++;
            else if(i+1<argc) mode=argv[++i];
            if(mode && !strcmp(mode,"prefer-h3")) prefer_h3=true;
            else if(mode && !strcmp(mode,"auto")) prefer_h3=false;
            else {fprintf(stderr,"--upstream-http requires auto or prefer-h3\n");return 2;}
        }
        else if(i+1<argc && (!strcmp(argv[i],"--tcp-idle-ms") || !strcmp(argv[i],"--tcp-io-ms") ||
                            !strcmp(argv[i],"--doh-connect-ms") || !strcmp(argv[i],"--doh-timeout-ms"))) {
            const char *option=argv[i];
            int max=!strncmp(option,"--tcp-",6)?MAX_TCP_TIMEOUT_MS:MAX_DOH_TIMEOUT_MS;
            long value=parse_range(argv[++i],MIN_TIMEOUT_MS,max);
            if(value<0) {
                fprintf(stderr,"invalid %s (%d..%d)\n",option,MIN_TIMEOUT_MS,max);return 2;
            }
            if(!strcmp(option,"--tcp-idle-ms")) tcp_idle_ms=(uint64_t)value;
            else if(!strcmp(option,"--tcp-io-ms")) tcp_io_ms=(uint64_t)value;
            else if(!strcmp(option,"--doh-connect-ms")) doh_connect_ms=value;
            else doh_timeout_ms=value;
        }
        else if(!strcmp(argv[i],"--max-host-connections") && i+1<argc)
            max_host_connections=(int)parse_range(argv[++i],1,16);
        else if(!strcmp(argv[i],"--udp-reply-max") && i+1<argc) {
            long value=parse_range(argv[++i],512,UDP_REPLY_MAX);
            if(value<0) {fprintf(stderr,"invalid --udp-reply-max (512..%d)\n",UDP_REPLY_MAX);return 2;}
            udp_reply_max=(unsigned)value;
        }
        else if(!strcmp(argv[i],"--cache-entries") && i+1<argc) {
            long value=parse_range(argv[++i],0,CACHE_MAX_ENTRIES);
            if(value<0) {fprintf(stderr,"invalid --cache-entries (0..%d)\n",CACHE_MAX_ENTRIES);return 2;}
            cache_entries=(size_t)value;
        }
        else {usage(stderr,argv[0]);return 2;}
    }
    if(port<0 || metrics_port<0 || metrics_port==port) {
        fprintf(stderr,"invalid port\n");return 2;
    }
    if(max_host_connections<0) {
        fprintf(stderr,"invalid --max-host-connections (1..16)\n");return 2;
    }
    if(doh_connect_ms>doh_timeout_ms) {
        fprintf(stderr,"--doh-connect-ms must be no greater than --doh-timeout-ms\n");return 2;
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
    upstream_http_version=select_http_version(curl_info?curl_info->features:0,prefer_h3);
    if(upstream_http_version==CURL_HTTP_VERSION_NONE) {
        fprintf(stderr,"--upstream-http=prefer-h3 requires libcurl with HTTP/3 support\n");
        curl_global_cleanup();return 2;
    }
    if(!configure_upstream(upstream,bootstrap_address)) {
        if(bootstrap_address) fprintf(stderr,"--bootstrap-address requires a numeric IP and an HTTPS upstream hostname\n");
        else fprintf(stderr,"invalid upstream (only HTTPS or loopback HTTP test endpoint)\n");
        curl_global_cleanup();return 2;
    }
    if(loopback_http) {
        if(prefer_h3) {
            fprintf(stderr,"--upstream-http=prefer-h3 requires an HTTPS upstream\n");
            curl_global_cleanup();return 2;
        }
        upstream_http_version=CURL_HTTP_VERSION_1_1;
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
    doh_headers=curl_slist_append(NULL,"Content-Type: application/dns-message");
    struct curl_slist *headers=doh_headers?curl_slist_append(doh_headers,"Accept: application/dns-message"):NULL;
    if(!headers) {
        fprintf(stderr,"level=error event=doh_headers_allocation\n");
        goto cleanup;
    }
    doh_headers=headers; /* Shared read-only until every easy handle is gone. */
    if(cache_entries && !(answer_cache=calloc(cache_entries,sizeof(*answer_cache)))) {
        fprintf(stderr,"level=error event=cache_allocation\n");
        goto cleanup;
    }
#define MULTI_OPT(key,val) do { \
    CURLMcode code=curl_multi_setopt(multi,key,val); \
    if(code!=CURLM_OK) { \
        fprintf(stderr,"level=error event=curl_multi_setopt option=%s code=%d\n",#key,(int)code); \
        goto cleanup; \
    } \
} while(0)
    MULTI_OPT(CURLMOPT_MAX_TOTAL_CONNECTIONS,16L);
    MULTI_OPT(CURLMOPT_MAX_HOST_CONNECTIONS,(long)max_host_connections);
    MULTI_OPT(CURLMOPT_PIPELINING,upstream_http_version!=CURL_HTTP_VERSION_1_1?CURLPIPE_MULTIPLEX:CURLPIPE_NOTHING);
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
    const char *http_preference=prefer_h3?"h3":"http/1.1";
    if(upstream_http_version==CURL_HTTP_VERSION_2TLS) http_preference="h2";
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
#define ADD(kind_,fd_,events_,idx_,gen_) do { \
    pfds[n]=(struct pollfd){.fd=(fd_),.events=(events_)}; \
    items[n++]=(PollItem){.kind=(kind_),.idx=(idx_),.generation=(gen_)}; \
} while(0)
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
        int result=poll(pfds,n,timeout);
        if(result<0 && errno!=EINTR) {perror("poll");exitcode=1;break;}
        expire_clients(clock_ms());
        for(size_t i=0;i<n && result>0;i++) {
            short re=pfds[i].revents;
            if(!re) continue;
            result--;
            int fd=pfds[i].fd;
            switch(items[i].kind) {
                case P_UDP:if(re&POLLIN) udp_io(udp);break;
                case P_TCP_LISTEN:if(re&POLLIN) accept_tcp(tcp,false);break;
                case P_METRIC_LISTEN:if(re&POLLIN) accept_tcp(mfd,true);break;
                case P_TCP_CLIENT: {
                    Client *c=&clients[items[i].idx];
                    if(c->fd!=fd || c->generation!=items[i].generation) break;
                    if(re&(POLLERR|POLLNVAL|POLLHUP)) close_client(c);
                    else tcp_io(c,re); /* Peer SHUT_WR arrives as readable EOF. */
                    break;
                }
                case P_METRIC_CLIENT: {
                    MetricClient *c=&metric_clients[items[i].idx];
                    if(c->fd!=fd || c->generation!=items[i].generation) break;
                    if(re&(POLLERR|POLLHUP|POLLNVAL)) close_metric(c);
                    else metric_io(c,re);
                    break;
                }
                case P_CURL:
                    if(curl_socket_still_watched(fd,items[i].generation)) {
                        int ev=0;
                        if(re&POLLIN) ev|=CURL_CSELECT_IN;
                        if(re&POLLOUT) ev|=CURL_CSELECT_OUT;
                        if(re&(POLLERR|POLLHUP|POLLNVAL)) ev|=CURL_CSELECT_ERR;
                        if(!drive_curl(fd,ev)) {exitcode=1;stopping=1;}
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
    while(idle_easy_count) curl_easy_cleanup(idle_easies[--idle_easy_count]);
    free(answer_cache);
    if(udp>=0) close(udp);
    if(tcp>=0) close(tcp);
    if(mfd>=0) close(mfd);
    curl_multi_cleanup(multi);
    curl_slist_free_all(doh_headers);
    curl_slist_free_all(bootstrap_hosts);
    curl_global_cleanup();
    return exitcode;
}
