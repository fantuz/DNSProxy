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
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* Opt-in DNS/DoH transport: single-owner event loop, bounded concurrency. */
enum { DNS_MAX=4096, TCP_MAX=65535, MAX_ACTIVE=128, MAX_CLIENTS=128 };
static volatile sig_atomic_t stopping;
static void stop_now(int sig) { (void)sig; stopping=1; }
static int nonblock(int fd) { int f=fcntl(fd,F_GETFL,0); return f<0?-1:fcntl(fd,F_SETFL,f|O_NONBLOCK); }
static uint16_t be16(const unsigned char *p) { return (uint16_t)(((unsigned)p[0]<<8)|p[1]); }

/* No C string functions on DNS wire bytes. Require exactly one complete question,
   with no compression pointer in QNAME (compression in responses is untouched). */
static bool valid_query(const unsigned char *p,size_t n) {
    if(n<17 || (p[2]&0x80) || be16(p+4)!=1) return false;
    size_t pos=12, labels=0, name_len=0;
    while(pos<n) {
        unsigned len=p[pos++];
        if(!len) return labels>0 && pos+4<=n;
        if(len>63 || pos+len>n || ++labels>127 || (name_len+=len+1)>255) return false;
        pos+=len;
    }
    return false;
}

typedef struct Client Client;
typedef struct Query Query;
struct Client { int fd; size_t have, need, sent, out_len; unsigned char in[TCP_MAX+2],out[TCP_MAX+2]; bool busy; uint64_t generation; };
struct Query {
    CURL *easy; struct curl_slist *headers;
    unsigned char *request, *response;
    size_t req_len, resp_len, resp_cap;
    struct sockaddr_storage peer; socklen_t peer_len;
    Client *client; uint64_t generation; int udp_fd;
    Query *next;
};
static Query *active;
static size_t active_count;
static CURLM *multi;
static const char *upstream;
static Client clients[MAX_CLIENTS];

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
        q->response=newp; q->resp_cap=cap;
    }
    memcpy(q->response+q->resp_len,p,n); q->resp_len+=n;
    return n;
}
static void remove_query(Query *q) {
    Query **it=&active;
    while(*it && *it!=q) it=&(*it)->next;
    if(*it) *it=q->next;
    if(q->easy) { curl_multi_remove_handle(multi,q->easy); curl_easy_cleanup(q->easy); }
    curl_slist_free_all(q->headers);
    free(q->request); free(q->response); free(q); --active_count;
}
static void close_client(Client *c) {
    if(c->fd>=0) close(c->fd);
    c->fd=-1; c->have=c->need=c->sent=c->out_len=0; c->busy=false; c->generation++;
}
static void send_error(Query *q,unsigned char rcode) {
    /* DNS SERVFAIL/REFUSED with original question retained, never synthesize
       an answer RR. Keep the request ID and RD flag. */
    if(q->req_len>TCP_MAX) return;
    size_t length=12, pos=12;
    while(pos<q->req_len && q->request[pos]) pos+=(size_t)q->request[pos]+1;
    if(pos+5>q->req_len) return;
    length=pos+5;
    unsigned char *p=malloc(length);
    if(!p) return;
    memcpy(p,q->request,length);
    p[2]=(unsigned char)((p[2]&0x79)|0x80); /* QR=1, clear TC/AA */
    p[3]=(unsigned char)((p[3]&0xf0)|(rcode&0x0f));
    memset(p+6,0,6);
    if(q->client) {
        Client *c=q->client;
        if(c->fd>=0 && c->generation==q->generation) {
            c->out[0]=(unsigned char)(length>>8); c->out[1]=(unsigned char)length;
            memcpy(c->out+2,p,length); c->out_len=length+2; c->sent=0;
        }
    } else sendto(q->udp_fd,p,length,0,(struct sockaddr*)&q->peer,q->peer_len);
    free(p);
}
static void complete(Query *q,CURLcode code) {
    long status=0;
    if(code==CURLE_OK) curl_easy_getinfo(q->easy,CURLINFO_RESPONSE_CODE,&status);
    bool ok=code==CURLE_OK && status==200 && q->resp_len>=12 && q->resp_len<=TCP_MAX
       && (q->response[2]&0x80) && memcmp(q->response,q->request,2)==0;
    if(ok) {
        if(q->client) {
            Client *c=q->client;
            if(c->fd>=0 && c->generation==q->generation) {
                c->out[0]=(unsigned char)(q->resp_len>>8); c->out[1]=(unsigned char)q->resp_len;
                memcpy(c->out+2,q->response,q->resp_len); c->out_len=q->resp_len+2; c->sent=0;
            }
        } else {
            /* Avoid returning oversized responses to UDP clients. */
            if(q->resp_len<=DNS_MAX) sendto(q->udp_fd,q->response,q->resp_len,0,(struct sockaddr*)&q->peer,q->peer_len);
            else send_error(q,2);
        }
    } else send_error(q,2);
    if(q->client && q->client->fd>=0 && q->client->generation==q->generation) q->client->busy=false;
    remove_query(q);
}
static bool submit(const unsigned char *data,size_t len,Client *client,int udp_fd,
                   const struct sockaddr_storage *peer,socklen_t peer_len) {
    if(active_count>=MAX_ACTIVE || !valid_query(data,len)) return false;
    Query *q=calloc(1,sizeof(*q)); if(!q) return false;
    q->request=malloc(len); if(!q->request) {free(q);return false;}
    memcpy(q->request,data,len); q->req_len=len;
    q->client=client; q->generation=client?client->generation:0; q->udp_fd=udp_fd;
    if(peer) {q->peer=*peer; q->peer_len=peer_len;}
    q->easy=curl_easy_init();
    if(!q->easy) {free(q->request);free(q);return false;}
    q->headers=curl_slist_append(q->headers,"Content-Type: application/dns-message");
    q->headers=curl_slist_append(q->headers,"Accept: application/dns-message");
    curl_easy_setopt(q->easy,CURLOPT_URL,upstream);
    curl_easy_setopt(q->easy,CURLOPT_HTTPHEADER,q->headers);
    curl_easy_setopt(q->easy,CURLOPT_POSTFIELDS,q->request);
    curl_easy_setopt(q->easy,CURLOPT_POSTFIELDSIZE_LARGE,(curl_off_t)len);
    curl_easy_setopt(q->easy,CURLOPT_HTTP_VERSION,CURL_HTTP_VERSION_2TLS);
    curl_easy_setopt(q->easy,CURLOPT_WRITEFUNCTION,collect);
    curl_easy_setopt(q->easy,CURLOPT_WRITEDATA,q);
    curl_easy_setopt(q->easy,CURLOPT_PRIVATE,q);
    curl_easy_setopt(q->easy,CURLOPT_TIMEOUT_MS,3000L);
    curl_easy_setopt(q->easy,CURLOPT_CONNECTTIMEOUT_MS,1500L);
    curl_easy_setopt(q->easy,CURLOPT_SSL_VERIFYPEER,1L);
    curl_easy_setopt(q->easy,CURLOPT_SSL_VERIFYHOST,2L);
    curl_easy_setopt(q->easy,CURLOPT_FOLLOWLOCATION,0L);
    curl_easy_setopt(q->easy,CURLOPT_NOSIGNAL,1L);
    if(curl_multi_add_handle(multi,q->easy)!=CURLM_OK) {
        curl_easy_cleanup(q->easy);curl_slist_free_all(q->headers);free(q->request);free(q);return false;
    }
    q->next=active; active=q; ++active_count;
    if(client) client->busy=true;
    return true;
}
static int listener(int type,const char *bindip,int port) {
    int fd=socket(AF_INET,type,0),yes=1;
    if(fd<0) return -1;
    setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes));
    struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons((uint16_t)port)};
    if(inet_pton(AF_INET,bindip,&a.sin_addr)!=1 || nonblock(fd)<0 ||
       bind(fd,(struct sockaddr*)&a,sizeof(a))<0 || (type==SOCK_STREAM && listen(fd,128)<0)) {
        close(fd);return -1;
    }
    return fd;
}
static void tcp_io(Client *c,short events) {
    if(c->fd<0) return;
    if(c->out_len) {
        if(events&POLLOUT) {
            ssize_t n=send(c->fd,c->out+c->sent,c->out_len-c->sent,MSG_NOSIGNAL);
            if(n>0) c->sent+=(size_t)n;
            else if(n<0 && (errno==EAGAIN || errno==EINTR)) return;
            else {close_client(c);return;}
            if(c->sent==c->out_len) close_client(c); /* one request per TCP connection */
        }
        return;
    }
    if(c->busy || !(events&POLLIN)) return;
    size_t target=c->need?c->need:2;
    ssize_t n=recv(c->fd,c->in+c->have,target-c->have,0);
    if(n==0) {close_client(c);return;}
    if(n<0) {if(errno!=EAGAIN && errno!=EINTR) close_client(c);return;}
    c->have+=(size_t)n;
    if(c->have==2 && !c->need) {
        size_t length=be16(c->in);
        if(length<17 || length>TCP_MAX) {close_client(c);return;}
        c->need=length+2;
    }
    if(c->need && c->have==c->need) {
        if(!submit(c->in+2,c->need-2,c,-1,NULL,0)) close_client(c);
    }
}
static void udp_io(int fd) {
    unsigned char buf[DNS_MAX];
    for(int i=0;i<32;i++) {
        struct sockaddr_storage peer; socklen_t slen=sizeof(peer);
        ssize_t n=recvfrom(fd,buf,sizeof(buf),0,(struct sockaddr*)&peer,&slen);
        if(n<0) break;
        if(!submit(buf,(size_t)n,NULL,fd,&peer,slen) && n>=12 && valid_query(buf,(size_t)n)) {
            /* overload: deliberately drop UDP; client may retry */
        }
    }
}
static void drain_completions(void) {
    int remaining; CURLMsg *msg;
    while((msg=curl_multi_info_read(multi,&remaining))) {
        if(msg->msg==CURLMSG_DONE) {
            Query *q=NULL;
            curl_easy_getinfo(msg->easy_handle,CURLINFO_PRIVATE,&q);
            if(q) complete(q,msg->data.result);
        }
    }
}
int main(int argc,char **argv) {
    const char *bindip="127.0.0.1"; int port=5300;
    upstream="https://cloudflare-dns.com/dns-query";
    for(int i=1;i<argc;i++) {
        if(!strcmp(argv[i],"-l") && i+1<argc) bindip=argv[++i];
        else if(!strcmp(argv[i],"-p") && i+1<argc) port=atoi(argv[++i]);
        else if(!strcmp(argv[i],"-s") && i+1<argc) upstream=argv[++i];
        else {fprintf(stderr,"usage: %s [-l IPv4] [-p port] [-s https://DoH-URL]\n",argv[0]);return 2;}
    }
    if(port<1 || port>65535 || (strncmp(upstream,"https://",8)!=0 && strncmp(upstream,"http://127.0.0.1:",17)!=0)) {
        fprintf(stderr,"invalid port or upstream (only HTTPS or local HTTP test endpoint)\n");return 2;
    }
    signal(SIGINT,stop_now);signal(SIGTERM,stop_now);signal(SIGPIPE,SIG_IGN);
    for(size_t i=0;i<MAX_CLIENTS;i++) clients[i].fd=-1;
    if(curl_global_init(CURL_GLOBAL_DEFAULT)!=CURLE_OK) return 1;
    multi=curl_multi_init();if(!multi) return 1;
    curl_multi_setopt(multi,CURLMOPT_MAX_TOTAL_CONNECTIONS,16L);
    curl_multi_setopt(multi,CURLMOPT_MAX_HOST_CONNECTIONS,8L);
    curl_multi_setopt(multi,CURLMOPT_PIPELINING,CURLPIPE_MULTIPLEX);
    int udp=listener(SOCK_DGRAM,bindip,port),tcp=listener(SOCK_STREAM,bindip,port);
    if(udp<0 || tcp<0) {perror("listen");return 1;}
    fprintf(stderr,"DNSProxy modern listening %s:%d -> %s\n",bindip,port,upstream);
    while(!stopping) {
        int running=0;curl_multi_perform(multi,&running);drain_completions();
        struct pollfd pfds[2+MAX_CLIENTS]; Client *mapping[MAX_CLIENTS];
        nfds_t nfds=0;pfds[nfds++]=(struct pollfd){.fd=udp,.events=POLLIN};
        pfds[nfds++]=(struct pollfd){.fd=tcp,.events=POLLIN};
        size_t mapped=0;
        for(size_t i=0;i<MAX_CLIENTS;i++) if(clients[i].fd>=0) {
            mapping[mapped++]=&clients[i];
            pfds[nfds++]=(struct pollfd){.fd=clients[i].fd,.events=clients[i].out_len?POLLOUT:(clients[i].busy?0:POLLIN)};
        }
        /* libcurl owns its connection sockets. curl_multi_poll services them,
           but must not block the listener; poll the listeners briefly first. */
        int ready=poll(pfds,nfds,10);
        if(ready>0) {
            if(pfds[0].revents&POLLIN) udp_io(udp);
            if(pfds[1].revents&POLLIN) for(int i=0;i<16;i++) {
                int fd=accept(tcp,NULL,NULL);
                if(fd<0) break;
                if(nonblock(fd)<0) {close(fd);continue;}
                size_t j=0;while(j<MAX_CLIENTS && clients[j].fd>=0) j++;
                if(j==MAX_CLIENTS) close(fd);
                else {uint64_t gen=clients[j].generation+1;clients[j]=(Client){.fd=fd,.generation=gen};}
            }
            for(size_t i=0;i<mapped;i++) {
                short ev=pfds[i+2].revents;
                if(ev&(POLLERR|POLLHUP|POLLNVAL)) close_client(mapping[i]);
                else if(ev) tcp_io(mapping[i],ev);
            }
        }
        curl_multi_poll(multi,NULL,0,0,NULL);
    }
    for(size_t i=0;i<MAX_CLIENTS;i++) close_client(&clients[i]);
    while(active) remove_query(active);
    close(udp);close(tcp);curl_multi_cleanup(multi);curl_global_cleanup();
    return 0;
}
