#define main dnsp_proxy_main
#include "../dnsp-modern.c"
#undef main

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

    if(select_http_version(0,false)!=CURL_HTTP_VERSION_1_1 ||
       select_http_version(CURL_VERSION_HTTP2,false)!=CURL_HTTP_VERSION_2TLS ||
       select_http_version(CURL_VERSION_HTTP2,true)!=CURL_HTTP_VERSION_NONE) return 9;
#if LIBCURL_VERSION_NUM >= 0x074200
    if(select_http_version(CURL_VERSION_HTTP2|CURL_VERSION_HTTP3,false)!=CURL_HTTP_VERSION_2TLS ||
       select_http_version(CURL_VERSION_HTTP2|CURL_VERSION_HTTP3,true)!=CURL_HTTP_VERSION_3) return 9;
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
    return valid?0:11;
}
