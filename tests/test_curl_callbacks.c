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
    return 0;
}
