#define main dnsp_proxy_main
#include "../dnsp-modern.c"
#undef main

static void fuzz_query(const uint8_t *data,size_t size) {
    DnsInfo info;
    if(dns_parse(data,size,NULL,&info)!=DNS_OK) return;
    size_t extra=edns_padding_size(data,size,&info);
    if(!extra) return;

    unsigned char *padded=malloc(size+extra);
    if(!padded) abort();
    write_padded_query(padded,data,size,&info,extra);
    if(dns_parse(padded,size+extra,NULL,&info)!=DNS_OK) abort();
    free(padded);
}

static void fuzz_reply(const uint8_t *data,size_t size) {
    const DnsInfo request={.qname="\3www\6google\3com",.qname_len=16,
                           .qtype=1,.qclass=1,.has_opt=true};
    DnsInfo info;
    if(dns_parse(data,size,&request,&info)!=DNS_OK) return;

    unsigned char *wire=malloc(size);
    if(!wire) abort();
    memcpy(wire,data,size);
    Query q={.response=wire,.resp_len=size,.added_padding=true};
    strip_doh_padding(&q,&info);
    CacheTtls ttls;
    if(cache_ttls(&q,&info,&ttls)) {
        for(size_t i=0;i<ttls.count;i++) {
            if(ttls.offset[i]+4u>q.resp_len) abort();
        }
    }
    age_forwarded_ttls(&q,&info,7);
    free(wire);
}

static void fuzz_headers(const uint8_t *data,size_t size) {
    Query q={.cache_headers.max_age=UINT32_MAX};
    while(size) {
        const uint8_t *newline=memchr(data,'\n',size);
        size_t length=newline?(size_t)(newline-data)+1:size;
        /* libcurl's callback signature takes a mutable pointer. */
        if(collect_doh_header((char *)data,1,length,&q)!=length) abort();
        data+=length;
        size-=length;
    }
    if(q.cache_headers.age && !q.cache_headers.age_seen) abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data,size_t size) {
    if(!size) return 0;
    switch(data[0]) {
        case 'Q': fuzz_query(data+1,size-1);break;
        case 'R': fuzz_reply(data+1,size-1);break;
        case 'H': fuzz_headers(data+1,size-1);break;
    }
    return 0;
}
