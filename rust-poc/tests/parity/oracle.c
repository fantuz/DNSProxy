/* Differential fixture. Compile with -I pointing to the pinned C checkout. */
#define main reference_main
#include "dnsp-modern.c"
#undef main

static unsigned long long fingerprint(const unsigned char *data, size_t length) {
    unsigned long long hash=14695981039346656037ULL;
    for (size_t i=0; i<length; i++) hash=(hash^data[i])*1099511628211ULL;
    return hash;
}

static void describe(DnsResult status, const DnsInfo *info) {
    printf("%d", (int)status);
    if (status==DNS_DROP) return;
    printf(" %zu %zu %u %u %u %u %u %u %u %u %llu",
        info->question_end, info->final_opt_rdlen, (unsigned)info->udp_limit,
        (unsigned)info->qtype, (unsigned)info->qclass, (unsigned)info->opcode,
        (unsigned)info->opt_ext_rcode, (unsigned)info->has_opt, (unsigned)info->opt_do,
        (unsigned)info->message_signature, fingerprint(info->qname, info->qname_len));
}

int main(void) {
    static CacheEntry slots[17];
    answer_cache=slots;
    cache_entries=sizeof(slots)/sizeof(*slots);

    unsigned char header[11];
    while (fread(header, 1, sizeof(header), stdin)==sizeof(header)) {
        udp_reply_max=be16(header);
        size_t query_len=be32(header+2), response_len=be32(header+6);
        unsigned char *query=malloc(query_len?query_len:1), *response=malloc(response_len?response_len:1);
        if (!query || !response || fread(query, 1, query_len, stdin)!=query_len ||
            fread(response, 1, response_len, stdin)!=response_len) return 1;
        DnsInfo qinfo={0}, rinfo={0};
        DnsResult status=dns_parse(query,query_len,NULL,&qinfo);
        describe(status,&qinfo);
        if (status==DNS_OK) {
            CacheEntry *slot=cache_slot_for(query,query_len,&qinfo);
            size_t extra=edns_padding_size(query,query_len,&qinfo);
            unsigned long long padded_hash=0;
            if (extra) {
                unsigned char *padded=malloc(query_len+extra);
                if (!padded) return 1;
                write_padded_query(padded,query,query_len,&qinfo,extra);
                padded_hash=fingerprint(padded,query_len+extra);
                free(padded);
            }
            printf(" | %u %u %td %zu %llu", (unsigned)plain_address_query(query,&qinfo),
                   (unsigned)failover_eligible(query,&qinfo), slot?slot-slots:-1,
                   extra?query_len+extra:0, padded_hash);
            if (header[10]) {
                printf(" | ");
                status=dns_parse(response,response_len,&qinfo,&rinfo);
                describe(status,&rinfo);
                if (status==DNS_OK) {
                    Query q={.response=response,.resp_len=response_len,.added_padding=extra!=0};
                    strip_doh_padding(&q,&rinfo);
                    CacheTtls ttls;
                    if (cache_ttls(&q,&rinfo,&ttls)) {
                        printf(" | %u", ttls.min_ttl);
                        for (size_t i=0;i<ttls.count;i++) printf(" %u",(unsigned)ttls.offset[i]);
                    }
                    age_forwarded_ttls(&q,&rinfo,17);
                    printf(" | %zu %llu", q.resp_len, fingerprint(response,q.resp_len));
                }
            }
        }
        putchar('\n');
        free(query);
        free(response);
    }
    return ferror(stdin)!=0;
}
