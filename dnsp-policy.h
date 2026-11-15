#ifndef DNSP_POLICY_H
#define DNSP_POLICY_H

/* Immutable, bounded domain policy. Only the loader thread touches files;
 * publication, lookups and retirement belong to the resolver event loop. */
#include <sys/stat.h>
#ifdef _WIN32
#include <io.h>
#else
#include <pthread.h>
#endif

enum { POLICY_MAX_FILES=64, POLICY_MAX_RULES=1000000, POLICY_LINE_MAX=4096,
       POLICY_INPUT_MAX=64*1024*1024, POLICY_POOL_MAX=64*1024*1024,
       POLICY_POOL_BLOCK=65536, POLICY_EXACT=1, POLICY_CHILDREN=2 };
typedef struct {const char *path; bool allow;} PolicySource;
typedef struct {size_t count; PolicySource file[POLICY_MAX_FILES];} PolicyConfig;
typedef struct {uint64_t size,modified,changed,device,inode;} PolicyStamp;
typedef struct {const char *name; unsigned flags;} PolicyRule;
typedef struct {PolicyRule *rule; size_t count,capacity;} PolicyIndex;
typedef struct PolicyPool PolicyPool;
struct PolicyPool {PolicyPool *next; size_t used,capacity; char data[];};
typedef struct {
    PolicyIndex deny,allow;
    PolicyPool *pool;
    size_t bytes,pool_bytes,input_bytes,parsed;
    PolicyStamp stamp[POLICY_MAX_FILES];
    uint64_t generation,loaded_ms;
} Policy;
typedef struct {
    const PolicyConfig *config;
    const Policy *previous;
    Policy *candidate;
    atomic_bool done,cancel;
    bool running,forced,changed;
    char error[256];
#ifdef _WIN32
    HANDLE thread;
#else
    pthread_t thread;
#endif
} PolicyWorker;

static void policy_free(Policy *policy) {
    if(!policy) return;
    while(policy->pool) {
        PolicyPool *next=policy->pool->next;
        free(policy->pool);policy->pool=next;
    }
    free(policy->deny.rule);free(policy->allow.rule);free(policy);
}
static FILE *policy_open(const char *path) {
#ifdef _WIN32
    int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,path,-1,NULL,0);
    wchar_t *wide=n?calloc((size_t)n,sizeof(*wide)):NULL;
    FILE *file=NULL;
    if(wide && MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,path,-1,wide,n)) {
        DWORD attrs=GetFileAttributesW(wide);
        if(attrs!=INVALID_FILE_ATTRIBUTES && !(attrs&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_DEVICE))) {
            HANDLE handle=CreateFileW(wide,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                NULL,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN,NULL);
            if(handle!=INVALID_HANDLE_VALUE) {
                int fd=_open_osfhandle((intptr_t)handle,_O_RDONLY|_O_BINARY);
                if(fd<0) CloseHandle(handle);
                else {file=_fdopen(fd,"rb");if(!file) _close(fd);}
            }
        }
    }
    free(wide);return file;
#else
    int fd=open(path,O_RDONLY|O_NONBLOCK|O_CLOEXEC);
    if(fd<0) return NULL;
    FILE *file=fdopen(fd,"rb");
    if(!file) close(fd);
    return file;
#endif
}
static bool policy_stamp(FILE *file,PolicyStamp *stamp) {
#ifdef _WIN32
    BY_HANDLE_FILE_INFORMATION info;
    HANDLE handle=(HANDLE)_get_osfhandle(_fileno(file));
    if(GetFileType(handle)!=FILE_TYPE_DISK || !GetFileInformationByHandle(handle,&info) ||
       (info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)) return false;
    *stamp=(PolicyStamp){.size=((uint64_t)info.nFileSizeHigh<<32)|info.nFileSizeLow,
        .modified=((uint64_t)info.ftLastWriteTime.dwHighDateTime<<32)|info.ftLastWriteTime.dwLowDateTime,
        .changed=((uint64_t)info.ftCreationTime.dwHighDateTime<<32)|info.ftCreationTime.dwLowDateTime,
        .device=info.dwVolumeSerialNumber,.inode=((uint64_t)info.nFileIndexHigh<<32)|info.nFileIndexLow};
#else
    struct stat info;
    if(fstat(fileno(file),&info)!=0 || !S_ISREG(info.st_mode) || info.st_size<0) return false;
#ifdef __APPLE__
    uint64_t modified=(uint64_t)info.st_mtimespec.tv_sec*1000000000u+(uint64_t)info.st_mtimespec.tv_nsec;
    uint64_t changed=(uint64_t)info.st_ctimespec.tv_sec*1000000000u+(uint64_t)info.st_ctimespec.tv_nsec;
#else
    uint64_t modified=(uint64_t)info.st_mtim.tv_sec*1000000000u+(uint64_t)info.st_mtim.tv_nsec;
    uint64_t changed=(uint64_t)info.st_ctim.tv_sec*1000000000u+(uint64_t)info.st_ctim.tv_nsec;
#endif
    *stamp=(PolicyStamp){.size=(uint64_t)info.st_size,.modified=modified,.changed=changed,
        .device=(uint64_t)info.st_dev,.inode=(uint64_t)info.st_ino};
#endif
    return true;
}
static bool policy_equal_stamp(PolicyStamp a,PolicyStamp b) {
    return a.size==b.size && a.modified==b.modified && a.changed==b.changed &&
           a.device==b.device && a.inode==b.inode;
}
static bool policy_sources_unchanged(const PolicyConfig *config,const Policy *old) {
    for(size_t i=0;i<config->count;i++) {
        FILE *file=policy_open(config->file[i].path);
        PolicyStamp stamp={0};
        bool ok=file && policy_stamp(file,&stamp) && policy_equal_stamp(stamp,old->stamp[i]);
        if(file) fclose(file);
        if(!ok) return false;
    }
    return true;
}
static int policy_compare(const void *left,const void *right) {
    return strcmp(((const PolicyRule*)left)->name,((const PolicyRule*)right)->name);
}
static void policy_sort(PolicyIndex *index) {
    if(index->count<2) return;
    qsort(index->rule,index->count,sizeof(*index->rule),policy_compare);
    size_t n=1;
    for(size_t i=1;i<index->count;i++) {
        if(!strcmp(index->rule[n-1].name,index->rule[i].name))
            index->rule[n-1].flags|=index->rule[i].flags;
        else index->rule[n++]=index->rule[i];
    }
    index->count=n;
}
/* List syntax is ASCII DNS presentation form, with IDNs supplied as A-labels.
 * Wire names are not C strings: embedded dots/NULs never acquire a new meaning. */
static bool policy_normalize(char *name,unsigned *flags) {
    *flags=POLICY_EXACT;
    if(name[0]=='*' && name[1]=='.') {memmove(name,name+2,strlen(name+2)+1);*flags=POLICY_CHILDREN;}
    else if(name[0]=='.') {memmove(name,name+1,strlen(name+1)+1);*flags=POLICY_EXACT|POLICY_CHILDREN;}
    size_t n=strlen(name);
    if(n && name[n-1]=='.') name[--n]=0;
    if(!n || n>253) return false;
    size_t label=0;
    for(size_t i=0;i<n;i++) {
        unsigned char c=(unsigned char)name[i];
        if(c=='.') {if(!label) return false;label=0;continue;}
        if(!((c>='a' && c<='z') || (c>='A' && c<='Z') ||
             (c>='0' && c<='9') || c=='-' || c=='_') || ++label>63) return false;
        if(c>='A' && c<='Z') name[i]=(char)(c+('a'-'A'));
    }
    return label!=0;
}
static bool policy_add(Policy *policy,bool allow,char *name,char *error,size_t error_len) {
    unsigned flags;
    if(!policy_normalize(name,&flags)) {snprintf(error,error_len,"invalid domain or unsupported list syntax");return false;}
    if(policy->parsed==POLICY_MAX_RULES) {snprintf(error,error_len,"more than %d input entries",POLICY_MAX_RULES);return false;}
    size_t n=strlen(name)+1;
    PolicyPool *pool=policy->pool;
    if(!pool || n>pool->capacity-pool->used) {
        if(policy->pool_bytes>POLICY_POOL_MAX-POLICY_POOL_BLOCK) {snprintf(error,error_len,"domain storage limit exceeded");return false;}
        pool=malloc(sizeof(*pool)+POLICY_POOL_BLOCK);
        if(!pool) goto allocation;
        *pool=(PolicyPool){.next=policy->pool,.capacity=POLICY_POOL_BLOCK};
        policy->pool=pool;policy->pool_bytes+=POLICY_POOL_BLOCK;
        policy->bytes+=sizeof(*pool)+POLICY_POOL_BLOCK;
    }
    PolicyIndex *index=allow?&policy->allow:&policy->deny;
    if(index->count==index->capacity) {
        size_t capacity=index->capacity?index->capacity*2:1024;
        if(capacity>POLICY_MAX_RULES) capacity=POLICY_MAX_RULES;
        PolicyRule *rules=realloc(index->rule,capacity*sizeof(*rules));
        if(!rules) goto allocation;
        policy->bytes+=(capacity-index->capacity)*sizeof(*rules);
        index->rule=rules;index->capacity=capacity;
    }
    memcpy(pool->data+pool->used,name,n);
    index->rule[index->count++]=(PolicyRule){.name=pool->data+pool->used,.flags=flags};
    pool->used+=n;policy->parsed++;
    return true;
allocation:
    snprintf(error,error_len,"policy allocation failed");return false;
}
static bool policy_line(Policy *policy,bool allow,char *line,char *error,size_t error_len) {
    char *comment=strchr(line,'#');if(comment) *comment=0;
    char *p=line;
    while(*p==' ' || *p=='\t' || *p=='\r') p++;
    if(!*p) return true;
    char *first=p;
    while(*p && *p!=' ' && *p!='\t' && *p!='\r') p++;
    if(*p) *p++=0;
    unsigned char address[16];
    bool hosts=inet_pton(AF_INET,first,address)==1 || inet_pton(AF_INET6,first,address)==1;
    if(!hosts) {
        while(*p==' ' || *p=='\t' || *p=='\r') p++;
        if(*p) {snprintf(error,error_len,"extra fields on a domain-only line");return false;}
        return policy_add(policy,allow,first,error,error_len);
    }
    bool found=false;
    while(*p) {
        while(*p==' ' || *p=='\t' || *p=='\r') p++;
        if(!*p) break;
        char *name=p;
        while(*p && *p!=' ' && *p!='\t' && *p!='\r') p++;
        if(*p) *p++=0;
        if(!policy_add(policy,allow,name,error,error_len)) return false;
        found=true;
    }
    if(!found) snprintf(error,error_len,"hosts address has no domain");
    return found;
}
static Policy *policy_load(const PolicyConfig *config,const atomic_bool *cancel,char error[256]) {
    Policy *policy=calloc(1,sizeof(*policy));
    if(!policy) {snprintf(error,256,"policy allocation failed");return NULL;}
    policy->bytes=sizeof(*policy);
    for(size_t i=0;i<config->count;i++) {
        FILE *file=policy_open(config->file[i].path);
        if(!file) {snprintf(error,256,"cannot open list %.160s",config->file[i].path);goto fail;}
        PolicyStamp before={0},after={0};
        bool ok=policy_stamp(file,&before) && before.size<=POLICY_INPUT_MAX-policy->input_bytes;
        char detail[160]="not a regular file or aggregate input exceeds 64 MiB";
        size_t line_no=0;
        char line[POLICY_LINE_MAX+1];
        while(ok) {
            size_t n=0;int c=EOF;
            if(atomic_load_explicit(cancel,memory_order_relaxed)) {ok=false;snprintf(detail,sizeof(detail),"cancelled");break;}
            while((c=fgetc(file))!=EOF && c!='\n') {
                if(policy->input_bytes==POLICY_INPUT_MAX || n==POLICY_LINE_MAX || !c) {ok=false;break;}
                policy->input_bytes++;line[n++]=(char)c;
            }
            if(!ok) {snprintf(detail,sizeof(detail),"input limit exceeded or embedded NUL");break;}
            if(c=='\n') {
                if(policy->input_bytes==POLICY_INPUT_MAX) {ok=false;snprintf(detail,sizeof(detail),"input limit exceeded");break;}
                policy->input_bytes++;
            }
            if(c==EOF && !n) break;
            line[n]=0;line_no++;
            char *start=line;
            if(line_no==1 && n>=3 && !memcmp(line,"\xef\xbb\xbf",3)) start+=3;
            if(!policy_line(policy,config->file[i].allow,start,detail,sizeof(detail))) {ok=false;break;}
            if(c==EOF) break;
        }
        ok=ok && !ferror(file) && policy_stamp(file,&after) && policy_equal_stamp(before,after);
        fclose(file);
        if(!ok) {snprintf(error,256,"%.100s:%zu: %.120s",config->file[i].path,line_no,detail);goto fail;}
        policy->stamp[i]=before;
    }
    policy_sort(&policy->deny);policy_sort(&policy->allow);
    if(!policy_sources_unchanged(config,policy)) {snprintf(error,256,"list changed while loading");goto fail;}
    return policy;
fail:
    policy_free(policy);return NULL;
}
static unsigned policy_find(const PolicyIndex *index,const char *name) {
    size_t left=0,right=index->count;
    while(left<right) {
        size_t mid=left+(right-left)/2;
        int cmp=strcmp(name,index->rule[mid].name);
        if(!cmp) return index->rule[mid].flags;
        if(cmp<0) right=mid;else left=mid+1;
    }
    return 0;
}
static bool policy_match(const PolicyIndex *index,const char *name) {
    if(policy_find(index,name)&POLICY_EXACT) return true;
    for(const char *p=strchr(name,'.');p;p=strchr(p+1,'.'))
        if(policy_find(index,p+1)&POLICY_CHILDREN) return true;
    return false;
}
static bool policy_blocked(const Policy *policy,const unsigned char *wire,size_t length) {
    if(!policy || !policy->deny.count || !length) return false;
    char name[256];size_t pos=0,used=0;
    while(pos<length) {
        size_t n=wire[pos++];
        if(!n) {
            if(pos!=length || !used) return false;
            name[used]=0;
            return !policy_match(&policy->allow,name) && policy_match(&policy->deny,name);
        }
        if(n>63 || n>length-pos || used+n+1>=sizeof(name)) return false;
        if(used) name[used++]='.';
        for(size_t i=0;i<n;i++) {
            unsigned char c=wire[pos++];
            if(!((c>='a' && c<='z') || (c>='A' && c<='Z') ||
                 (c>='0' && c<='9') || c=='-' || c=='_')) return false;
            name[used++]=(char)((c>='A' && c<='Z')?c+('a'-'A'):c);
        }
    }
    return false;
}
static void policy_worker_run(PolicyWorker *worker) {
    worker->changed=worker->forced || !policy_sources_unchanged(worker->config,worker->previous);
    if(worker->changed) worker->candidate=policy_load(worker->config,&worker->cancel,worker->error);
    atomic_store_explicit(&worker->done,true,memory_order_release);
}
#ifdef _WIN32
static DWORD WINAPI policy_thread(void *arg) {policy_worker_run(arg);return 0;}
#else
static void *policy_thread(void *arg) {policy_worker_run(arg);return NULL;}
#endif
static bool policy_worker_start(PolicyWorker *worker,const PolicyConfig *config,const Policy *old,bool force) {
    *worker=(PolicyWorker){.config=config,.previous=old,.forced=force};
    atomic_init(&worker->done,false);atomic_init(&worker->cancel,false);
#ifdef _WIN32
    worker->thread=CreateThread(NULL,0,policy_thread,worker,0,NULL);
    worker->running=worker->thread!=NULL;
#else
    worker->running=pthread_create(&worker->thread,NULL,policy_thread,worker)==0;
#endif
    return worker->running;
}
static void policy_worker_join(PolicyWorker *worker) {
    if(!worker->running) return;
#ifdef _WIN32
    WaitForSingleObject(worker->thread,INFINITE);CloseHandle(worker->thread);
#else
    pthread_join(worker->thread,NULL);
#endif
    worker->running=false;
}

#endif
