/* Native lifecycle / DNS configuration helper. No third-party runtime required.
 * DNS snapshots are configured values, never DHCP's effective resolver list. */
#import <Foundation/Foundation.h>
#import <SystemConfiguration/SystemConfiguration.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <grp.h>

static NSString *const Root=@"/Library/Application Support/DNSProxy";
static NSString *const Label=@"net.fantuz.dnsproxy";
static NSString *const Recovery=@"net.fantuz.dnsproxy.recovery";
static NSString *const Daemons=@"/Library/LaunchDaemons";
static NSString *const Log=@"/var/log/dnsp-modern.log";
static void require(BOOL ok,NSString *reason) {
    if(!ok) @throw [NSException exceptionWithName:@"DNSProxy" reason:reason userInfo:nil];
}
static NSString *inside(NSString *name) {return [Root stringByAppendingPathComponent:name];}
static BOOL exists(NSString *path) {struct stat st;return lstat(path.fileSystemRepresentation,&st)==0;}
static void protectedPath(NSString *path,BOOL directory) {
    struct stat st;
    require(lstat(path.fileSystemRepresentation,&st)==0 && st.st_uid==0 && !(st.st_mode&0022) &&
            (directory?S_ISDIR(st.st_mode):S_ISREG(st.st_mode)),
            [@"Unsafe ownership, permissions or path: " stringByAppendingString:path]);
}
static void syncDirectory(NSString *path) {
    int fd=open(path.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
    require(fd>=0,@"Cannot open state directory");
    int result=fsync(fd);close(fd);require(result==0,@"Cannot sync state directory");
}
static void save(NSDictionary *value,NSString *path) {
    NSError *error=nil;
    NSData *data=[NSPropertyListSerialization dataWithPropertyList:value format:NSPropertyListXMLFormat_v1_0 options:0 error:&error];
    require(data!=nil,error.localizedDescription?:@"Invalid property list");
    NSString *temporary=[path stringByAppendingFormat:@".%@.tmp",NSUUID.UUID.UUIDString];
    int fd=open(temporary.fileSystemRepresentation,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
    require(fd>=0,@"Cannot create transaction file");
    const char *bytes=data.bytes;size_t left=data.length;BOOL ok=YES;
    while(left) {ssize_t n=write(fd,bytes,left);if(n<0 && errno==EINTR) continue;if(n<=0){ok=NO;break;}bytes+=n;left-=(size_t)n;}
    if(fsync(fd)!=0) ok=NO;
    close(fd);
    if(ok) ok=rename(temporary.fileSystemRepresentation,path.fileSystemRepresentation)==0;
    if(!ok) unlink(temporary.fileSystemRepresentation);
    require(ok,@"Cannot persist transaction file");
    syncDirectory(path.stringByDeletingLastPathComponent);
    // macOS fsync alone does not flush the device's write cache. Flush after
    // the rename and directory sync, before callers are allowed to change DNS.
    fd=open(path.fileSystemRepresentation,O_RDWR|O_NOFOLLOW);
    require(fd>=0,@"Cannot reopen durable state file");
    int flushed=fcntl(fd,F_FULLFSYNC);close(fd);
    require(flushed==0,@"Cannot fully sync transaction state to storage");
}
static NSDictionary *load(NSString *path) {
    if(!exists(path)) return nil;
    protectedPath(path,NO);
    NSDictionary *value=[NSDictionary dictionaryWithContentsOfURL:[NSURL fileURLWithPath:path] error:NULL];
    require([value isKindOfClass:NSDictionary.class],@"Invalid state file; retain it for recovery");
    return value;
}
static int execute(NSString *program,NSArray<NSString*> *args,BOOL checked) {
    NSTask *task=[NSTask new];task.executableURL=[NSURL fileURLWithPath:program];task.arguments=args;
    task.environment=@{@"PATH":@"/usr/bin:/bin:/usr/sbin:/sbin",@"LC_ALL":@"C"};
    NSError *error=nil;require([task launchAndReturnError:&error],error.localizedDescription?:@"Cannot launch system tool");
    [task waitUntilExit];
    if(checked) require(task.terminationStatus==0,[NSString stringWithFormat:@"%@ %@ failed (%d)",program,args,task.terminationStatus]);
    return task.terminationStatus;
}
static NSString *plist(NSString *label) {return [Daemons stringByAppendingPathComponent:[label stringByAppendingString:@".plist"]];}
static void launch(NSString *action,NSString *label,BOOL checked) {
    execute(@"/bin/launchctl",@[action,@"system",plist(label)],checked);
}

/* Lock the system preferences for each complete transaction. Concurrent edits
 * made outside this helper are detected before restore, never overwritten. */
@protocol DNSPreferences <NSObject>
- (NSDictionary*)read:(NSString*)identifier;
- (BOOL)supported:(NSString*)identifier;
- (void)write:(NSDictionary*)changes;
- (NSArray*)services;
@end
@interface NativePreferences : NSObject <DNSPreferences> {SCPreferencesRef prefs;}
@end
@implementation NativePreferences
- (instancetype)init {
    self=[super init];if(self) {
        prefs=SCPreferencesCreate(NULL,CFSTR("DNSProxy"),NULL);
        require(prefs && SCPreferencesLock(prefs,TRUE),@"Cannot lock macOS network preferences");
    }return self;
}
- (void)dealloc {if(prefs){SCPreferencesUnlock(prefs);CFRelease(prefs);}}
- (SCNetworkServiceRef)service:(NSString*)identifier {
    SCNetworkServiceRef service=SCNetworkServiceCopy(prefs,(__bridge CFStringRef)identifier);
    require(service!=NULL,[@"Network service unavailable: " stringByAppendingString:identifier]);return service;
}
- (BOOL)supported:(NSString*)identifier {
    SCNetworkServiceRef service=[self service:identifier];
    SCNetworkInterfaceRef interface=SCNetworkServiceGetInterface(service);
    CFStringRef type=interface?SCNetworkInterfaceGetInterfaceType(interface):NULL;
    BOOL ok=SCNetworkServiceGetEnabled(service) && type &&
        (CFEqual(type,kSCNetworkInterfaceTypeEthernet)||CFEqual(type,kSCNetworkInterfaceTypeIEEE80211));
    SCNetworkProtocolRef protocol=SCNetworkServiceCopyProtocol(service,kSCNetworkProtocolTypeDNS);
    ok=ok && protocol && SCNetworkProtocolGetEnabled(protocol);
    if(protocol)CFRelease(protocol);
    CFRelease(service);return ok;
}
- (NSDictionary*)read:(NSString*)identifier {
    SCNetworkServiceRef service=[self service:identifier];
    SCNetworkProtocolRef protocol=SCNetworkServiceCopyProtocol(service,kSCNetworkProtocolTypeDNS);
    CFRelease(service);require(protocol!=NULL,@"Network service has no DNS protocol");
    CFDictionaryRef config=SCNetworkProtocolGetConfiguration(protocol);
    if(!config && SCError()!=kSCStatusNoKey && SCError()!=kSCStatusOK) {
        CFRelease(protocol);require(NO,@"Cannot read configured DNS settings");
    }
    NSDictionary *snapshot=@{@"Present":@(config!=NULL),@"Configuration":config?[(__bridge NSDictionary*)config copy]:@{}};
    CFRelease(protocol);return snapshot;
}
- (void)write:(NSDictionary*)changes {
    for(NSString *identifier in changes) {
        SCNetworkServiceRef service=[self service:identifier];
        SCNetworkProtocolRef protocol=SCNetworkServiceCopyProtocol(service,kSCNetworkProtocolTypeDNS);CFRelease(service);
        require(protocol!=NULL,@"Network service has no DNS protocol");
        NSDictionary *snapshot=changes[identifier];
        BOOL ok=SCNetworkProtocolSetConfiguration(protocol,[snapshot[@"Present"] boolValue]?(__bridge CFDictionaryRef)snapshot[@"Configuration"]:NULL);
        CFRelease(protocol);require(ok,@"Cannot set DNS configuration");
    }
    require(SCPreferencesCommitChanges(prefs),@"Cannot commit DNS configuration");
    require(SCPreferencesApplyChanges(prefs),@"Cannot apply DNS configuration");
}
- (NSArray*)services {
    NSArray *all=CFBridgingRelease(SCNetworkServiceCopyAll(prefs));NSMutableArray *result=[NSMutableArray new];
    for(id item in all) {
        SCNetworkServiceRef service=(__bridge SCNetworkServiceRef)item;
        NSString *identifier=(__bridge NSString*)SCNetworkServiceGetServiceID(service);
        [result addObject:@{@"ID":identifier,@"Name":(__bridge NSString*)SCNetworkServiceGetName(service)?:@"",@"Supported":@([self supported:identifier])}];
    }return result;
}
@end

/* Snapshot full DNS dictionaries (including search domains/options). The only
 * changed key is ServerAddresses. Restoring absent configuration re-enables
 * DHCP/automatic DNS; it never converts DHCP's current addresses to static. */
static NSDictionary *plan(id<DNSPreferences> prefs,NSArray *identifiers) {
    require(identifiers.count>0,@"Select at least one network-service UUID");
    NSMutableDictionary *entries=[NSMutableDictionary new];
    for(NSString *identifier in identifiers) {
        require(!entries[identifier] && [[NSUUID alloc] initWithUUIDString:identifier]!=nil,@"Duplicate or invalid service UUID");
        require([prefs supported:identifier],@"Only enabled Ethernet/Wi-Fi services are supported; VPN/managed DNS must be configured separately");
        NSDictionary *before=[prefs read:identifier];NSMutableDictionary *config=[before[@"Configuration"] mutableCopy];
        require(!config[@"SupplementalMatchDomains"] && !config[@"SupplementalMatchOrders"],@"Scoped/split DNS configuration is not supported");
        NSArray *servers=config[@"ServerAddresses"];
        require(![servers containsObject:@"127.0.0.1"] && ![servers containsObject:@"::1"],@"DNS already points at loopback; establish the original settings first");
        config[@"ServerAddresses"]=@[@"127.0.0.1",@"::1"];
        entries[identifier]=@{@"Before":before,@"After":@{@"Present":@YES,@"Configuration":config}};
    }
    return @{@"Version":@1,@"Phase":@"Pending",@"Deadline":[NSDate dateWithTimeIntervalSinceNow:120],@"Entries":entries};
}
static void validateState(NSDictionary *state) {
    require([state[@"Version"] isEqual:@1] && [state[@"Entries"] isKindOfClass:NSDictionary.class] && [state[@"Entries"] count]>0 &&
        [@[@"Pending",@"Active",@"Restoring"] containsObject:state[@"Phase"]] && [state[@"Deadline"] isKindOfClass:NSDate.class],@"Invalid DNS transaction; retain state for manual recovery");
    for(NSString *identifier in state[@"Entries"]) {
        NSDictionary *entry=state[@"Entries"][identifier];
        require([[NSUUID alloc] initWithUUIDString:identifier]!=nil,@"Invalid saved network-service UUID");
        for(NSString *key in @[@"Before",@"After"])
            require([entry[key] isKindOfClass:NSDictionary.class] && [entry[key][@"Present"] isKindOfClass:NSNumber.class] &&
                    [entry[key][@"Configuration"] isKindOfClass:NSDictionary.class],@"Invalid DNS snapshot");
    }
}
static void restore(id<DNSPreferences> prefs,NSDictionary *state,NSString *path) {
    validateState(state);NSMutableDictionary *pending=[state mutableCopy];pending[@"Phase"]=@"Restoring";save(pending,path);
    NSMutableDictionary *changes=[NSMutableDictionary new];
    for(NSString *identifier in state[@"Entries"]) {
        NSDictionary *entry=state[@"Entries"][identifier],*current=[prefs read:identifier];
        if([current isEqual:entry[@"Before"]]) continue;
        require([current isEqual:entry[@"After"]],[@"DNS was changed externally; resolve conflict and retry restore: " stringByAppendingString:identifier]);
        changes[identifier]=entry[@"Before"];
    }
    // Apply even if already restored: a previous commit may have succeeded but
    // ApplyChanges failed. Do not discard the recovery record until apply works.
    [prefs write:changes];
    require(unlink(path.fileSystemRepresentation)==0,@"Cannot remove restored state");syncDirectory(path.stringByDeletingLastPathComponent);
}
static BOOL recoveryDue(NSDictionary *state,NSDate *now) {
    validateState(state);
    return [state[@"Phase"] isEqual:@"Restoring"] ||
        ([state[@"Phase"] isEqual:@"Pending"] && [state[@"Deadline"] compare:now]!=NSOrderedDescending);
}
static void enable(id<DNSPreferences> prefs,NSArray *identifiers,NSString *path,BOOL (^health)(void),void (^arm)(void)) {
    require(!exists(path),@"A DNS snapshot already exists; restore it before enabling again");
    require(health(),@"Both loopback families must answer UDP/TCP DNS before changing settings");
    NSDictionary *state=plan(prefs,identifiers);
    arm(); // Recovery must be installed and loaded before persisting intent or writing DNS.
    save(state,path);
    @try {
        NSMutableDictionary *changes=[NSMutableDictionary new];
        for(NSString *identifier in state[@"Entries"]) changes[identifier]=state[@"Entries"][identifier][@"After"];
        [prefs write:changes];
        require(health(),@"DNS health check failed after configuration; restoring original settings");
        NSMutableDictionary *active=[state mutableCopy];active[@"Phase"]=@"Active";save(active,path);
    } @catch(NSException *error) {
        @try {restore(prefs,state,path);} @catch(NSException *rollback) {fprintf(stderr,"Rollback pending: %s\n",rollback.reason.UTF8String);}
        @throw error;
    }
}

static BOOL dnsProbe(int family,int type,BOOL upstream) {
    unsigned char query[]={0x73,0x29,1,0,0,1,0,0,0,0,0,0,7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
    if(!upstream) query[12]=255; // Local FORMERR tests the resolver without Internet at boot.
    int fd=socket(family,type,0);if(fd<0)return NO;
    struct timeval timeout={2,0};int one=1;
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));
    struct sockaddr_in v4={.sin_len=sizeof(v4),.sin_family=AF_INET,.sin_port=htons(53),.sin_addr={htonl(INADDR_LOOPBACK)}};
    struct sockaddr_in6 v6={.sin6_len=sizeof(v6),.sin6_family=AF_INET6,.sin6_port=htons(53),.sin6_addr=IN6ADDR_LOOPBACK_INIT};
    BOOL ok=connect(fd,family==AF_INET?(struct sockaddr*)&v4:(struct sockaddr*)&v6,family==AF_INET?sizeof(v4):sizeof(v6))==0;
    unsigned char answer[4096];ssize_t length=-1;
    if(ok && type==SOCK_STREAM) {
        unsigned char framed[sizeof(query)+2]={0,sizeof(query)};memcpy(framed+2,query,sizeof(query));
        ok=send(fd,framed,sizeof(framed),0)==sizeof(framed);
        unsigned char prefix[2];
        if(ok) ok=recv(fd,prefix,2,MSG_WAITALL)==2;
        size_t wanted=ok?((size_t)prefix[0]<<8)|prefix[1]:0;
        if(ok && wanted<=sizeof(answer)) length=recv(fd,answer,wanted,MSG_WAITALL);
        if(length!=(ssize_t)wanted) ok=NO;
    } else if(ok) {
        ok=send(fd,query,sizeof(query),0)==sizeof(query);
        if(ok) length=recv(fd,answer,sizeof(answer),0);
    }
    close(fd);
    if(!ok || length<12 || memcmp(answer,query,2) || !(answer[2]&0x80) || (answer[2]&2)) return NO;
    if(!upstream) return (answer[3]&15)==1;
    return length>=(ssize_t)sizeof(query) && (answer[3]&15)==0 && answer[4]==0 && answer[5]==1 &&
        !memcmp(answer+12,query+12,sizeof(query)-12);
}
static BOOL healthy(BOOL upstream) {
    for(int family=0;family<2;family++) for(int transport=0;transport<2;transport++)
        if(!dnsProbe(family?AF_INET6:AF_INET,transport?SOCK_STREAM:SOCK_DGRAM,upstream))return NO;
    return YES;
}
static NSDictionary *recoveryJob(void) {
    return @{@"Label":Recovery,@"ProgramArguments":@[inside(@"dnsp-macos"),@"recover"],
        @"RunAtLoad":@YES,@"StartInterval":@60,@"ProcessType":@"Background"};
}
static NSDictionary *serviceJob(NSString *upstream,NSString *bootstrap,BOOL customCA) {
    NSMutableArray *args=[@[inside(@"dnsp-modern"),@"-l",@"127.0.0.1",@"-l",@"::1",@"-p",@"53",
        @"-s",upstream,@"--bootstrap-address",bootstrap,@"--cache-entries",@"256"] mutableCopy];
    if(customCA) [args addObjectsFromArray:@[@"--ca-file",inside(@"ca-bundle.crt")]];
    NSMutableDictionary *sockets=[NSMutableDictionary new];
    for(NSString *family in @[@"4",@"6"]) for(NSString *type in @[@"UDP",@"TCP"]) {
        BOOL ipv6=[family isEqual:@"6"];
        sockets[[type stringByAppendingString:family]]=@{@"SockFamily":ipv6?@"IPv6":@"IPv4",
            @"SockType":[type isEqual:@"UDP"]?@"dgram":@"stream",@"SockNodeName":ipv6?@"::1":@"127.0.0.1",
            @"SockServiceName":@"53",@"SockPassive":@YES};
    }
    return @{@"Label":Label,@"ProgramArguments":args,@"UserName":@"nobody",@"GroupName":@"nobody",
        @"EnvironmentVariables":@{@"DNSP_LAUNCHD":@"1"},@"Sockets":sockets,@"RunAtLoad":@YES,
        @"KeepAlive":@{@"SuccessfulExit":@NO},@"ThrottleInterval":@10,@"ExitTimeOut":@10,
        @"StandardOutPath":@"/dev/null",@"StandardErrorPath":Log,@"WorkingDirectory":Root,
        @"ProcessType":@"Background",@"Umask":@077};
}
static gid_t logGroup(void) {
    struct group *group=getgrnam("nobody");
    require(group!=NULL,@"Cannot find the service log group");
    return group->gr_gid;
}
static void checkLog(void) {
    struct stat st;
    require(lstat(Log.fileSystemRepresentation,&st)==0 && S_ISREG(st.st_mode) &&
        st.st_nlink==1 && st.st_uid==0 && st.st_gid==logGroup() && (st.st_mode&0777)==0660,
        @"Service log ownership or permissions changed; expected root:nobody mode 0660");
}
static void checkInstalled(void) {
    checkLog();
    protectedPath(Root,YES);protectedPath(inside(@"dnsp-modern"),NO);protectedPath(inside(@"dnsp-macos"),NO);
    NSDictionary *record=load(inside(@"installation.plist"));
    require([record[@"Version"] isEqual:@1] && [record[@"Service"] isEqual:load(plist(Label))] &&
        [recoveryJob() isEqual:load(plist(Recovery))],@"Installation or launchd job differs from its ownership record; refusing changes");
}
static void armRecovery(void) {
    require([recoveryJob() isEqual:load(plist(Recovery))],@"Recovery job ownership mismatch");
    if(execute(@"/bin/launchctl",@[@"print",[@"system/" stringByAppendingString:Recovery]],NO)!=0)
        launch(@"bootstrap",Recovery,YES);
}
static void rotateLog(void) {
    checkLog();
    int fd=open(Log.fileSystemRepresentation,O_RDWR|O_NOFOLLOW);if(fd<0)return;
    struct stat st;
    if(fstat(fd,&st)==0 && st.st_size>4*1024*1024) {
        // Copy/truncate retains launchd's open log descriptor. Keep only the
        // most recent 4 MiB; concurrent lines may be lost at the rotation edge.
        NSString *old=[Log stringByAppendingString:@".1"];
        int out=open(old.fileSystemRepresentation,O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW,0640);
        if(out>=0) {
            off_t pos=st.st_size-4*1024*1024;BOOL ok=YES;char buffer[16384];
            while(pos<st.st_size) {
                ssize_t n=pread(fd,buffer,sizeof(buffer),pos);
                if(n<=0){ok=NO;break;}
                ssize_t written=write(out,buffer,(size_t)n);if(written!=n){ok=NO;break;}pos+=n;
            }
            if(fsync(out)!=0)ok=NO;
            if(ok) (void)ftruncate(fd,0);
            close(out);
        }
    }
    close(fd);
}
static void copyExecutable(NSString *source,NSString *destination) {
    int input=open(source.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW);
    struct stat st;
    require(input>=0,@"Cannot open bundle executable");
    if(fstat(input,&st)!=0 || !S_ISREG(st.st_mode) || st.st_size<=0 || st.st_size>128*1024*1024) {
        close(input);require(NO,@"Bundle executable must be a regular file (maximum 128 MiB)");
    }
    int output=open(destination.fileSystemRepresentation,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0700);
    if(output<0){close(input);require(NO,@"Cannot create installed executable");}
    // Copy bytes into a new root-owned file; do not inherit source ACLs/xattrs.
    BOOL ok=YES;char bytes[16384];ssize_t length;
    while((length=read(input,bytes,sizeof(bytes)))!=0) {
        if(length<0){if(errno==EINTR)continue;ok=NO;break;}
        ssize_t offset=0;
        while(offset<length) {
            ssize_t n=write(output,bytes+offset,(size_t)(length-offset));
            if(n<0 && errno==EINTR)continue;
            if(n<=0){ok=NO;break;}offset+=n;
        }
        if(!ok)break;
    }
    if(fchown(output,0,0)!=0 || fchmod(output,0755)!=0 || fsync(output)!=0)ok=NO;
    close(input);close(output);require(ok,@"Cannot copy/protect installed executable");
}
static void install(NSArray *arguments,NSString *source) {
    require(arguments.count==0 || arguments.count==2 || arguments.count==3,@"Usage: install [HTTPS_UPSTREAM NUMERIC_BOOTSTRAP [CA_FILE]]");
    NSString *upstream=arguments.count?arguments[0]:@"https://cloudflare-dns.com/dns-query";
    NSString *bootstrap=arguments.count?arguments[1]:@"1.1.1.1";
    NSURL *url=[NSURL URLWithString:upstream];unsigned char address[16];
    require([url.scheme isEqual:@"https"] && url.host.length && !url.user && !url.password && !url.fragment &&
        [upstream rangeOfCharacterFromSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].location==NSNotFound,@"Upstream must be an HTTPS URL without credentials, whitespace or fragment");
    require(inet_pton(AF_INET,bootstrap.UTF8String,address)==1 || inet_pton(AF_INET6,bootstrap.UTF8String,address)==1,@"Bootstrap must be a numeric IP address");
    require(!exists(Root) && !exists(plist(Label)) && !exists(plist(Recovery)) && !exists(Log) && !exists([Log stringByAppendingString:@".1"]),@"Existing installation/job/log found; restore DNS and uninstall first");
    require(execute(@"/bin/launchctl",@[@"print",[@"system/" stringByAppendingString:Label]],NO)!=0 &&
        execute(@"/bin/launchctl",@[@"print",[@"system/" stringByAppendingString:Recovery]],NO)!=0,@"A job with this label is already loaded");
    BOOL made=NO;
    @try {
        require(mkdir(Root.fileSystemRepresentation,0755)==0,@"Cannot create installation directory");made=YES;
        require(chmod(Root.fileSystemRepresentation,0755)==0,@"Cannot protect installation directory");
        for(NSString *name in @[@"dnsp-modern",@"dnsp-macos"]) {
            copyExecutable([source stringByAppendingPathComponent:name],inside(name));
        }
        if(arguments.count==3) {
            NSData *ca=[NSData dataWithContentsOfFile:arguments[2]];require(ca.length>0 && ca.length<4*1024*1024,@"Cannot read CA file (maximum 4 MiB)");
            require([ca writeToFile:inside(@"ca-bundle.crt") options:NSDataWritingAtomic error:NULL],@"Cannot copy CA file");
            require(chmod(inside(@"ca-bundle.crt").fileSystemRepresentation,0644)==0,@"Cannot protect CA file");
        }
        int fd=open(Log.fileSystemRepresentation,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
        require(fd>=0,@"Cannot create service log");
        // launchd opens StandardErrorPath read/write with the job's credentials.
        // Retain root ownership and grant both permissions to its service group.
        BOOL logOK=fchown(fd,0,logGroup())==0 && fchmod(fd,0660)==0;
        close(fd);require(logOK,@"Cannot grant the service access to its log");
        NSDictionary *service=serviceJob(upstream,bootstrap,arguments.count==3);
        save(service,plist(Label));save(recoveryJob(),plist(Recovery));
        save(@{@"Version":@1,@"Service":service},inside(@"installation.plist"));
        launch(@"bootstrap",Label,YES);
        BOOL ready=NO;for(int i=0;i<20;i++){if(healthy(NO)){ready=YES;break;}usleep(250000);}
        require(ready,@"Service failed to start on both loopback families; installation rolled back");
        launch(@"bootstrap",Recovery,YES);
    } @catch(NSException *error) {
        if(made) {
            // Preserve useful startup diagnostics before removing owned files.
            execute(@"/bin/launchctl",@[@"print",[@"system/" stringByAppendingString:Label]],NO);
            int diagnostic=open(Log.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW);
            if(diagnostic>=0) {
                char tail[16384];off_t end=lseek(diagnostic,0,SEEK_END);
                if(end>0) {
                    off_t start=end>(off_t)sizeof(tail)?end-(off_t)sizeof(tail):0;
                    ssize_t n=pread(diagnostic,tail,sizeof(tail),start);
                    if(n>0){fputs("DNSProxy startup log:\n",stderr);fwrite(tail,1,(size_t)n,stderr);}
                }
                close(diagnostic);
            }
            launch(@"bootout",Recovery,NO);launch(@"bootout",Label,NO);
            unlink(plist(Label).fileSystemRepresentation);unlink(plist(Recovery).fileSystemRepresentation);unlink(Log.fileSystemRepresentation);
            [NSFileManager.defaultManager removeItemAtPath:Root error:NULL];
        }
        @throw error;
    }
}
#ifndef DNSP_MACOS_TEST
int main(int argc,const char **argv) {
    @autoreleasepool {
        int lock=-1;
        @try {
            require(argc>=2,@"Usage: dnsp-macos install|status|services|start|stop|enable-dns UUID...|restore-dns|recover|uninstall");
            require(geteuid()==0,@"Run this helper with sudo (including status/services)");umask(077);
            protectedPath(@"/Library/Application Support",YES);protectedPath(Daemons,YES);
            NSString *lockPath=@"/Library/Application Support/.net.fantuz.dnsproxy.lock";
            lock=open(lockPath.fileSystemRepresentation,O_RDWR|O_CREAT|O_NOFOLLOW,0600);
            require(lock>=0,@"Cannot open lifecycle lock");protectedPath(lockPath,NO);
            NSString *action=@(argv[1]);
            if(flock(lock,LOCK_EX|LOCK_NB)!=0) {require([action isEqual:@"recover"],@"Another DNSProxy lifecycle command is running");close(lock);return 0;}
            NSMutableArray *arguments=[NSMutableArray new];for(int i=2;i<argc;i++)[arguments addObject:@(argv[i])];
            if([action isEqual:@"install"]) {
                NSString *source=NSBundle.mainBundle.executablePath.stringByDeletingLastPathComponent;
                install(arguments,source);
            } else if([action isEqual:@"services"]) {
                require(!arguments.count,@"services takes no arguments");
                for(NSDictionary *service in [[NativePreferences new] services])
                    printf("%s  %s  %s\n",[service[@"ID"] UTF8String],[service[@"Name"] UTF8String],[service[@"Supported"] boolValue]?"Ethernet/Wi-Fi":"unsupported");
            } else {
                if([action isEqual:@"recover"] && !exists(Root)){close(lock);return 0;}
                checkInstalled();NSString *path=inside(@"dns-state.plist");NSDictionary *state=load(path);
                if(state)validateState(state);
                require([action isEqual:@"enable-dns"] || !arguments.count,@"Unexpected command arguments");
                if([action isEqual:@"status"]) {
                    execute(@"/bin/launchctl",@[@"print",[@"system/" stringByAppendingString:Label]],NO);
                    printf("DNS transaction: %s\n",state?[state[@"Phase"] UTF8String]:"none (original DNS settings)");
                } else if([action isEqual:@"enable-dns"]) {
                    enable([NativePreferences new],arguments,path,^BOOL{return healthy(YES);},^{armRecovery();});
                    puts("DNS configured; original settings saved. Use restore-dns before stopping/uninstalling.");
                } else if([action isEqual:@"restore-dns"]) {
                    if(state)restore([NativePreferences new],state,path);puts("Original DNS configuration restored.");
                } else if([action isEqual:@"recover"]) {
                    if(state && recoveryDue(state,NSDate.date))
                        restore([NativePreferences new],state,path);
                    rotateLog();
                } else if([action isEqual:@"start"]) {
                    launch(@"bootstrap",Label,YES);
                } else if([action isEqual:@"stop"] || [action isEqual:@"uninstall"]) {
                    require(!state,@"Restore DNS first; a saved transaction still exists");
                    launch(@"bootout",Label,NO);
                    require(execute(@"/bin/launchctl",@[@"print",[@"system/" stringByAppendingString:Label]],NO)!=0,@"Service is still loaded");
                    if([action isEqual:@"uninstall"]) {
                        launch(@"bootout",Recovery,NO);
                        require(execute(@"/bin/launchctl",@[@"print",[@"system/" stringByAppendingString:Recovery]],NO)!=0,@"Recovery job is still loaded");
                        unlink(plist(Label).fileSystemRepresentation);unlink(plist(Recovery).fileSystemRepresentation);
                        unlink(Log.fileSystemRepresentation);unlink([Log stringByAppendingString:@".1"].fileSystemRepresentation);
                        require([NSFileManager.defaultManager removeItemAtPath:Root error:NULL],@"Cannot remove installation directory");
                    }
                } else require(NO,@"Unknown command");
            }
            if(lock>=0)close(lock);return 0;
        } @catch(NSException *error) {
            fprintf(stderr,"DNSProxy: %s\n",error.reason.UTF8String);if(lock>=0)close(lock);return 1;
        }
    }
}
#endif
