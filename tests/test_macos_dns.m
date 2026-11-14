/* Transaction tests use the production engine with an injected preferences
 * backend. Native CI never redirects the runner's live DNS configuration. */
#define DNSP_MACOS_TEST
#import "../packaging/macos/dnsp-macos.m"
static NSString *const A=@"11111111-1111-1111-1111-111111111111";
static NSString *const B=@"22222222-2222-2222-2222-222222222222";
@interface FakePreferences : NSObject <DNSPreferences>
@property NSMutableDictionary *values;
@property BOOL failBefore;
@property BOOL failAfter;
@property BOOL unsupported;
@property NSUInteger writes;
@end
@implementation FakePreferences
- (instancetype)init {self=[super init];if(self)self.values=[NSMutableDictionary new];return self;}
- (NSDictionary*)read:(NSString*)identifier {require(self.values[identifier]!=nil,@"Missing service");return self.values[identifier];}
- (BOOL)supported:(NSString*)identifier {(void)identifier;return !self.unsupported;}
- (NSArray*)services {return @[];}
- (void)write:(NSDictionary*)changes {
    self.writes++;
    if(self.failBefore){self.failBefore=NO;require(NO,@"Commit failed");}
    [self.values addEntriesFromDictionary:changes];
    if(self.failAfter){self.failAfter=NO;require(NO,@"Apply failed");}
}
@end
static void expectFailure(void (^body)(void)) {
    BOOL failed=NO;@try{body();}@catch(NSException *error){(void)error;failed=YES;}require(failed,@"Expected failure did not occur");
}
int main(void) {
    @autoreleasepool {
        @try {
            require(geteuid()==0,@"Run tests as root for protected-state checks");
            NSString *dir=[NSTemporaryDirectory() stringByAppendingPathComponent:NSUUID.UUID.UUIDString];
            require(mkdir(dir.fileSystemRepresentation,0700)==0,@"Cannot create test directory");
            NSString *path=[dir stringByAppendingPathComponent:@"dns-state.plist"];
            NSDictionary *automatic=@{@"Present":@NO,@"Configuration":@{}};
            NSDictionary *manual=@{@"Present":@YES,@"Configuration":@{@"ServerAddresses":@[@"192.0.2.1",@"2001:db8::1"],@"SearchDomains":@[@"lab.example"],@"Options":@"timeout:2"}};
            FakePreferences *prefs=[FakePreferences new];
            void (^reset)(void)=^{prefs.values=[@{A:automatic,B:manual} mutableCopy];prefs.failBefore=NO;prefs.failAfter=NO;prefs.unsupported=NO;prefs.writes=0;unlink(path.fileSystemRepresentation);};
            __block BOOL armed=NO;
            reset();enable(prefs,@[A,B],path,^BOOL{return YES;},^{armed=YES;});
            require(armed && [load(path)[@"Phase"] isEqual:@"Active"],@"Missing armed active state");
            require([prefs.values[B][@"Configuration"][@"SearchDomains"] isEqual:manual[@"Configuration"][@"SearchDomains"]],@"Search domains lost");
            expectFailure(^{enable(prefs,@[A],path,^BOOL{return YES;},^{});});
            restore(prefs,load(path),path);
            require(!exists(path) && [prefs.values[A] isEqual:automatic] && [prefs.values[B] isEqual:manual],@"Exact original configuration not restored");
            puts("PASS automatic/static/IPv6/search domains round trip and repeated-enable guard");

            reset();expectFailure(^{enable(prefs,@[A],path,^BOOL{return NO;},^{});});
            require(!prefs.writes && !exists(path),@"Failed health changed DNS");
            expectFailure(^{enable(prefs,@[A],path,^BOOL{return YES;},^{require(NO,@"Cannot arm recovery");});});
            require(!prefs.writes && !exists(path),@"Failed recovery registration changed DNS");
            __block int checks=0;
            expectFailure(^{enable(prefs,@[A,B],path,^BOOL{return ++checks==1;},^{});});
            require(!exists(path) && [prefs.values[A] isEqual:automatic] && [prefs.values[B] isEqual:manual],@"Failed postcheck not rolled back");
            puts("PASS preflight, recovery-registration and post-change health failures");

            for(int after=0;after<2;after++) {
                reset();prefs.failBefore=!after;prefs.failAfter=after;
                expectFailure(^{enable(prefs,@[A,B],path,^BOOL{return YES;},^{});});
                require(!exists(path) && [prefs.values[A] isEqual:automatic] && [prefs.values[B] isEqual:manual],@"Commit/apply failure not rolled back");
            }
            puts("PASS commit/apply failures");

            reset();NSDictionary *pending=plan(prefs,@[A,B]);save(pending,path);
            require(!recoveryDue(pending,NSDate.date),@"Pending transaction recovered before its deadline");
            require(recoveryDue(pending,[NSDate dateWithTimeIntervalSinceNow:180]),@"Expired pending transaction was not recoverable");
            NSMutableDictionary *phase=[pending mutableCopy];phase[@"Phase"]=@"Active";
            require(!recoveryDue(phase,[NSDate dateWithTimeIntervalSinceNow:180]),@"Committed DNS unexpectedly restored");
            phase[@"Phase"]=@"Restoring";require(recoveryDue(phase,NSDate.date),@"Interrupted restore was not retried immediately");
            // Simulate power loss between individual changes, before Active was saved.
            prefs.values[A]=pending[@"Entries"][A][@"After"];
            restore(prefs,load(path),path);
            require(!exists(path) && [prefs.values[A] isEqual:automatic] && [prefs.values[B] isEqual:manual],@"Interrupted setup recovery failed");
            puts("PASS durable pending recovery after partial configuration");

            reset();enable(prefs,@[A,B],path,^BOOL{return YES;},^{});
            NSDictionary *external=@{@"Present":@YES,@"Configuration":@{@"ServerAddresses":@[@"192.0.2.99"]}};
            prefs.values[B]=external;
            expectFailure(^{restore(prefs,load(path),path);});
            require(exists(path) && [prefs.values[B] isEqual:external] && [load(path)[@"Phase"] isEqual:@"Restoring"],@"Conflict was overwritten or snapshot lost");
            prefs.values[B]=manual;restore(prefs,load(path),path);
            require(!exists(path) && [prefs.values[A] isEqual:automatic],@"Retry after resolved conflict failed");
            puts("PASS administrator conflict preservation and retry");

            reset();enable(prefs,@[A,B],path,^BOOL{return YES;},^{});
            NSDictionary *detached=prefs.values[B];[prefs.values removeObjectForKey:B];
            expectFailure(^{restore(prefs,load(path),path);});require(exists(path),@"Unavailable service lost recovery record");
            prefs.values[B]=detached;restore(prefs,load(path),path);
            puts("PASS unavailable service retained until it returns");

            reset();prefs.unsupported=YES;expectFailure(^{enable(prefs,@[A],path,^BOOL{return YES;},^{});});
            require(!exists(path) && !prefs.writes,@"Unsupported service was modified");
            reset();expectFailure(^{enable(prefs,@[A,A],path,^BOOL{return YES;},^{});});
            require(!exists(path),@"Duplicate selection saved state");
            NSDictionary *bad=@{@"Version":@999};save(bad,path);expectFailure(^{restore(prefs,load(path),path);});
            require([load(path) isEqual:bad],@"Corrupt state was overwritten");
            puts("PASS unsupported service, duplicate UUID and state-schema guards");

            // Read-only use of the real SystemConfiguration backend on each native runner.
            NativePreferences *native=[NativePreferences new];NSArray *services=[native services];
            for(NSDictionary *service in services) if([service[@"Supported"] boolValue]) {
                NSDictionary *snapshot=[native read:service[@"ID"]];require(snapshot[@"Configuration"]!=nil,@"Native snapshot missing");
            }
            printf("PASS native preferences discovery/read (%lu services; no DNS writes)\n",(unsigned long)services.count);
            [NSFileManager.defaultManager removeItemAtPath:dir error:NULL];return 0;
        } @catch(NSException *error) {fprintf(stderr,"FAIL: %s\n",error.reason.UTF8String);return 1;}
    }
}
