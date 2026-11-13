/* CI-only SCM fixture: exercise the production adapter's reported-error path.
 * Never included in the downloadable bundle. */
#include <windows.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>
#include "../dnsp-service.h"
static atomic_bool stopped;
static void stop(int signal) {(void)signal;stopped=true;}
static int run(int argc,char **argv) {
    if(argc!=2 || !dnsp_service_active() || !dnsp_service_ready()) return 2;
    HANDLE marker=CreateFileA(argv[1],GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    bool fail=marker!=INVALID_HANDLE_VALUE;
    if(fail) CloseHandle(marker);
    for(unsigned i=0;!stopped;i++) {
        Sleep(100);
        (void)dnsp_service_tick();
        if(fail && i==15) return 42;
    }
    return 0;
}
int main(int argc,char **argv) {return dnsp_service_dispatch(argc,argv,run,stop);}
