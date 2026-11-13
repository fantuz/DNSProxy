#ifndef DNSP_SERVICE_H
#define DNSP_SERVICE_H
/* Windows lifecycle adapter. Resolver sockets/libcurl stay on the ServiceMain
 * thread; the SCM callback only requests stop and reports status. */
#ifdef _WIN32
#include <stdio.h>
#include <stdlib.h>
#include <io.h>

static bool dnsp_as_service;
static SERVICE_STATUS_HANDLE dnsp_service_handle;
static SERVICE_STATUS dnsp_service_status;
static SRWLOCK dnsp_service_lock=SRWLOCK_INIT;
static wchar_t *dnsp_service_name,*dnsp_service_log;
static char **dnsp_service_argv;
static int dnsp_service_argc,dnsp_service_result=1;
static int (*dnsp_service_run)(int,char**);
static void (*dnsp_service_stop)(int);

static wchar_t *dnsp_utf16(const char *text) {
    int count=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,text,-1,NULL,0);
    wchar_t *out=count?calloc((size_t)count,sizeof(*out)):NULL;
    if(out && !MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,text,-1,out,count)) {free(out);out=NULL;}
    return out;
}
static bool dnsp_service_active(void) {return dnsp_as_service;}
static bool dnsp_service_status_locked(DWORD state,DWORD error) {
    dnsp_service_status.dwServiceType=SERVICE_WIN32_OWN_PROCESS;
    dnsp_service_status.dwCurrentState=state;
    dnsp_service_status.dwControlsAccepted=state==SERVICE_RUNNING?SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN:0;
    dnsp_service_status.dwWin32ExitCode=error?ERROR_SERVICE_SPECIFIC_ERROR:NO_ERROR;
    dnsp_service_status.dwServiceSpecificExitCode=error;
    dnsp_service_status.dwWaitHint=(state==SERVICE_START_PENDING || state==SERVICE_STOP_PENDING)?10000:0;
    dnsp_service_status.dwCheckPoint=dnsp_service_status.dwWaitHint?1:0;
    return SetServiceStatus(dnsp_service_handle,&dnsp_service_status)!=0;
}
static DWORD WINAPI dnsp_service_control(DWORD control,DWORD type,void *data,void *context) {
    (void)type;(void)data;(void)context;
    AcquireSRWLockExclusive(&dnsp_service_lock);
    DWORD result=NO_ERROR;
    if(control==SERVICE_CONTROL_STOP || control==SERVICE_CONTROL_SHUTDOWN) {
        dnsp_service_stop(0);
        if(dnsp_service_status.dwCurrentState==SERVICE_RUNNING)
            (void)dnsp_service_status_locked(SERVICE_STOP_PENDING,0);
    } else if(control==SERVICE_CONTROL_INTERROGATE) {
        if(dnsp_service_status.dwCurrentState!=SERVICE_STOPPED)
            (void)SetServiceStatus(dnsp_service_handle,&dnsp_service_status);
    } else result=ERROR_CALL_NOT_IMPLEMENTED;
    ReleaseSRWLockExclusive(&dnsp_service_lock);
    return result;
}
static bool dnsp_service_ready(void) {
    if(!dnsp_as_service) return true;
    AcquireSRWLockExclusive(&dnsp_service_lock);
    bool ok=dnsp_service_status_locked(SERVICE_RUNNING,0);
    ReleaseSRWLockExclusive(&dnsp_service_lock);
    return ok;
}
/* stderr is owned by the resolver thread. Keep one 4 MiB previous log and
 * rotate at most once per second. Never write logs into the executable folder. */
static bool dnsp_service_tick(void) {
    if(!dnsp_as_service) return true;
    static ULONGLONG next;
    ULONGLONG now=GetTickCount64();
    if(now<next) return true;
    next=now+1000;
    if(_ftelli64(stderr)<4*1024*1024) return true;
    size_t size=wcslen(dnsp_service_log)+3;
    wchar_t *old=calloc(size,sizeof(*old));
    if(!old) return false;
    swprintf(old,size,L"%ls.1",dnsp_service_log);
    bool ok=_wfreopen(L"NUL",L"a",stderr)!=NULL;
    if(ok) ok=MoveFileExW(dnsp_service_log,old,MOVEFILE_REPLACE_EXISTING)!=0;
    if(!_wfreopen(dnsp_service_log,L"ab",stderr)) ok=false;
    else setvbuf(stderr,NULL,_IONBF,0);
    free(old);
    return ok;
}
static void WINAPI dnsp_service_main(DWORD argc,wchar_t **argv) {
    (void)argc;(void)argv;
    dnsp_service_handle=RegisterServiceCtrlHandlerExW(dnsp_service_name,dnsp_service_control,NULL);
    if(!dnsp_service_handle) return;
    AcquireSRWLockExclusive(&dnsp_service_lock);
    bool ok=dnsp_service_status_locked(SERVICE_START_PENDING,0);
    ReleaseSRWLockExclusive(&dnsp_service_lock);
    if(ok && _wfreopen(dnsp_service_log,L"ab",stderr)) {
        setvbuf(stderr,NULL,_IONBF,0);
        dnsp_service_result=dnsp_service_tick()?dnsp_service_run(dnsp_service_argc,dnsp_service_argv):1;
    }
    AcquireSRWLockExclusive(&dnsp_service_lock);
    (void)dnsp_service_status_locked(SERVICE_STOPPED,(DWORD)dnsp_service_result);
    ReleaseSRWLockExclusive(&dnsp_service_lock);
}
static int dnsp_service_dispatch(int argc,char **argv,int (*run)(int,char**),void (*stop)(int)) {
    if(argc<5 || strcmp(argv[3],"--service-log") || !argv[2][0] || strlen(argv[2])>128 ||
       strspn(argv[2],"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")!=strlen(argv[2])) {
        fprintf(stderr,"Usage: %s --service NAME --service-log ABSOLUTE_PATH [resolver options]\n",argv[0]);
        return 2;
    }
    dnsp_service_name=dnsp_utf16(argv[2]);dnsp_service_log=dnsp_utf16(argv[4]);
    dnsp_service_argv=calloc((size_t)argc,sizeof(*dnsp_service_argv));
    if(!dnsp_service_name || !dnsp_service_log || !dnsp_service_argv ||
       !(wcslen(dnsp_service_log)>3 && dnsp_service_log[1]==L':' &&
         (dnsp_service_log[2]==L'\\' || dnsp_service_log[2]==L'/'))) {
        free(dnsp_service_name);free(dnsp_service_log);free(dnsp_service_argv);return 2;
    }
    dnsp_service_argv[0]=argv[0];
    for(int i=5;i<argc;i++) dnsp_service_argv[i-4]=argv[i];
    dnsp_service_argc=argc-4;dnsp_service_run=run;dnsp_service_stop=stop;dnsp_as_service=true;
    SERVICE_TABLE_ENTRYW table[]={{dnsp_service_name,dnsp_service_main},{NULL,NULL}};
    if(!StartServiceCtrlDispatcherW(table)) {
        fprintf(stderr,"Service dispatcher failed (Windows error %lu); use the foreground command outside SCM.\n",GetLastError());
        dnsp_service_result=1;
    }
    free(dnsp_service_argv);free(dnsp_service_name);free(dnsp_service_log);
    return dnsp_service_result;
}
#else
static bool dnsp_service_active(void) {return false;}
static bool dnsp_service_ready(void) {return true;}
static bool dnsp_service_tick(void) {return true;}
#endif
#endif
