/* Test-only localhost diagnostics; this executable is never packaged. */
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <curl/curl.h>

static CURL *traced_easy_init(void) {
    CURL *easy=curl_easy_init();
    if(easy) curl_easy_setopt(easy,CURLOPT_VERBOSE,1L);
    return easy;
}
static void traced_easy_reset(CURL *easy) {
    curl_easy_reset(easy);
    curl_easy_setopt(easy,CURLOPT_VERBOSE,1L);
}
#define curl_easy_init traced_easy_init
#define curl_easy_reset traced_easy_reset
#include "../dnsp-modern.c"
