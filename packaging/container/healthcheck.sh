#!/bin/sh
set -eu
port=${DNSP_HEALTH_PORT:-9153}
case "$port" in
    ''|*[!0-9]*) echo 'DNSP_HEALTH_PORT must be a numeric loopback port' >&2; exit 2 ;;
esac
if [ "${#port}" -gt 5 ] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    echo 'DNSP_HEALTH_PORT must be in 1..65535' >&2
    exit 2
fi
exec curl --fail --silent --show-error --max-time 2 --noproxy '*' "http://127.0.0.1:$port/metrics"
