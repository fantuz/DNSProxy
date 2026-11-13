#!/bin/sh
set -eu
cd "$(dirname "$0")"
exec ./dnsp-modern -l 127.0.0.1 -l ::1 -p 5053 --bootstrap-address 1.1.1.1 --cache-entries 256 -m 9090
