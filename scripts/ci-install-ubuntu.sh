#!/bin/sh
# Hosted runners also configure vendor feeds. DNSProxy's native build dependencies
# all come from the runner's Ubuntu archives, including updates and security.
set -eu
sources=/etc/apt/sources.list.d/ubuntu.sources
if [ ! -s "$sources" ]; then sources=/etc/apt/sources.list; fi
if [ ! -s "$sources" ]; then
    echo "Ubuntu package sources are missing from this runner" >&2
    exit 1
fi

ubuntu_apt() {
    apt-get -o "Dir::Etc::sourcelist=$sources" -o Dir::Etc::sourceparts=- "$@"
}
ubuntu_apt update
ubuntu_apt install -y "$@"
