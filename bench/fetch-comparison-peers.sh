#!/bin/sh
# Install the two pinned Linux x86-64 benchmark peers in a new directory.
set -eu
if [ "$#" -ne 1 ] || [ "$(uname -sm)" != "Linux x86_64" ]; then
    echo "Usage on Linux x86-64: $0 NEW_DIRECTORY" >&2
    exit 2
fi
dest=$1
mkdir -p "$(dirname "$dest")"
tmp=$(mktemp -d "$(dirname "$dest")/.doh-peers.XXXXXXXX")
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin"

fetch() {
    url=$1 digest=$2 member=$3 binary=$4
    curl -fsSL --retry 3 --proto '=https' --proto-redir '=https' "$url" -o "$tmp/archive"
    printf '%s  %s\n' "$digest" "$tmp/archive" | sha256sum -c - >/dev/null
    tar -xzOf "$tmp/archive" "$member" > "$tmp/bin/$binary"
    chmod 755 "$tmp/bin/$binary"
}

fetch 'https://github.com/AdguardTeam/dnsproxy/releases/download/v0.86.0/dnsproxy-linux-amd64-v0.86.0.tar.gz' \
    17ac43f76ebfcedf547c663f6f31aa70e68b8eb6fc41d2fc37d3bfe21a2ced66 \
    ./linux-amd64/dnsproxy dnsproxy
fetch 'https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/2.1.21/dnscrypt-proxy-linux_x86_64-2.1.21.tar.gz' \
    22561e748066de5a4a6fc383d7a6bb0826c895b50afe34077a5784eee5e238c0 \
    linux-x86_64/dnscrypt-proxy dnscrypt-proxy

mkdir "$dest"
mv "$tmp/bin/dnsproxy" "$tmp/bin/dnscrypt-proxy" "$dest/"
