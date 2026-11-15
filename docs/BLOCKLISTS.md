# Optional DNS domain filtering

Filtering is disabled until at least one `--blocklist FILE` is supplied. The same
C implementation runs on Linux, Windows and macOS. No web administration server,
database, external DNS provider or third-party list is required by the filter.

```sh
./dnsp-modern --blocklist domains.txt --allowlist exceptions.txt -m 9153
./dnsp-modern --blocklist domains.txt --allowlist exceptions.txt --check-blocklists
dig @127.0.0.1 -p 5300 ads.example A
dig @127.0.0.1 -p 5300 ads.example HTTPS +tcp
curl -fsS http://127.0.0.1:9153/metrics | grep -E '^dnsp_block(list|ed)_'
```

`--check-blocklists` validates the complete selected set and prints rule counts
and allocated bytes. It opens no DNS/metrics listeners and makes no upstream
request. Invalid/missing inputs exit with status 2, as does a normal startup
with invalid policy. `--allowlist` alone is an error.

## File syntax and precedence

Repeat `--blocklist` and `--allowlist` for multiple files. Both accept:

```text
# Exact name, including an optional final dot; matching ignores ASCII case.
ads.example
Ads.Other.Example.

# This name AND its descendants.
.tracking.example

# Descendants only; children.example itself remains eligible for forwarding.
*.children.example

# Hosts-file syntax; the address is ignored, and aliases are separate rules.
0.0.0.0 advertising.example telemetry.example
:: ipv6-advertising.example
```

`#` starts a comment. Blank lines, CRLF and an initial UTF-8 BOM are accepted.
Names may contain ASCII letters, digits, hyphens and underscores; supply IDNs as
ASCII A-labels (`xn--...`). Labels are limited to 63 octets and names to the DNS
wire limit of 255 octets. Unicode names, regular expressions, escaped labels,
URLs, Adblock syntax (`||name^`) and extra fields on domain-only lines are
rejected. A hosts line must contain a numeric IPv4/IPv6 address and one or more
names. This parser does not implement hosts-file address overrides.

Allow rules override deny rules **for the same name**. An exact exception does
not allow descendants automatically. Each reachable alias/endpoint is checked
independently: allowing the original question does not allow a blocked target.
Use an appropriate exception for the target too. Duplicate rules are combined.
Suffixes match complete labels: `.ads.example` cannot match `notads.example`.

DNS labels are parsed as length-delimited wire data. An embedded dot or NUL in
a label cannot turn a binary DNS name into a different dotted list entry.

## Replies and protocol behaviour

Policy applies to supported ordinary `IN` queries, independent of QTYPE,
including A, AAAA, MX, TXT, DNSSEC, HTTPS/SVCB, ANY and unknown/private types.
IPv4/IPv6 UDP and TCP use the same policy. Other QCLASS values retain their
normal forwarding behaviour; malformed/unsupported requests retain the
existing FORMERR/NOTIMP/drop behaviour.

The default is `--block-response refused`: RCODE REFUSED, with an EDNS Extended
DNS Error INFO-CODE **15 (Blocked)** when the request supplied EDNS(0). This
reports local operator policy as defined by [RFC 8914](https://www.rfc-editor.org/rfc/rfc8914.html#section-4.16).
EDE is not added to a non-EDNS request. Unsupported EDNS versions on a denied
query receive BADVERS and the supported version 0, per
[RFC 6891](https://www.rfc-editor.org/rfc/rfc6891.html#section-6.1.3).

Optional compatibility modes are explicit:

| Mode | Local response |
| --- | --- |
| `refused` | REFUSED for every denied supported IN query; default |
| `nxdomain` | NXDOMAIN with an empty answer |
| `nodata` | NOERROR with an empty answer |
| `null` | A = `0.0.0.0`, AAAA = `::`, TTL 0; NODATA for other types |

All modes include EDE for EDNS(0). Local replies preserve the question, ID, RD
and CD, advertise recursion availability, clear AD/AA/TC and omit upstream
records. No SOA, RRSIG or authenticated denial is invented. Local denials are
not inserted into the answer cache. Empty negative replies contain no SOA
negative-cache TTL. NXDOMAIN can affect descendant lookups at downstream
resolvers ([RFC 8020](https://www.rfc-editor.org/rfc/rfc8020.html)); choose the
default REFUSED when that implication is unwanted.

DO/CD do not bypass policy. A blocked TSIG/SIG(0) exchange receives an unsigned
local policy reply: DNSProxy has no signing key. A client demanding an
authenticated response can reject it. Unblocked signed messages retain the
existing transparent forwarding behaviour. DNSSEC validation remains upstream;
local policy denials are not cryptographically authenticated by a domain owner.
Clients independently validating DNSSEC must account for local filtering policy.

## Aliases, caching and requests already underway

Query names are checked before cache lookup, coalescing or new upstream work.
Validated upstream replies are checked again against the **currently published**
policy before caching, truncation or forwarding. This includes outstanding TCP
queries and every waiter on a coalesced UDP query. A newly denied question is
not retried against a backup after an upstream failure.

The response check follows reachable CNAME edges, DNAME suffix substitutions
and HTTPS/SVCB targets (AliasMode and ServiceMode, including address hints).
It inspects answer records reachable from the original question; unrelated
answer, authority and additional records do not cause a denial. DNAME does not
redirect its owner. HTTPS/SVCB TargetName must be uncompressed, per
[RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html#section-2.2).

The graph is limited to 128 alias records and 129 reachable names. Invalid
target encodings, oversized DNAME substitutions, allocation failure or an
exceeded graph budget produce SERVFAIL, never a partially inspected answer.
Cycles are visited once. Unknown RR types remain opaque; this is not a general
inspection engine for MX/SRV targets, RPZ rules, IP-address feeds or DNS rebinding.

A successful reload clears the shared answer cache. Replies completing later
are inspected before repopulating it, so an old positive or alias answer cannot
bypass a new rule. Replies already sent or queued for transmission cannot be
recalled; client caches retain their own previously received data.

## Reloading and bounded resource use

File checks run in a worker every 5 seconds. Set `--blocklist-reload-ms MS` to
100..86400000, or 0 to disable automatic checks. The worker checks file identity,
size and high-resolution modification/change times; unchanged files are not
parsed again. All file I/O, parsing and sorting are outside the packet loop.
The event loop publishes one complete immutable snapshot and retires the old
one after the loader has finished using it. Queries hold no ruleset pointers.

On Linux/macOS, `kill -HUP PID` requests a forced background reload. The packaged
Linux unit also supports `systemctl reload dnsp-modern`. Reloading a process
without filtering enabled is harmless. For an installed Windows service:

```powershell
(Get-Service DNSProxy).ExecuteCommand(6) # SERVICE_CONTROL_PARAMCHANGE
```

These commands acknowledge a request, not successful publication. Confirm the
generation/success counter or `event=blocklist_reload` log afterward. Missing,
unreadable, malformed, changing, oversized or unallocatable inputs retain the
**entire previous** ruleset and increment the failure counter. No temporary
empty policy is published. A deliberately empty local file is valid; the
download helper rejects empty/comment-only feeds to catch broken updates.

Limits apply to the complete set: 64 regular files, 64 MiB of input, 1,000,000
input entries before deduplication, 4,096 bytes per line and 64 MiB of domain
string storage. The index adds bounded rule arrays. Reloading temporarily holds
the old and candidate snapshots, and allocators may retain freed pages. No
list file is read for individual queries, and no regular expression is run.

Prometheus exposes blocked query/alias counters, deny/allow entry counts, active
generation, allocated policy bytes, reload successes/failures and seconds since
the last successful load. Age is local load age, not the provider's publication
date. SIGUSR1 reports include policy totals. Domain/client names are not labels
or default query logs.

## Downloading updates separately

Linux packages install `dnsp-update-blocklist`; macOS/Windows archives include
`update-blocklist.py`. The helper requires Python 3; the resolver and native
service do not acquire a Python dependency on desktop platforms. Select feeds
you trust and check their licensing; no third-party list is bundled or enabled.

```sh
sudo dnsp-update-blocklist https://provider.example/domains.txt /etc/dnsp-modern/domains.txt \
  --binary /usr/bin/dnsp-modern
# Optional independently obtained digest: --sha256 HEX_DIGEST
```

The destination directory must already exist. Downloads use verified HTTPS,
reject insecure redirects/credentials/HTML/compression, have socket and elapsed
read time limits and a 64 MiB ceiling. The candidate is validated using the
actual resolver executable before a same-directory atomic replacement. The
helper rejects symlink outputs, preserves existing POSIX owner/mode, flushes
the file and POSIX directory, and retains the previous file on download or
validation failure. Validation covers the downloaded file; the daemon then
validates the complete configured set before publication. Schedule this helper
with your existing timer/task scheduler; it never runs inside the DNS loop.

## Packaged services

Linux: create administrator-owned, service-readable files under
`/etc/dnsp-modern/` (directory 0755, files 0644). `ProtectHome=yes` prevents using
a home-directory path. Use a systemd override, preserving your existing listener
and upstream settings, for example:

```ini
[Service]
ExecStart=
ExecStart=/usr/bin/dnsp-modern -l 127.0.0.1 -p 5300 -m 9153 --blocklist /etc/dnsp-modern/domains.txt --allowlist /etc/dnsp-modern/allow.txt
```

Run `systemctl daemon-reload` and restart once to change startup options.
Later file updates reload without a restart. Do not make policy files writable
by the resolver's service account.

Windows: the installer accepts `-BlocklistFile FILE...`, `-AllowlistFile FILE...`
and `-BlockResponse refused|nxdomain|nodata|null`. It copies and validates files
inside the protected installation's `policy` directory. LocalService can read
them; administrators update those installed copies. Example:

```powershell
.\Install-DNSProxyService.ps1 -BlocklistFile 'C:\Lists\domains.txt' -AllowlistFile 'C:\Lists\allow.txt'
```

macOS: append policy options to the existing native helper installation:

```sh
sudo ./dnsp-macos install --blocklist /path/domains.txt --allowlist /path/allow.txt
```

The helper copies/validates files as root-owned, service-readable `policy-N.txt`
files inside `/Library/Application Support/DNSProxy`; the unprivileged resolver
reads those installed copies. Preserve root ownership/mode when updating them.
Changing source files outside that installation does not update the copies.
The existing DNS integration health probe resolves `example.com`; keep that
name eligible when enabling managed adapter DNS.

## Validation and performance

`make modern check` includes filtering/updater regressions. Native macOS and
Windows CI run these against extracted bundles, with real launchd/SCM service
copy/reload acceptance. Sanitizers exercise snapshot retirement and failure
paths. The parser fuzzer includes list syntax, wire matching and alias graphs.

GitHub's HTTP/2 job builds the PR's base binary on the same runner and records
interleaved base/disabled/100k/1M scenarios, blocked traffic and reloads during
load in the `dnsp-modern-benchmark-smoke` artifact (`bench-ci-policy.json`).
Results include QPS, p95/p99, CPU, active policy bytes and Linux peak RSS.
Three samples per steady scenario use broad relative gates: at least 65% of
base throughput and at most 2.5 times base p99. They catch large regressions;
they are not precise capacity estimates for other machines. Functional errors,
timeouts, upstream leakage for blocked queries and unexpected memory growth
also fail the benchmark. Ordinary upstream HTTP/2/3/netem tests remain enabled.

Domain filtering cannot distinguish advertisements from wanted content served
under the same hostname. Clients using another DNS service or their own DoH can
bypass local policy; this feature does not intercept those connections.
