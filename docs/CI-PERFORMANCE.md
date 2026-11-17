# CI dependency reuse and timing

Windows CI rebuilds and tests the native AMD64/ARM64 product on each applicable
commit. The reusable inputs are the compiler environment, the x64 Python test
driver and Python package downloads. Product executables, DLL bundles and test
results are never restored as build inputs.

## Windows environment caches

The ARM64 hosted image lacks the requested x64 CPython tool-cache entry. The
workflow pins the fixture interpreter to 3.13.17 and restores only that x64
installation and its completion marker before `setup-python`. A cache miss
uses the normal installer. A version/platform check precedes saving the bare
runtime, before protocol packages are installed. Both products and platform
probes retain their native architecture; x64 is only the fixture driver.

The prepared MSYS2 cache contains the compiler, curl and packaging tools, plus
the pacman installed-package database. It uses exact keys separated by runner
image, MSYSTEM, workflow configuration and a seven-day UTC epoch bucket. There
is no fallback to an older epoch. A miss performs the usual full update and
installation; a hit validates the installed package set and executes the
compiler, pkg-config and Python before building. An invalid snapshot is removed
and the normal installation is used. Hits never run a partial pacman upgrade.

MSYS2's own package-download cache remains enabled for cold setup. After a
successful native build, the prepared installation is saved independently of
the source tree. On subsequent hits the MSYS shell is invoked directly at the
same temporary installation path, with the same MSYSTEM, minimal PATH and
working-directory behavior as the setup action.

Update `DNSP_PYTHON_VERSION` to adopt another CPython patch. Change the `v1`
cache schema to invalidate prepared snapshots immediately, or delete the
specific cache in GitHub Actions. Runner image changes also invalidate them.
The seven-day toolchain refresh balances setup cost with dependency updates;
urgent MSYS2 updates should invalidate the schema rather than wait for it.

## Parallel Windows tests

`scripts/run-windows-tests.py` runs three independent groups with two workers:

| Group | Suites | Listener range |
| --- | --- | --- |
| core | Core resolver and IPv6 | 10000–15999 |
| policy | Hedging, blocklists and updater | 18000–23999 |
| protocol | HTTP/2 benchmarks and isolated HTTP/3 | 26000–31999 |

The core, IPv6 and benchmark port allocators respect the group range. Upstream
fixtures otherwise use OS-assigned ephemeral ports. Each group has its own
Python processes, temporary fixture state and log. Suites inside a group remain
sequential. All suites finish even if another suite fails, and any nonzero exit
fails the workflow. A five-minute per-suite limit terminates its process tree.

Port-53 launchers, DNS configuration/rollback and SCM acceptance remain serial
after the groups. Their recovery delays and assertions are unchanged. The
workflow still extracts the actual ZIP and removes MSYS2 from the test PATH.

The `dnsp-windows-test-logs-*` artifacts contain group output and `timings.json`;
the job summary lists elapsed times and failures. `--workers 1` gives a serial
comparison with the same suites and range isolation.

## Linux fixtures

HTTP/2 and HTTP/3 jobs read the versioned `ci/requirements-*.txt` files. Pip's
download cache is keyed by OS, runner architecture and requirements; virtual
environments are recreated on each job. Windows uses a separate Python x64 key.

The HTTP/3 benchmark image now uses BuildKit's GitHub Actions cache. Only the
Debian/compiler/Python dependency layers are reused; the `tests` stage always
copies and compiles current sources. `pull: true` checks the Debian base, and a
seven-day build argument refreshes package-install layers. Runtime/release OCI
image freshness and publication rules are unchanged.

## Measuring the change

The 4.8.0 master run, `44000148438`, provides this baseline:

| Stage | Windows AMD64 | Windows ARM64 |
| --- | ---: | ---: |
| Python setup | under 1 s | 109 s |
| MSYS2 setup | 81 s | 194 s |
| Native build and bundle | 8 s | 6 s |
| Portable tests | 238 s | 282 s |
| Entire job | 355 s | 629 s |

Compare a first run with the prepared caches absent, then rerun the same commit
with warm caches. Record cache hits, restoration/saving overhead, group timings
and the entire job duration. PR caches are scoped to that PR, so the first
master run after merging may need its own cache fill. A cache hit alone does
not establish a speedup. Publication still uses the exact tested artifacts.

Obsolete validation runs for the same PR are cancelled when a newer commit
arrives. Push, tag and manual publication runs have independent concurrency
groups and retain the existing per-tag publication lock.
