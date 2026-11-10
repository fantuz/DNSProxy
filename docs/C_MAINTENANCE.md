# Maintaining DNSProxy's C code

## Decide what belongs in Git

| Kind of file | Criterion | Where it belongs |
| --- | --- | --- |
| Source, headers, build rules, packaging and CI | Required to build, test, or ship a supported target from a fresh checkout | Git |
| Test fixtures | Small, intentional inputs with a named test and known expected behavior | Git, alongside the tests |
| Build outputs | Regenerable binaries, objects, packages, bytecode and benchmark results | Local build directories, CI artifacts, or versioned releases |
| Historical material | Has reference value or a consumer outside the supported build | Documented archive with provenance and links from the historical notes |

Use `git ls-files -ci --exclude-standard` to find files already tracked despite
ignore rules. Check build inputs, scripts and docs before proposing a removal.
The `encode.o` and `decode.o` files are historical artifacts of the retired
`dnsp-h2` build. The supported `dnsp-modern` build is defined in `modern.mk`.
Treat a binary with no known source as a historical artifact until its provenance
is established.
[Git ignore documentation](https://git-scm.com/docs/gitignore)

## Review the C changes

- **Wire input.** Check lengths before reading or copying. Validate offsets,
  record boundaries, and DNS compression pointers against the available bytes.
  Use the correct signedness for socket return values and buffer sizes. Test
  boundaries at the smallest and largest accepted messages.
- **Ownership.** Make it clear who closes each socket and who frees each buffer
  or libcurl handle. Trace normal completion, setup failure, timeout, client
  disconnect, and shutdown. Review cleanup after partially completed setup.
- **Event loop.** Account for short reads and writes, `EINTR`, `EAGAIN`, and
  stale events after an fd is reused. Keep retries, queues and timeouts bounded.
  Test multiple queries on the same TCP connection as well as disconnects.
- **Dependencies and trust.** Keep dependency discovery in the build. Preserve
  certificate and hostname checks for upstream DoH. Review changes to listener
  binding, logging, and metrics for their effects on exposure and privacy.
- **Regression tests.** Use the loopback fixtures for reproducible success and
  failure cases. Use public resolvers for manual interoperability checks.
  Compare behavior at the UDP, TCP and DoH boundaries affected by the change.

## Checks before opening a PR

Run these from the repository root with the build and test dependencies listed
in the README. `-B` rebuilds when changing compilers or flags.

```sh
git diff --check
make -B -f modern.mk modern-check CFLAGS='-O2 -g -Werror'
```

Use a second compiler where available. For changes to memory ownership, buffer
handling or the event loop, also exercise the integration suite with sanitizers.

```sh
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
  make -B -f modern.mk modern-check \
  CFLAGS='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer'
```

AddressSanitizer catches memory errors on executed paths. UndefinedBehaviorSanitizer
checks selected forms of undefined behavior. The protocol fixtures and CodeQL
scan cover complementary cases.
[AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html) ·
[UndefinedBehaviorSanitizer](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)

Review CI for the target architectures. Package changes should pass the DEB and
RPM jobs, including the install and removal checks. Keep source removals,
build changes, and behavior changes in separate PRs when they can be verified
independently.
