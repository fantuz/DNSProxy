# Contributing to DNSProxy

DNSProxy forwards local DNS requests to a DoH upstream. Work on the supported
C resolver starts from `master`. Open a branch and pull request for changes.
For packaging or desktop changes, identify the operating systems and
architectures you tested.

- **Bug reports.** Include the version, installation method, steps to reproduce,
  expected result and observed result. Redact private domains, credentials,
  addresses and client logs. [Open a bug report](https://github.com/fantuz/DNSProxy/issues/new/choose)
- **Design questions and proposals.** Describe the use case and any relevant
  constraints. [Start a discussion](https://github.com/fantuz/DNSProxy/discussions)
- **Security reports.** Send suspected vulnerabilities through the private
  advisory form. [Security policy](SECURITY.md)

## Testing changes

Build the resolver and run the local checks from the repository root.

```sh
make -f modern.mk modern-check
git diff --check
```

For changes to C code, the maintenance guide lists warning and sanitizer builds.
For performance claims, include the workload, revision, raw measurements and
enough information to repeat the run. [C maintenance](docs/C_MAINTENANCE.md) ·
[Benchmark instructions](bench/README.md)

Describe the user-visible change and the checks you ran in the pull request.
GitHub runs `DNSProxy PR checks` against the proposed merge. The project’s
conduct guidelines apply in issues, pull requests and discussions.
[Code of conduct](CODE_OF_CONDUCT.md)
