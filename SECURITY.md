# Security policy

## Supported versions

The supported implementation is `dnsp-modern`. Security fixes land on `master`
and ship in subsequent releases. If you found an issue on an older release,
include that version and whether it also affects the latest release if you can
check safely. The archived DNSProxy implementations are historical references.

## Reporting a vulnerability

Use [GitHub's private vulnerability reporting](https://github.com/fantuz/DNSProxy/security/advisories/new)
for suspected vulnerabilities. Use the [issue tracker](https://github.com/fantuz/DNSProxy/issues)
for general bugs and feature requests.

In a private report, include what you can reproduce.

- The output of `dnsp-modern --version`, the OS and architecture, and how you
  installed the binary.
- The relevant listener and upstream settings, including the transports used.
- Minimal steps or test data that reproduce the issue and the impact you observed.

Redact credentials and private client or network data from logs and test cases.

## Coordinated disclosure

Maintainers use the private advisory thread to confirm impact, coordinate a fix
or mitigation, and agree on disclosure timing. Please keep vulnerability details
private during that process. A published advisory identifies affected and fixed
versions and describes available mitigations.
