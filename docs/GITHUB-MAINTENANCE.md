# Maintaining DNSProxy on GitHub

## Current repository

The `master` ruleset requires `DNSProxy PR checks` on an up-to-date branch and
blocks deletion and non-fast-forward updates. The aggregate check covers the
jobs selected for the change. CodeQL scans the C code. Potential
vulnerabilities can be reported privately. These settings were checked on
2026-11-27. [Active branch rules](https://github.com/fantuz/DNSProxy/rules) ·
[CI definitions](../.github/workflows) · [Security policy](../SECURITY.md)

The default workflow token has read access to repository contents in the main
build. Publishing jobs request write access for their release or package
operations. External Actions references use full commit SHAs. Dependabot
checks those pins and the Python protocol fixture requirements weekly.
Review upstream release notes when accepting an update.
[Dependency update configuration](../.github/dependabot.yml) ·
[GitHub Actions security guidance](https://docs.github.com/en/actions/reference/security/secure-use)

DNSProxy is a public fork. GitHub excludes forks from its community-profile
metrics. Review the contributor guide, conduct policy, reporting forms, PR
template and branch rules directly when assessing this project.
[Contributing](../CONTRIBUTING.md) ·
[GitHub community metrics](https://docs.github.com/en/rest/metrics/community)

## Controls as the project grows

| Scale | What to check | Where the maintainer acts |
| --- | --- | --- |
| Individual maintainer | Verify account 2FA and recovery access. Check that secret scanning, push protection and Dependabot alerts are enabled for this repository. These settings require an authenticated settings review. | Account **Password and authentication**, repository **Settings → Security** |
| Several maintainers | Assign named owners for the resolver, packaging and release workflows. Once a second reviewer is available, add a PR review rule and require code-owner approval on sensitive paths. Test the release workflow against the ruleset. | [CODEOWNERS and review rules](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners) |
| Wider binary and container distribution | The v4.11.1 release ships SHA-256 checksums. The release API reports it as mutable. The OCI build disables provenance and SBOM output. Add verifiable attestations for release files and the published image digest, then test immutable publication, retry and verification before enabling it for the next release. | [Release](https://github.com/fantuz/DNSProxy/releases/tag/v4.11.1-modern) · [OCI build](../.github/workflows/dnsp-modern-container.yml) · [Artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations) · [Immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases) |

The repository already has platform CI, release checksums and a security
contact. A future score or coverage badge should link to the report for the
revision it describes.
