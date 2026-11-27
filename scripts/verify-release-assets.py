#!/usr/bin/env python3
"""Match a published GitHub release and its SHA256SUMS against the tested package set."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


def manifest_entries(data):
    entries = {}
    for line in data.decode('ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64}) [ *]([A-Za-z0-9][A-Za-z0-9.+_-]*)', line)
        if not match:
            raise ValueError('Invalid SHA256SUMS entry')
        digest, name = match.groups()
        if name == 'SHA256SUMS' or name in entries:
            raise ValueError(f'Unexpected or duplicate manifest entry: {name}')
        entries[name] = digest
    if not entries:
        raise ValueError('Empty SHA256SUMS')
    return entries


def verify(release, tag, published, tested, newly_published):
    if release['tag_name'] != tag or release['draft'] or release['prerelease']:
        raise ValueError(f'Expected the stable published release {tag}')
    manifest = manifest_entries(published)
    build = manifest_entries(tested)
    if manifest.keys() != build.keys():
        raise ValueError('Published package names differ from the expected build set')
    if newly_published and manifest != build:
        raise ValueError('Published packages differ from the tested build')
    expected = {**manifest, 'SHA256SUMS': hashlib.sha256(published).hexdigest()}
    seen = set()
    for asset in release['assets']:
        name = asset['name']
        if name not in expected or name in seen:
            raise ValueError(f'Unexpected or duplicate release asset: {name}')
        if asset['state'] != 'uploaded' or asset['size'] <= 0:
            raise ValueError(f'Incomplete release asset: {name}')
        if asset.get('digest') != 'sha256:' + expected[name]:
            raise ValueError(f'GitHub SHA-256 differs from the release manifest: {name}')
        seen.add(name)
    if missing := expected.keys() - seen:
        raise ValueError(f'Missing release assets: {", ".join(sorted(missing))}')
    return len(manifest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tag')
    parser.add_argument('release_json', type=Path)
    parser.add_argument('published_manifest', type=Path)
    parser.add_argument('tested_manifest', type=Path)
    parser.add_argument('--newly-published', action='store_true')
    args = parser.parse_args()
    try:
        count = verify(json.loads(args.release_json.read_bytes()), args.tag,
                       args.published_manifest.read_bytes(), args.tested_manifest.read_bytes(),
                       args.newly_published)
    except (ValueError, KeyError, OSError) as error:
        sys.exit(str(error))
    print(f'Verified {count} packages and SHA256SUMS for {args.tag} against GitHub asset digests.')


if __name__ == '__main__':
    main()
