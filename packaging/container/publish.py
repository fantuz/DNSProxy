#!/usr/bin/env python3
"""Promote the tested OCI index; keep release tags immutable and aliases monotonic."""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
import re
import subprocess

from oci_bundle import Archive, PREFIX


def version_tuple(version):
    if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', version):
        raise ValueError(f'Expected a stable MAJOR.MINOR.PATCH version, got {version!r}')
    return tuple(int(part) for part in version.split('.'))


def should_promote(existing, digest, version, *, immutable):
    if existing is None:
        return True
    raw, current = existing
    if current == digest:
        return False
    if immutable:
        raise ValueError('Refusing to replace an existing version tag with different image contents')
    previous = json.loads(raw).get('annotations', {}).get(PREFIX + 'version', '')
    if version_tuple(previous) == version_tuple(version):
        raise ValueError('The same release version already has different image contents')
    return version_tuple(previous) < version_tuple(version)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--repository', required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--digest', required=True)
    parser.add_argument('--authfile', required=True)
    parser.add_argument('--staging-tag', required=True)
    parser.add_argument('--local-registry', action='store_true', help='CI loopback registry only')
    args = parser.parse_args()
    version_tuple(args.version)
    if not re.fullmatch(r'[a-z0-9.:-]+/[a-z0-9/_.-]+', args.repository):
        raise ValueError('Invalid registry repository')
    if not re.fullmatch(r'build-[0-9]+-[0-9]+', args.staging_tag):
        raise ValueError('Invalid staging tag')
    if args.local_registry and not args.repository.startswith('127.0.0.1:'):
        raise ValueError('Insecure registry testing is restricted to loopback')
    with ExitStack() as stack:
        archive = Archive(args.archive, args.revision, args.version, stack)
        if set(archive.images) != {'amd64', 'arm64'} or archive.root['digest'] != args.digest:
            raise ValueError('The release archive differs from the tested multi-platform index')
    options = ['--authfile', args.authfile]
    if args.local_registry:
        options += ['--tls-verify=false']

    def inspect(tag):
        result = subprocess.run(['skopeo', 'inspect', '--raw', *options,
                                 f'docker://{args.repository}:{tag}'], capture_output=True, check=False)
        if result.returncode:
            error = result.stderr.decode(errors='replace')
            if any(marker in error.lower() for marker in ('manifest unknown', 'name unknown')):
                return None
            raise RuntimeError(error)
        return result.stdout, 'sha256:' + hashlib.sha256(result.stdout).hexdigest()

    def copy(source, tag):
        # copy has separate source/destination TLS switches, unlike inspect.
        copy_options = ['--authfile', args.authfile]
        if args.local_registry:
            copy_options += ['--dest-tls-verify=false', '--src-tls-verify=false']
        subprocess.run(['skopeo', 'copy', '--all', '--preserve-digests', *copy_options,
                        source, f'docker://{args.repository}:{tag}'], check=True)
        if inspect(tag)[1] != args.digest:
            raise RuntimeError('Published OCI index digest differs from the tested image')

    # This also creates/links a new GHCR package before inspecting release tags.
    copy('oci-archive:' + os.path.abspath(args.archive), args.staging_tag)
    version_tag = args.version
    tags = [(version_tag, True), ('.'.join(version_tag.split('.')[:2]), False),
            (version_tag.split('.')[0], False), ('latest', False)]
    for tag, immutable in tags:
        if should_promote(inspect(tag), args.digest, args.version, immutable=immutable):
            copy(f'docker://{args.repository}@{args.digest}', tag)
            print(f'Published {args.repository}:{tag}@{args.digest}')
        else:
            print(f'Kept {args.repository}:{tag}')


if __name__ == '__main__':
    main()
