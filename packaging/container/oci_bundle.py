#!/usr/bin/env python3
"""Validate and combine tested OCI archives without rebuilding their image blobs."""
import argparse
from contextlib import ExitStack
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile

INDEX = 'application/vnd.oci.image.index.v1+json'
MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
CONFIG = 'application/vnd.oci.image.config.v1+json'
SOURCE = 'https://github.com/fantuz/DNSProxy'
PREFIX = 'org.opencontainers.image.'


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def descriptor(data, media_type, **extra):
    return dict(mediaType=media_type, size=len(data),
                digest='sha256:' + hashlib.sha256(data).hexdigest(), **extra)


def blob_path(digest):
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
        raise ValueError('Expected a SHA256 OCI digest')
    return 'blobs/sha256/' + digest[7:]


class Archive:
    def __init__(self, path, revision, version, stack):
        self.tar = stack.enter_context(tarfile.open(path, 'r:'))
        self.members = {}
        for member in self.tar:
            name = member.name.removeprefix('./')
            if name in self.members:
                raise ValueError(f'Duplicate archive member: {name}')
            self.members[name] = member
        self.blobs = {}
        layout = self.read_json('oci-layout')
        if layout != {'imageLayoutVersion': '1.0.0'}:
            raise ValueError('Unsupported OCI layout')
        root = self.read_json('index.json')
        if root.get('schemaVersion') != 2 or len(root.get('manifests', [])) != 1:
            raise ValueError('Expected exactly one named image in the OCI archive')
        self.root = root['manifests'][0]
        self.images = {}
        self.walk(self.root, revision, version)

    def member(self, name):
        member = self.members.get(name)
        if member is None or not member.isfile():
            raise ValueError(f'Missing regular OCI file: {name}')
        return member

    def read_json(self, name):
        member = self.member(name)
        if member.size > 2 * 1024 * 1024:
            raise ValueError('OCI JSON metadata is too large')
        with self.tar.extractfile(member) as source:
            return json.load(source)

    def verify_blob(self, desc):
        path = blob_path(desc['digest'])
        member = self.member(path)
        if member.size != desc['size']:
            raise ValueError(f'OCI blob size mismatch: {path}')
        if path not in self.blobs:
            digest = hashlib.sha256()
            with self.tar.extractfile(member) as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b''):
                    digest.update(chunk)
            if 'sha256:' + digest.hexdigest() != desc['digest']:
                raise ValueError(f'OCI blob digest mismatch: {path}')
            self.blobs[path] = member
        return path

    def walk(self, desc, revision, version, depth=0):
        path = self.verify_blob(desc)
        document = self.read_json(path)
        if document.get('schemaVersion') != 2:
            raise ValueError('Unsupported OCI manifest schema')
        media_type = desc['mediaType']
        if media_type == INDEX:
            if depth or not document.get('manifests'):
                raise ValueError('Unexpected nested or empty OCI index')
            for child in document['manifests']:
                self.walk(child, revision, version, depth + 1)
            return
        if media_type != MANIFEST or document.get('mediaType') != MANIFEST:
            raise ValueError('Expected an OCI image manifest')
        config_desc = document['config']
        if config_desc['mediaType'] != CONFIG:
            raise ValueError('Expected an OCI image configuration')
        config = self.read_json(self.verify_blob(config_desc))
        arch = config.get('architecture')
        if config.get('os') != 'linux' or arch not in ('amd64', 'arm64'):
            raise ValueError('Unsupported container platform')
        if arch in self.images:
            raise ValueError(f'Duplicate platform: {arch}')
        platform = desc.get('platform', {'os': 'linux', 'architecture': arch})
        if platform.get('os') != 'linux' or platform.get('architecture') != arch:
            raise ValueError('OCI descriptor and image platform disagree')
        labels = config.get('config', {}).get('Labels', {})
        expected = {'revision': revision, 'version': version, 'source': SOURCE}
        if any(labels.get(PREFIX + key) != value for key, value in expected.items()):
            raise ValueError('Image source, version or revision differs from the tested commit')
        for layer in document['layers']:
            self.verify_blob(layer)
        self.images[arch] = dict(desc, platform=platform)
        self.images[arch]['config_digest'] = config_desc['digest']

    def summary(self):
        return {'digest': self.root['digest'], 'platforms': self.images}


def add_bytes(target, name, data):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o644
    target.addfile(info, io.BytesIO(data))


def combine(paths, destination, revision, version):
    with ExitStack() as stack:
        sources = [Archive(path, revision, version, stack) for path in paths]
        images, blobs = {}, {}
        for source in sources:
            for arch, desc in source.images.items():
                if arch in images:
                    raise ValueError(f'Duplicate platform: {arch}')
                images[arch] = {key: value for key, value in desc.items() if key != 'config_digest'}
            for path in source.blobs:
                blobs[path] = source
        if set(images) != {'amd64', 'arm64'}:
            raise ValueError('Both linux/amd64 and linux/arm64 must pass before publication')
        index = encoded({'schemaVersion': 2, 'mediaType': INDEX,
                         'manifests': [images[arch] for arch in sorted(images)],
                         'annotations': {PREFIX + 'revision': revision, PREFIX + 'version': version,
                                         PREFIX + 'source': SOURCE}})
        root = descriptor(index, INDEX, annotations={PREFIX + 'ref.name': 'dnsproxy'})
        with tarfile.open(destination, 'w') as target:
            # Skopeo's rootless untar must not have to create implicit parents:
            # containers/storage otherwise tries to chown those parents to root.
            for name in ('blobs/', 'blobs/sha256/'):
                info = tarfile.TarInfo(name)
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                target.addfile(info)
            add_bytes(target, 'oci-layout', encoded({'imageLayoutVersion': '1.0.0'}))
            add_bytes(target, 'index.json', encoded({'schemaVersion': 2, 'manifests': [root]}))
            add_bytes(target, blob_path(root['digest']), index)
            for path, source in sorted(blobs.items()):
                member = source.member(path)
                info = tarfile.TarInfo(path)
                info.size, info.mode = member.size, 0o644
                with source.tar.extractfile(member) as stream:
                    target.addfile(info, stream)
        return root['digest']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--version', required=True)
    commands = parser.add_subparsers(dest='command', required=True)
    verify = commands.add_parser('verify')
    verify.add_argument('archive', type=Path)
    verify.add_argument('--architectures', default='amd64,arm64')
    merge = commands.add_parser('combine')
    merge.add_argument('--output', type=Path, required=True)
    merge.add_argument('archives', nargs='+', type=Path)
    args = parser.parse_args()
    if args.command == 'combine':
        print(combine(args.archives, args.output, args.revision, args.version))
    else:
        with ExitStack() as stack:
            archive = Archive(args.archive, args.revision, args.version, stack)
            if set(archive.images) != set(args.architectures.split(',')):
                raise ValueError('Archive does not contain exactly the requested platforms')
            print(json.dumps(archive.summary(), sort_keys=True))


if __name__ == '__main__':
    main()
