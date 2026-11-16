"""Artifact integrity checks for the images promoted from CI to the registry."""
from contextlib import ExitStack
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

BASE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('oci_bundle', BASE/'packaging/container/oci_bundle.py')
oci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oci)
REVISION = 'a' * 40
VERSION = '4.7.0'


def fixture(path, arch, *, revision=REVISION, version=VERSION, corrupt=False, symlink=False):
    # The layer bytes are opaque to the bundler, just as compressed real layers are.
    layer = b'shared layer data'
    config = oci.encoded({'os': 'linux', 'architecture': arch, 'config': {'Labels': {
        oci.PREFIX + 'revision': revision, oci.PREFIX + 'version': version,
        oci.PREFIX + 'source': oci.SOURCE}}})
    manifest = oci.encoded({'schemaVersion': 2, 'mediaType': oci.MANIFEST,
                           'config': oci.descriptor(config, oci.CONFIG),
                           'layers': [oci.descriptor(layer, 'application/vnd.oci.image.layer.v1.tar+gzip')]})
    desc = oci.descriptor(manifest, oci.MANIFEST, platform={'os': 'linux', 'architecture': arch})
    with tarfile.open(path, 'w') as target:
        oci.add_bytes(target, 'oci-layout', oci.encoded({'imageLayoutVersion': '1.0.0'}))
        oci.add_bytes(target, 'index.json', oci.encoded({'schemaVersion': 2, 'manifests': [desc]}))
        for data in (config, manifest, layer):
            name = oci.blob_path(oci.descriptor(data, '')['digest'])
            if data == layer and symlink:
                info = tarfile.TarInfo(name)
                info.type, info.linkname = tarfile.SYMTYPE, '/etc/passwd'
                target.addfile(info)
            else:
                oci.add_bytes(target, name, b'bad layer contents' if data == layer and corrupt else data)
    return desc['digest'], oci.descriptor(config, '')['digest']


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_both_tested_images_are_preserved_and_common_layers_deduplicated(self):
        native = []
        expected = {}
        for arch in ('amd64', 'arm64'):
            path = self.root/f'{arch}.tar'
            expected[arch] = fixture(path, arch)
            native.append(path)
        result = self.root/'multi.tar'
        digest = oci.combine(native, result, REVISION, VERSION)
        with ExitStack() as stack:
            archive = oci.Archive(result, REVISION, VERSION, stack)
            self.assertEqual(archive.root['digest'], digest)
            for arch, (manifest, config) in expected.items():
                self.assertEqual(archive.images[arch]['digest'], manifest)
                self.assertEqual(archive.images[arch]['config_digest'], config)
            self.assertEqual(len(archive.blobs), 6)  # two manifests/configs, one layer and one index
        again = self.root/'again.tar'
        self.assertEqual(oci.combine(native[::-1], again, REVISION, VERSION), digest)
        self.assertEqual(result.read_bytes(), again.read_bytes())

    def test_changed_blobs_wrong_source_and_symlinks_cannot_be_promoted(self):
        for options in ({'corrupt': True}, {'symlink': True}, {'revision': 'b' * 40},
                        {'version': '4.6.0'}):
            with self.subTest(options=options), ExitStack() as stack:
                path = self.root/'bad.tar'
                fixture(path, 'amd64', **options)
                with self.assertRaises(ValueError):
                    oci.Archive(path, REVISION, VERSION, stack)

    def test_missing_or_duplicate_platform_cannot_be_released(self):
        path = self.root/'amd64.tar'
        fixture(path, 'amd64')
        for paths in ([path], [path, path]):
            with self.subTest(paths=paths), self.assertRaises(ValueError):
                oci.combine(paths, self.root/'bad.tar', REVISION, VERSION)

    def test_duplicate_metadata_is_rejected(self):
        path = self.root/'duplicate.tar'
        fixture(path, 'amd64')
        with tarfile.open(path, 'a') as target:
            oci.add_bytes(target, 'index.json', b'{}')
        with ExitStack() as stack, self.assertRaises(ValueError):
            oci.Archive(path, REVISION, VERSION, stack)

    def test_descriptor_platform_must_match_the_configuration(self):
        path = self.root/'wrong-platform.tar'
        fixture(path, 'amd64')
        with tarfile.open(path) as source:
            members = [(member.name, source.extractfile(member).read()) for member in source]
        with tarfile.open(path, 'w') as target:
            for name, data in members:
                if name == 'index.json':
                    document = json.loads(data)
                    document['manifests'][0]['platform']['architecture'] = 'arm64'
                    data = oci.encoded(document)
                info = tarfile.TarInfo(name)
                info.size = len(data)
                target.addfile(info, io.BytesIO(data))
        with ExitStack() as stack, self.assertRaises(ValueError):
            oci.Archive(path, REVISION, VERSION, stack)


if __name__ == '__main__':
    unittest.main(verbosity=2)
