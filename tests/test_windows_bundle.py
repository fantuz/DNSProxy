"""PE architecture checks run locally; extracted native ZIP checks run on Windows CI."""
import hashlib
import os
from pathlib import Path
import re
import runpy
import struct
import subprocess
import tempfile
import unittest

BASE = Path(__file__).resolve().parents[1]
BUNDLE = runpy.run_path(str(BASE / 'scripts/bundle-windows.py'))
check_machine = BUNDLE['check_machine']


def pe_image(machine, magic=0x20b):
    dos = bytearray(64)
    dos[:2] = b'MZ'
    struct.pack_into('<I', dos, 60, 64)
    pe = bytearray(26)
    pe[:4] = b'PE\0\0'
    struct.pack_into('<H', pe, 4, machine)
    struct.pack_into('<H', pe, 24, magic)
    return bytes(dos + pe)


class PEMachineTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.binary = Path(directory.name) / 'binary.dll'

    def test_native_64_bit_images_and_wrong_architecture(self):
        for arch, machine in BUNDLE['MACHINES'].items():
            self.binary.write_bytes(pe_image(machine))
            check_machine(self.binary, arch)
            with self.assertRaisesRegex(ValueError, 'expected'):
                check_machine(self.binary, 'arm64' if arch == 'amd64' else 'amd64')

    def test_bad_headers_and_32_bit_images_are_rejected(self):
        bad_offset = bytearray(pe_image(0xaa64))
        struct.pack_into('<I', bad_offset, 60, 0xffffffff)
        bad_signature = bytearray(pe_image(0xaa64))
        bad_signature[64:68] = b'NOPE'
        for content in (b'', b'MZ', pe_image(0xaa64)[:70], bad_offset, bad_signature,
                        pe_image(0x14c, 0x10b), pe_image(0xaa64, 0x10b)):
            with self.subTest(length=len(content)):
                self.binary.write_bytes(content)
                with self.assertRaises(ValueError):
                    check_machine(self.binary, 'arm64')


@unittest.skipUnless(os.name == 'nt' and os.environ.get('DNSP_TEST_WINDOWS_ARCH'),
                     'Requires an extracted Windows CI bundle and its target architecture')
class NativeBundleTests(unittest.TestCase):
    def test_resolver_dependencies_and_probes_are_native(self):
        arch = os.environ['DNSP_TEST_WINDOWS_ARCH']
        binary = Path(os.environ['DNSP_TEST_BINARY'])
        directory = binary.parent
        for name in ('dnsp-modern.exe', 'platform-probe.exe', 'service-fixture.exe'):
            check_machine(directory / name, arch)
        libraries = list(directory.glob('*.dll'))
        self.assertTrue(libraries, 'The portable libcurl dependency closure must be bundled')
        for library in libraries:
            check_machine(library, arch)
        target = 'ARM64 / CLANGARM64' if arch == 'arm64' else 'x86-64 / UCRT64'
        self.assertIn('Target: native Windows ' + target, (directory / 'BUILD-INFO.txt').read_text())

    def test_loaded_libcurl_matches_the_recorded_msys2_package(self):
        binary = Path(os.environ['DNSP_TEST_BINARY'])
        prefix = {'amd64': 'mingw-w64-ucrt-x86_64', 'arm64': 'mingw-w64-clang-aarch64'}[
            os.environ['DNSP_TEST_WINDOWS_ARCH']]
        info = (binary.parent / 'BUILD-INFO.txt').read_text(encoding='utf-8')
        match = re.search(rf'^{prefix}-curl (?:[0-9]+:)?([0-9.]+)-[0-9.]+$', info, re.MULTILINE)
        self.assertIsNotNone(match, f'Missing {prefix}-curl package revision in BUILD-INFO.txt')
        self.assertTrue((binary.parent / 'libcurl-4.dll').is_file())
        output = subprocess.check_output([str(binary), '--version'], text=True, timeout=10)
        fields = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
        for key in ('libcurl_build', 'libcurl_runtime'):
            self.assertEqual(fields[key], match[1], key)

    def test_extracted_files_match_the_bundled_checksums(self):
        directory = Path(os.environ['DNSP_TEST_BINARY']).parent
        manifest = (directory / 'SHA256SUMS').read_text().splitlines()
        self.assertTrue(manifest)
        for line in manifest:
            digest, name = line.split('  ', 1)
            path = directory / name
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest, name)


if __name__ == '__main__':
    unittest.main(verbosity=2)
