"""Release retries must preserve immutable versions and never downgrade aliases."""
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'packaging/container'))
from oci_bundle import PREFIX  # noqa: E402
from publish import should_promote, version_tuple  # noqa: E402


def existing(version):
    data = json.dumps({'annotations': {PREFIX + 'version': version}}).encode()
    return data, 'sha256:' + hashlib.sha256(data).hexdigest()


class PublicationTests(unittest.TestCase):
    def test_retry_is_idempotent_and_release_tag_cannot_change(self):
        old = existing('4.7.0')
        self.assertFalse(should_promote(old, old[1], '4.7.0', immutable=True))
        with self.assertRaises(ValueError):
            should_promote(old, 'sha256:' + 'a' * 64, '4.7.0', immutable=True)
        self.assertTrue(should_promote(None, old[1], '4.7.0', immutable=True))

    def test_old_release_retry_does_not_downgrade_latest_or_minor_alias(self):
        desired = existing('4.7.9')[1]
        self.assertFalse(should_promote(existing('4.8.0'), desired, '4.7.9', immutable=False))
        self.assertFalse(should_promote(existing('4.7.10'), desired, '4.7.9', immutable=False))
        self.assertTrue(should_promote(existing('4.7.8'), desired, '4.7.9', immutable=False))

    def test_unknown_metadata_and_same_version_different_contents_fail_closed(self):
        for old in (existing(''), existing('garbage'), existing('4.7.0')):
            with self.subTest(old=old), self.assertRaises(ValueError):
                should_promote(old, 'sha256:' + 'b' * 64, '4.7.0', immutable=False)

    def test_only_stable_canonical_versions_are_accepted(self):
        self.assertEqual(version_tuple('4.10.12'), (4, 10, 12))
        for invalid in ('4.7', 'v4.7.0', '4.7.0-modern', '04.7.0', '4.7.0~pre1', '4.7.0\n'):
            with self.subTest(version=invalid), self.assertRaises(ValueError):
                version_tuple(invalid)


if __name__ == '__main__':
    unittest.main(verbosity=2)
