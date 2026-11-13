import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.repo = self.root / "work"
        self.repo.mkdir()
        self.origin = self.root / "origin.git"
        self.git("init", "-q", "--bare", "-b", "master", str(self.origin))
        self.git("init", "-q", "-b", "master")
        self.git("config", "user.name", "Release CI")
        self.git("config", "user.email", "release-ci@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("remote", "add", "origin", str(self.origin))
        (self.repo / "scripts").mkdir()
        for name in ("release-common.sh", "prepare-release.sh", "ci-release-plan.sh", "publish-modern.sh"):
            shutil.copy(SCRIPTS / name, self.repo / "scripts")
        (self.repo / "VERSION").write_text("0.3.6\n")
        self.git("add", ".")
        self.git("commit", "-qm", "Base commit")
        self.base = self.git("rev-parse", "HEAD")
        self.git("tag", "--no-sign", "-a", "-m", "Previous tag", "v0.3.7-modern")
        self.git("push", "-q", "origin", "master", "v0.3.7-modern")
        self.git("checkout", "-q", "--detach", self.base)

        self.output = self.root / "output"
        self.stage = "refs/heads/ci/release-42"
        self.tag = "refs/tags/v0.3.8-modern"
        self.env = os.environ | {
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": "refs/heads/master",
            "GITHUB_RUN_ID": "42",
            "GITHUB_RUN_NUMBER": "42",
            "GITHUB_SHA": self.base,
            "GITHUB_OUTPUT": str(self.output),
            "PUBLISH_REQUESTED": "true",
            "REQUESTED_RELEASE_VERSION": "0.3.8",
        }

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.repo, text=True,
                              capture_output=True, check=True).stdout.strip()

    def ref(self, name):
        result = self.git("ls-remote", "origin", name)
        return result.split()[0] if result else None

    def script(self, name, *args, succeeds=True, **env):
        self.output.write_text("")
        shell = "bash" if name == "publish-modern.sh" else "sh"
        result = subprocess.run([shell, f"scripts/{name}", *map(str, args)],
                                cwd=self.repo, text=True, capture_output=True, env=self.env | env)
        self.assertEqual(result.returncode == 0, succeeds, result.stdout + result.stderr)
        return dict(line.split("=", 1) for line in self.output.read_text().splitlines())

    def packages(self, directory):
        directory.mkdir()
        for distro in ("ubuntu22.04", "ubuntu24.04", "debian13"):
            for arch in ("amd64", "arm64"):
                (directory / f"dnsp-modern_0.3.8+{distro}_{arch}.deb").write_text(arch)
        for arch in ("x86_64", "aarch64"):
            (directory / f"dnsp-modern-0.3.8-1.el9.{arch}.rpm").write_text(arch)
        (directory / "dnsp-modern-0.3.8-windows-amd64-poc.zip").write_text("Windows bundle")
        return directory

    def test_prepare_plan_and_publish_retry(self):
        prepared = self.script("prepare-release.sh")["commit"]
        self.assertEqual(self.git("rev-parse", "HEAD^"), self.base)
        self.assertEqual(self.git("diff", "--name-only", self.base, prepared), "VERSION")
        self.assertEqual(self.git("show", f"{prepared}:VERSION"), "0.3.8")
        self.assertEqual(self.ref("refs/heads/master"), self.base)
        self.assertEqual(self.ref(self.stage), prepared)
        self.assertIsNone(self.ref(self.tag))
        self.script("ci-release-plan.sh", succeeds=False, PREPARED_RELEASE_COMMIT=self.base)
        self.assertEqual(self.script("ci-release-plan.sh", PREPARED_RELEASE_COMMIT=prepared), {
            "version": "0.3.8", "tag": "v0.3.8-modern", "mode": "manual", "commit": prepared,
        })

        # The stub confines publication to the test repo and can interrupt it after tagging.
        gh = self.root / "gh"
        gh.write_text('''#!/bin/sh
case "$2" in
    view) test -f "$TEST_RELEASE" && printf 'false\\n' ;;
    create)
        printf '%s\\n' "$@" >> "$TEST_CREATE_ARGS"
        test "$FAIL_PUBLICATION" = false && sha256sum -c SHA256SUMS && touch "$TEST_RELEASE"
        ;;
    *) exit 2 ;;
esac
''')
        gh.chmod(0o755)
        assets = self.packages(self.root / "packages")
        expected_packages = sorted(path.name for path in assets.iterdir())
        # CI also supplies a per-ZIP checksum; the release uses its aggregate manifest.
        (assets / "dnsp-modern-0.3.8-windows-amd64-poc.zip.sha256").write_text("CI sidecar")
        release = self.root / "published"
        create_args = self.root / "create-args"
        publish = {
            "PATH": f"{self.root}:{os.environ['PATH']}",
            "RELEASE_MODE": "manual", "RELEASE_TAG": "v0.3.8-modern", "RELEASE_COMMIT": prepared,
            "TEST_RELEASE": str(release),
            "TEST_CREATE_ARGS": str(create_args),
        }
        self.script("publish-modern.sh", assets, succeeds=False, FAIL_PUBLICATION="true", **publish)
        self.assertEqual(self.ref(self.tag), prepared)
        self.assertEqual(self.ref(self.stage), prepared)
        self.assertFalse(release.exists())
        self.git("checkout", "-q", "--detach", self.base)
        self.assertEqual(self.script("prepare-release.sh")["commit"], prepared)
        self.git("checkout", "-q", "--detach", prepared)
        self.script("publish-modern.sh", assets, FAIL_PUBLICATION="false", **publish)
        self.assertTrue(release.exists())
        self.assertEqual(self.ref(self.tag), prepared)
        self.assertIsNone(self.ref(self.stage))
        attempts = create_args.read_text()
        arguments = attempts.splitlines()
        self.assertEqual(arguments.count("create"), 2)
        self.assertEqual(arguments.count("--prerelease=false"), 2)
        self.assertNotIn("--prerelease", arguments)
        self.assertNotIn("--prerelease=true", arguments)
        for package in expected_packages:
            self.assertEqual(arguments.count(package), 2)
        checksums = (assets / "SHA256SUMS").read_text().splitlines()
        self.assertEqual(len(checksums), 9)
        self.assertEqual(sorted(line.split("  ", 1)[1] for line in checksums), expected_packages)
        self.script("publish-modern.sh", assets, FAIL_PUBLICATION="true", **publish)
        self.assertEqual(create_args.read_text(), attempts)

    def test_incomplete_package_sets_never_tag_or_publish(self):
        prepared = self.script("prepare-release.sh")["commit"]
        gh_calls = self.root / "gh-calls"
        gh = self.root / "gh"
        gh.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$TEST_GH_CALLS"\nexit 1\n')
        gh.chmod(0o755)
        for case in ("missing-windows", "empty-windows", "wrong-version", "extra-zip", "missing-linux"):
            with self.subTest(case=case):
                assets = self.packages(self.root / case)
                windows = assets / "dnsp-modern-0.3.8-windows-amd64-poc.zip"
                if case == "missing-windows":
                    windows.unlink()
                elif case == "empty-windows":
                    windows.write_bytes(b"")
                elif case == "wrong-version":
                    windows.rename(assets / "dnsp-modern-0.3.7-windows-amd64-poc.zip")
                elif case == "extra-zip":
                    (assets / "stale-build.zip").write_text("old build")
                else:
                    (assets / "dnsp-modern_0.3.8+debian13_arm64.deb").unlink()
                self.script("publish-modern.sh", assets, succeeds=False,
                            PATH=f"{self.root}:{os.environ['PATH']}",
                            RELEASE_MODE="manual", RELEASE_TAG="v0.3.8-modern",
                            RELEASE_COMMIT=prepared, TEST_GH_CALLS=str(gh_calls))
                self.assertIsNone(self.ref(self.tag))
                self.assertEqual(self.ref(self.stage), prepared)
                self.assertFalse(gh_calls.exists())

    def test_sync_master_to_published_version_keeps_existing_tag(self):
        prepared = self.script("prepare-release.sh")["commit"]
        self.git("push", "-q", "origin", f"{prepared}:{self.tag}")
        self.git("checkout", "-q", "master")
        (self.repo / "VERSION").write_text("0.3.8\n")
        self.git("commit", "-qm", "Sync published version", "--", "VERSION")
        synced = self.git("rev-parse", "HEAD")
        self.assertNotEqual(synced, prepared)
        self.git("push", "-q", "origin", "master")

        plan = self.script("ci-release-plan.sh", GITHUB_EVENT_NAME="push",
                           REQUESTED_RELEASE_VERSION="", PUBLISH_REQUESTED="false")
        self.assertEqual(plan, {
            "version": "0.3.8~pre42.ci", "tag": "v0.3.8-modern",
            "mode": "snapshot", "commit": synced,
        })
        self.assertEqual(self.ref(self.tag), prepared)
        self.assertEqual(self.ref("refs/heads/master"), synced)

    def test_invalid_or_used_versions_never_stage(self):
        for version in ("0.3.07", "0.3.8\nmode=manual", "0.3.6", "0.3.7"):
            with self.subTest(version=version):
                self.script("prepare-release.sh", succeeds=False, REQUESTED_RELEASE_VERSION=version)
        self.script("prepare-release.sh", succeeds=False, GITHUB_REF="refs/heads/topic")
        self.script("prepare-release.sh", succeeds=False, PUBLISH_REQUESTED="false")
        self.script("ci-release-plan.sh", succeeds=False)
        self.git("push", "-q", "origin", f"{self.base}:refs/tags/v0.3.10-modern")
        self.script("prepare-release.sh", succeeds=False)
        self.assertIsNone(self.ref(self.stage))
        self.assertIsNone(self.ref(self.tag))

    def test_existing_release_modes(self):
        snapshot = self.script("ci-release-plan.sh", REQUESTED_RELEASE_VERSION="", PUBLISH_REQUESTED="false")
        self.assertEqual((snapshot["mode"], snapshot["version"]), ("snapshot", "0.3.6~pre42.ci"))
        tag = self.script("ci-release-plan.sh", GITHUB_EVENT_NAME="push", GITHUB_REF="refs/tags/v0.3.6-modern",
                          REQUESTED_RELEASE_VERSION="", PUBLISH_REQUESTED="false")
        self.assertEqual((tag["mode"], tag["commit"]), ("tag", self.base))
        (self.repo / "VERSION").write_text("0.3.8\n")
        self.git("commit", "-qm", "Version bump", "--", "VERSION")
        automatic = self.script("ci-release-plan.sh", GITHUB_EVENT_NAME="push", REQUESTED_RELEASE_VERSION="")
        self.assertEqual((automatic["mode"], automatic["version"]), ("master", "0.3.8"))


if __name__ == "__main__":
    unittest.main()
