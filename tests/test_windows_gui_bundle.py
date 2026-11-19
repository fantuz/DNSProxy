"""Runtime dependency/provenance checks without requiring Windows or GTK."""

import hashlib
import io
import json
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
builder = runpy.run_path(str(ROOT / "scripts/build-windows-gui-bundle.py"))
PREFIX = "mingw-w64-ucrt-x86_64-"
SHA = "a" * 40
SOURCE = builder["ZSTD_MAGIC"] + b"source"


def package(name, dependencies=(), provides=()):
    return (
        {
            "NAME": [name],
            "VERSION": ["1.2.3-4"],
            "DEPENDS": list(dependencies),
            "PROVIDES": list(provides),
        },
        Path("unused"),
    )


class RuntimeClosureTests(unittest.TestCase):
    def packages(self):
        result = {
            PREFIX + "gtk4": package(
                PREFIX + "gtk4", [PREFIX + "glib2>=2.0", PREFIX + "cc-libs"]
            ),
            PREFIX + "python-gobject": package(
                PREFIX + "python-gobject", [PREFIX + "python", PREFIX + "glib2"]
            ),
            PREFIX + "python-cairo": package(
                PREFIX + "python-cairo", [PREFIX + "python"]
            ),
            PREFIX + "glib2": package(PREFIX + "glib2"),
            PREFIX + "python": package(PREFIX + "python"),
            PREFIX + "gcc-libs": package(
                PREFIX + "gcc-libs", provides=[PREFIX + "cc-libs=15.0"]
            ),
            PREFIX + "gcc": package(PREFIX + "gcc", [PREFIX + "gcc-libs"]),
            "bash": package("bash"),
        }
        return result

    def test_runtime_closure_resolves_virtual_provider_without_copying_compiler(self):
        names = builder["dependency_closure"](self.packages(), PREFIX)
        self.assertIn(PREFIX + "gcc-libs", names)
        self.assertNotIn(PREFIX + "gcc", names)
        self.assertNotIn("bash", names)
        self.assertEqual(len(names), 6)

    def test_missing_ambiguous_and_non_native_dependencies_fail(self):
        for issue in ("missing", "ambiguous", "non-native"):
            with self.subTest(issue=issue):
                packages = self.packages()
                if issue == "missing":
                    del packages[PREFIX + "glib2"]
                elif issue == "ambiguous":
                    packages[PREFIX + "clang-libs"] = package(
                        PREFIX + "clang-libs", provides=[PREFIX + "cc-libs"]
                    )
                else:
                    packages[PREFIX + "gtk4"][0]["DEPENDS"].append("bash")
                with self.assertRaises(ValueError):
                    builder["dependency_closure"](packages, PREFIX)

    def test_runtime_paths_cannot_escape_the_native_prefix(self):
        self.assertEqual(
            builder["relative_file"](
                "ucrt64/lib/gtk-4.0/4.0.0/immodules.dll", "ucrt64"
            ),
            Path("lib/gtk-4.0/4.0.0/immodules.dll"),
        )
        for value in (
            "../outside",
            "/ucrt64/bin/tool.exe",
            "ucrt64/../outside",
            "mingw64/bin/tool.exe",
            "C:/ucrt64/bin/tool.exe",
            "ucrt64/bin\\outside.exe",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                builder["relative_file"](value, "ucrt64")

    def test_stage_keeps_package_licenses_but_excludes_unowned_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prefix, output, metadata = (
                root / "ucrt64",
                root / "bundle",
                root / "local/pkg",
            )
            (prefix / "bin").mkdir(parents=True)
            (prefix / "share/licenses/pkg").mkdir(parents=True)
            output.mkdir()
            metadata.mkdir(parents=True)
            (prefix / "bin/runtime.dll").write_bytes(b"runtime")
            (prefix / "bin/unowned-compiler.exe").write_bytes(b"compiler")
            (prefix / "share/licenses/pkg/LICENSE").write_text("package license")
            (metadata / "desc").write_text("%NAME%\npkg\n\n%VERSION%\n1.0-1\n")
            (metadata / "files").write_text(
                "%FILES%\nucrt64/\nucrt64/bin/\nucrt64/bin/runtime.dll\n"
                "ucrt64/share/licenses/pkg/LICENSE\n"
                "usr/\nusr/share/\nusr/share/libalpm/\nusr/share/libalpm/hooks/\n"
                "usr/share/libalpm/hooks/mingw-w64-ucrt-x86_64-glib-compile-schemas.hook\n"
                "usr/share/libalpm/scripts/\n"
                "usr/share/libalpm/scripts/mingw-w64-ucrt-x86_64-gtk-update-icon-cache\n"
            )
            packages = {"pkg": ({}, metadata)}
            builder["stage_runtime"](prefix, output, ["pkg"], packages)
            self.assertEqual(
                (output / "runtime/bin/runtime.dll").read_bytes(), b"runtime"
            )
            self.assertTrue((output / "runtime/share/licenses/pkg/LICENSE").is_file())
            self.assertFalse((output / "runtime/bin/unowned-compiler.exe").exists())
            self.assertFalse((output / "runtime/usr").exists())
            self.assertIn(
                "usr/share/libalpm/hooks/",
                (output / "runtime-package-metadata/pkg.files").read_text(),
            )
            for value in (
                "usr/bin/tool.exe",
                "usr/share/libalpm/hooks/../tool.exe",
                "usr/share/libalpm/scripts/../tool.exe",
                "/usr/share/libalpm/hooks/foreign.hook",
            ):
                self.assertFalse(builder["is_package_hook_metadata"](value))

    def test_source_urls_use_pkgbase_and_strip_epoch(self):
        info = {
            "NAME": [PREFIX + "runtime"],
            "BASE": ["mingw-w64-runtime"],
            "VERSION": ["2:1.2.3-4"],
        }
        url, destination = builder["source_request"](info, Path("sources"))
        self.assertEqual(
            url,
            "https://repo.msys2.org/mingw/sources/mingw-w64-runtime-1.2.3-4.src.tar.zst",
        )
        self.assertEqual(destination.name, "mingw-w64-runtime-1.2.3-4.src.tar.zst")

    def test_source_versions_preserve_msys_tilde_separator(self):
        info = {
            "NAME": [PREFIX + "directx-headers"],
            "BASE": ["mingw-w64-directx-headers"],
            "VERSION": ["1~1.619.5-1"],
        }
        url, destination = builder["source_request"](info, Path("sources"))
        self.assertTrue(
            url.endswith("/mingw-w64-directx-headers-1~1.619.5-1.src.tar.zst")
        )
        self.assertEqual(
            destination.name, "mingw-w64-directx-headers-1~1.619.5-1.src.tar.zst"
        )
        for value in ("1/escape-1", "1\\escape-1", "1 whitespace-1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                builder["source_request"](dict(info, VERSION=[value]), Path("sources"))

    def test_generated_schema_and_gio_caches_use_only_staged_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / "private runtime"
            (runtime / "share/glib-2.0/schemas").mkdir(parents=True)
            (runtime / "lib/gio/modules").mkdir(parents=True)
            with patch("subprocess.run") as run:
                builder["compile_runtime_caches"](runtime)
            self.assertEqual(run.call_count, 2)
            for call in run.call_args_list:
                command = call.args[0]
                self.assertTrue(Path(command[0]).is_relative_to(runtime))
                self.assertTrue(Path(command[1]).is_relative_to(runtime))

    def test_generated_mime_and_icon_caches_replace_host_package_hooks(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / "private runtime"
            (runtime / "share/mime/packages").mkdir(parents=True)
            theme = runtime / "share/icons/hicolor"
            theme.mkdir(parents=True)
            (theme / "index.theme").write_text("[Icon Theme]\nName=Hicolor\n")
            (runtime / "bin").mkdir()
            icon_tool = runtime / "bin/gtk-update-icon-cache.exe"
            icon_tool.write_bytes(b"native test fixture")
            with patch("subprocess.run") as run:
                builder["compile_runtime_caches"](runtime)
            self.assertEqual(run.call_count, 2)
            self.assertEqual(
                run.call_args_list[0].args[0],
                [
                    str(runtime / "bin/update-mime-database.exe"),
                    str(runtime / "share/mime"),
                ],
            )
            self.assertEqual(
                run.call_args_list[1].args[0], [str(icon_tool), "--force", str(theme)]
            )


class ManifestTests(unittest.TestCase):
    def manifest(self):
        return {
            "schema_version": 1,
            "project": "DNSProxy",
            "version": "4.9.0",
            "source_sha": SHA,
            "architecture": "amd64",
            "packages": [{"name": "runtime"}],
            "sources": [
                {
                    "file": "runtime.src.tar.zst",
                    "sha256": hashlib.sha256(SOURCE).hexdigest(),
                    "size": len(SOURCE),
                }
            ],
            "files": {"app/main.py": hashlib.sha256(b"program").hexdigest()},
        }

    def test_bundle_identity_and_complete_inventory_are_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app").mkdir()
            (root / "app/main.py").write_bytes(b"program")
            manifest = self.manifest()
            (root / "bundle-manifest.json").write_text(json.dumps(manifest))
            validate = builder["validate_manifest"]
            validate(root, "4.9.0", SHA, "amd64")
            for version, sha, arch in (
                ("4.8.0", SHA, "amd64"),
                ("4.9.0", "b" * 40, "amd64"),
                ("4.9.0", SHA, "arm64"),
            ):
                with self.assertRaises(ValueError):
                    validate(root, version, sha, arch)
            (root / "app/main.py").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "checksum"):
                validate(root, "4.9.0", SHA, "amd64")
            (root / "app/main.py").write_bytes(b"program")
            (root / "app/extra.py").write_text("unrecorded")
            with self.assertRaisesRegex(ValueError, "inventory"):
                validate(root, "4.9.0", SHA, "amd64")

    def test_complete_source_archive_and_matching_identity_are_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.manifest()

            def archive(content):
                path = root / "sources.zip"
                with zipfile.ZipFile(path, "w") as output:
                    output.writestr("bundle-manifest.json", json.dumps(manifest))
                    output.writestr("LICENSE", "MIT")
                    output.writestr("THIRD_PARTY_NOTICES.txt", "notices")
                    output.writestr("runtime.src.tar.zst", content)
                return path

            validate = builder["validate_sources"]
            validate(archive(SOURCE), "4.9.0", SHA, "amd64")
            with self.assertRaisesRegex(ValueError, "checksum"):
                validate(
                    archive(builder["ZSTD_MAGIC"] + b"altered"), "4.9.0", SHA, "amd64"
                )
            with self.assertRaisesRegex(ValueError, "match"):
                validate(archive(SOURCE), "4.9.0", SHA, "arm64")
            with self.assertRaisesRegex(ValueError, "Zstandard"):
                validate(archive(b"<html>Error</html>"), "4.9.0", SHA, "amd64")


class SourceDownloadTests(unittest.TestCase):
    def test_network_failure_identifies_the_source_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "runtime.src.tar.zst"
            url = "https://example.test/runtime.src.tar.zst"
            with patch("urllib.request.urlopen", side_effect=OSError("HTTP 404")):
                with self.assertRaisesRegex(RuntimeError, url) as failure:
                    builder["download_source"]((url, destination), tar="bsdtar")
                self.assertIn(destination.name, str(failure.exception))

    def test_nonempty_http_error_body_is_rejected_before_archive_inspection(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "runtime.src.tar.zst"
            with (
                patch(
                    "urllib.request.urlopen",
                    return_value=io.BytesIO(b"<html>proxy error</html>"),
                ),
                patch("subprocess.check_output") as listing,
            ):
                with self.assertRaisesRegex(ValueError, "Zstandard"):
                    builder["download_source"](
                        ("https://example.test/runtime.src.tar.zst", destination),
                        tar="bsdtar",
                    )
                listing.assert_not_called()

    def test_source_archive_must_be_readable_and_include_pkgbuild(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "runtime.src.tar.zst"
            for members, succeeds in (
                ("package/PKGBUILD\npackage/upstream.tar.gz\n", True),
                ("package/README\n", False),
            ):
                with (
                    self.subTest(members=members),
                    patch("urllib.request.urlopen", return_value=io.BytesIO(SOURCE)),
                    patch("subprocess.check_output", return_value=members) as listing,
                ):
                    if succeeds:
                        result = builder["download_source"](
                            ("https://example.test/runtime.src.tar.zst", destination),
                            tar="private/bsdtar.exe",
                        )
                        self.assertEqual(
                            result["sha256"], hashlib.sha256(SOURCE).hexdigest()
                        )
                    else:
                        with self.assertRaisesRegex(ValueError, "PKGBUILD"):
                            builder["download_source"](
                                (
                                    "https://example.test/runtime.src.tar.zst",
                                    destination,
                                ),
                                tar="private/bsdtar.exe",
                            )
                    listing.assert_called_once_with(
                        ["private/bsdtar.exe", "-tf", str(destination)],
                        text=True,
                        timeout=90,
                    )


if __name__ == "__main__":
    unittest.main()
