#!/usr/bin/env python3
"""Compare full native Mac builds on the same runner after warming the toolchain."""

import argparse
import json
from pathlib import Path
import platform
from statistics import median
import subprocess
import time


ROOT = Path(__file__).resolve().parent.parent


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def measure(profile, report_directory, run_name):
    arguments = ["bash", "scripts/build-macos.sh"]
    if profile == "baseline":
        arguments.append("--benchmark-baseline")
    log = (
        report_directory / f"macos-build-{platform.machine()}-{run_name}-{profile}.log"
    )
    started = time.perf_counter()
    with log.open("w") as output:
        result = subprocess.run(
            arguments, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, timeout=180
        )
    elapsed = time.perf_counter() - started
    if result.returncode:
        raise RuntimeError(
            f"{profile} build failed ({result.returncode}):\n{log.read_text()[-12000:]}"
        )
    bundle = ROOT / "dist" / f"macos-{platform.machine()}"
    return {
        "run": run_name,
        "profile": profile,
        "wall_seconds_including_packaging": elapsed,
        "build_info": (bundle / "BUILD-INFO.txt").read_text(),
        "executables": {
            name: {
                "bytes": (bundle / name).stat().st_size,
                "architectures": command("lipo", "-archs", str(bundle / name)),
            }
            for name in ("dnsp-modern", "dnsp-macos")
        },
        "compile_tasks": {
            path.stem: path.read_text()
            for path in sorted(
                (ROOT / "dist").glob(f"macos-build-{platform.machine()}-*.time")
            )
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "dist" / f"macos-build-{platform.machine()}.json",
    )
    options = parser.parse_args()
    if platform.system() != "Darwin":
        parser.error("Run this comparison on native macOS")
    options.output.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "schema": 2,
        "scope": "Full clean builds including linking, validation, checksums and packaging on one runner with warm toolchain and filesystem caches.",
        "machine": platform.machine(),
        "os": platform.platform(),
        "hardware": command("sysctl", "-n", "machdep.cpu.brand_string"),
        "compiler": command("xcrun", "clang", "--version"),
        "source_commit": command("git", "-C", str(ROOT), "rev-parse", "HEAD"),
        "runs": [],
    }
    # First-use SDK and compiler costs belong to neither side of the comparison.
    report["warmup"] = measure("release", options.output.parent, "warmup")
    # Each profile runs first in two pairs and second in two. Finish with the
    # release archive so the downstream acceptance tests exercise that build.
    order = (
        "baseline",
        "release",
        "release",
        "baseline",
        "release",
        "baseline",
        "baseline",
        "release",
    )
    for index, profile in enumerate(order, 1):
        report["runs"].append(measure(profile, options.output.parent, str(index)))
    samples = {
        profile: [
            run["wall_seconds_including_packaging"]
            for run in report["runs"]
            if run["profile"] == profile
        ]
        for profile in ("baseline", "release")
    }
    medians = {profile: median(values) for profile, values in samples.items()}
    report["median_seconds"] = medians
    report["release_to_baseline_wall_ratio"] = medians["release"] / medians["baseline"]
    options.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                "report": str(options.output),
                "hardware": report["hardware"],
                "first_release_seconds": report["warmup"][
                    "wall_seconds_including_packaging"
                ],
                "wall_seconds": samples,
                "median_seconds": medians,
                "release_to_baseline_wall_ratio": report[
                    "release_to_baseline_wall_ratio"
                ],
                "baseline_executables": report["runs"][0]["executables"],
                "release_executables": report["runs"][-1]["executables"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
