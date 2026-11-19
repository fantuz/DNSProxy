#!/usr/bin/env python3
"""Measure a sequential O2 baseline and the native Mac release build.

The final archive always comes from the second, release-profile build. Timings
are evidence from one CI machine, not a performance requirement or an estimate
of DNS/network throughput.
"""

import argparse
import json
from pathlib import Path
import platform
import subprocess
import time


ROOT = Path(__file__).resolve().parent.parent


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def measure(profile, report_directory):
    arguments = ["bash", "scripts/build-macos.sh"]
    if profile == "baseline":
        arguments.append("--benchmark-baseline")
    log = report_directory / f"macos-build-{platform.machine()}-{profile}.log"
    started = time.perf_counter()
    with log.open("w") as output:
        result = subprocess.run(arguments, cwd=ROOT, stdout=output,
                                stderr=subprocess.STDOUT, timeout=180)
    elapsed = time.perf_counter() - started
    if result.returncode:
        raise RuntimeError(f"{profile} build failed ({result.returncode}):\n{log.read_text()[-12000:]}")
    bundle = ROOT / "dist" / f"macos-{platform.machine()}"
    return {
        "profile": profile,
        "wall_seconds_including_packaging": elapsed,
        "build_info": (bundle / "BUILD-INFO.txt").read_text(),
        "executables": {
            name: {"bytes": (bundle / name).stat().st_size,
                   "architectures": command("lipo", "-archs", str(bundle / name))}
            for name in ("dnsp-modern", "dnsp-macos")
        },
        "compile_tasks": {
            path.stem: path.read_text()
            for path in sorted((ROOT / "dist").glob(f"macos-build-{platform.machine()}-*.time"))
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path,
                        default=ROOT / "dist" / f"macos-build-{platform.machine()}.json")
    options = parser.parse_args()
    if platform.system() != "Darwin":
        parser.error("Run this comparison on native macOS")
    options.output.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "schema": 1,
        "scope": "One sequential baseline/release pair; wall time includes compilation and packaging. No DNS throughput claim.",
        "machine": platform.machine(),
        "os": platform.platform(),
        "hardware": command("sysctl", "-n", "machdep.cpu.brand_string"),
        "compiler": command("xcrun", "clang", "--version"),
        "source_commit": command("git", "-C", str(ROOT), "rev-parse", "HEAD"),
        "runs": [],
    }
    # Never leave a baseline archive for the publication workflow to collect.
    # If either build fails this step fails before acceptance/publication.
    for profile in ("baseline", "release"):
        report["runs"].append(measure(profile, options.output.parent))
    baseline, release = report["runs"]
    report["release_to_baseline_wall_ratio"] = (
        release["wall_seconds_including_packaging"] /
        baseline["wall_seconds_including_packaging"]
    )
    options.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"report": str(options.output),
                      "release_to_baseline_wall_ratio": report["release_to_baseline_wall_ratio"],
                      "baseline_seconds": baseline["wall_seconds_including_packaging"],
                      "release_seconds": release["wall_seconds_including_packaging"],
                      "release_executables": release["executables"]}, indent=2))


if __name__ == "__main__":
    main()
