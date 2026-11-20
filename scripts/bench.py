import argparse
import ctypes.util
import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
WORKLOADS = {
    "transaction": {"tier": "change", "area": "rules", "binary": "bench_change", "description": "commit and verify 1000 rules"},
    "upstream": {"tier": "full", "area": "rules", "binary": "bench", "description": "upstream set, rule and transaction comparison"},
}


def binary_path(name):
    target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
    if not target.is_absolute():
        target = ROOT / target
    return target / "release" / "examples" / WORKLOADS[name]["binary"]


def select(tier, names, area, skips):
    rank = {"edit": 0, "change": 1, "full": 2}
    unknown = (set(names) | set(skips)) - WORKLOADS.keys()
    if unknown:
        raise ValueError("unknown workload: " + ", ".join(sorted(unknown)))
    if area and area not in {w["area"] for w in WORKLOADS.values()}:
        raise ValueError("unknown area: " + area)
    chosen = [name for name, w in WORKLOADS.items() if rank[w["tier"]] <= rank[tier]
              and (not names or name in names) and (not area or w["area"] == area)
              and name not in skips]
    omitted = set(names) - set(chosen)
    if omitted:
        raise ValueError("requested workload excluded by tier, area, or skip: " + ", ".join(sorted(omitted)))
    if tier != "edit" and not chosen:
        raise ValueError("selection matches no workloads")
    return chosen


def preflight(names):
    errors = []
    if names and not shutil.which("unshare"):
        errors.append("install unshare to create a network namespace")
    if names and hasattr(os, "geteuid") and os.geteuid() != 0:
        errors.append("run as root with permission to create a network namespace")
    for name in names:
        binary = binary_path(name)
        if not binary.is_file() or not os.access(binary, os.X_OK):
            errors.append(f"{name}: build {binary} before running")
        else:
            sources = [ROOT / "Cargo.toml", ROOT / "Cargo.lock", ROOT / "examples" / (WORKLOADS[name]["binary"] + ".rs")]
            sources.extend((ROOT / "src").rglob("*.rs"))
            if any(source.stat().st_mtime_ns > binary.stat().st_mtime_ns for source in sources):
                errors.append(f"{name}: rebuild stale {binary}")
    if "upstream" in names and not shutil.which("nft"):
        errors.append("upstream: install nftables")
    if "upstream" in names and not ctypes.util.find_library("nftables"):
        errors.append("upstream: install libnftables")
    if "upstream" in names and not (binary_path("upstream").parent.parent / "nfcrt").is_file():
        errors.append("upstream: build the release nfcrt binary")
    elif "upstream" in names:
        nfcrt = binary_path("upstream").parent.parent / "nfcrt"
        cli_sources = [ROOT / "Cargo.toml", ROOT / "Cargo.lock", ROOT / "cli" / "Cargo.toml",
                       *list((ROOT / "cli" / "src").rglob("*.rs")), *list((ROOT / "src").rglob("*.rs"))]
        if any(source.stat().st_mtime_ns > nfcrt.stat().st_mtime_ns for source in cli_sources):
            errors.append(f"upstream: rebuild stale {nfcrt}")
    if names and not errors:
        try:
            probe = subprocess.run(["unshare", "-n", "true"], capture_output=True, text=True, timeout=10)
            if probe.returncode:
                errors.append("network namespace preflight failed: " + probe.stderr.strip())
        except (OSError, subprocess.TimeoutExpired) as e:
            errors.append(f"network namespace preflight failed: {e}")
    return errors


def self_test():
    assert select("edit", [], None, []) == []
    assert select("change", [], None, []) == ["transaction"]
    assert select("full", ["upstream"], "rules", []) == ["upstream"]
    for args in [("change", ["missing"], None, []), ("change", ["upstream"], None, []),
                 ("change", [], "missing", []), ("change", [], None, ["transaction"])]:
        try:
            select(*args)
        except ValueError:
            continue
        raise AssertionError(f"selection unexpectedly accepted: {args}")
    print("selection checks passed")


def main():
    p = argparse.ArgumentParser(description="Select bounded benchmark workloads; Full requires --tier full.")
    p.add_argument("action", choices=["list", "check", "run"], help="list workloads, check prerequisites, or run")
    p.add_argument("--tier", choices=["edit", "change", "full"], default="change", help="maximum workload tier")
    p.add_argument("--workload", action="append", default=[], help="select a named workload; repeatable")
    p.add_argument("--area", help="select an area")
    p.add_argument("--skip", action="append", default=[], help="exclude a workload; repeatable")
    p.add_argument("--dry-run", action="store_true", help="print commands without checking or writing")
    args = p.parse_args()
    if args.action == "list":
        for name, w in WORKLOADS.items():
            print(f"{name}: {w['tier']} {w['area']} — {w['description']}")
        return 0
    try:
        names = select(args.tier, args.workload, args.area, args.skip)
    except ValueError as e:
        print(e, file=sys.stderr)
        return 2
    commands = [["unshare", "-n", str(binary_path(n))] for n in names]
    if args.dry_run:
        for command in commands:
            print(" ".join(command))
        if args.tier == "edit":
            print("benchmark selection self-test")
        return 0
    errors = preflight(names)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    if args.action == "check":
        print("preflight passed; host timing readiness is not established")
        return 0
    if args.tier == "edit":
        self_test()
        return 0
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    out = ROOT / ".work" / "bench" / stamp
    out.mkdir(parents=True)
    results = []
    for name, command in zip(names, commands):
        start = time.monotonic()
        try:
            result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=900)
            code, output = result.returncode, result.stdout + result.stderr
        except subprocess.TimeoutExpired as e:
            code, output = 1, f"timed out: {e}"
        (out / f"{name}.log").write_text(output)
        results.append({"workload": name, "exit": code, "seconds": time.monotonic() - start,
                        "timing": "unvalidated; host readiness not established"})
    excluded = {name: "not selected" for name in WORKLOADS if name not in names}
    revision, dirty = "unavailable", "unavailable"
    if shutil.which("git"):
        rev = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True)
        status = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True)
        if rev.returncode == 0:
            revision = rev.stdout.strip()
        if status.returncode == 0:
            dirty = bool(status.stdout)
    summary = {"revision": revision, "dirty": dirty,
               "platform": list(os.uname()) if hasattr(os, "uname") else "unavailable",
               "results": results, "excluded": excluded, "host_readiness": "not established"}
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(results, indent=2))
    print(f"results: {out}")
    return int(any(r["exit"] != 0 for r in results))


if __name__ == "__main__":
    sys.exit(main())
