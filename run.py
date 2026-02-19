#!/usr/bin/env python3

import argparse
import shlex
import subprocess
from pathlib import Path

PROJ_ROOT = Path(__file__).resolve().parent.relative_to(Path.cwd())
BUILD_DIR = PROJ_ROOT / "build"


def system(cmd: list[str], *, check: bool = True) -> int:
    rendered = " ".join(shlex.quote(part) for part in cmd)
    print(f"\033[34mRunning: `{rendered}`\033[0m", flush=True)
    completed = subprocess.run(cmd, check=check)
    return completed.returncode


def main(program: str) -> None:
    system(["make"])

    loader = BUILD_DIR / "loader"
    assert loader.exists(), f"missing loader: {loader}"

    pattern = "*.elf" if program == "all" else f"{program}.elf"
    elfs = sorted(BUILD_DIR.glob(pattern))
    assert elfs, f"no ELF files found under {BUILD_DIR} matching {pattern}"

    for elf in elfs:
        direct_rc = system([str(elf)], check=False)
        print(f"{elf}: direct exit={direct_rc}")

        loader_rc = system([str(loader), str(elf)], check=False)
        print(f"{elf}: loader exit={loader_rc}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Build syslift and run ELF program(s) directly and via loader."
    )
    parser.add_argument(
        "program",
        nargs="?",
        default="all",
        help="Program name (e.g. getpid), or 'all'.",
    )
    args = parser.parse_args()
    main(args.program)
