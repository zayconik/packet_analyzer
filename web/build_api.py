#!/usr/bin/env python3
"""Build the dpi_api binary used by the web UI."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SOURCES = [
    "src/main_json.cpp",
    "src/dpi_processor.cpp",
    "src/pcap_reader.cpp",
    "src/packet_parser.cpp",
    "src/sni_extractor.cpp",
    "src/types.cpp",
]

OUTPUT = "dpi_api.exe" if sys.platform == "win32" else "dpi_api"


def main() -> int:
    cmd = [
        "g++",
        "-std=c++17",
        "-O2",
        "-I", "include",
        "-o", OUTPUT,
        *SOURCES,
    ]

    if sys.platform == "win32":
        cmd[1:1] = ["-static-libgcc", "-static-libstdc++", "-static"]

    print("Building", OUTPUT, "...")
    print(" ".join(cmd))
    result = subprocess.run(cmd, cwd=ROOT)
    if result.returncode == 0:
        print(f"Built {ROOT / OUTPUT}")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
