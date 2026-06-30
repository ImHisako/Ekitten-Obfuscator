#!/usr/bin/env python3
"""Compatibility entry point for the Ekitten obfuscator CLI."""

from pathlib import Path
import runpy


if __name__ == "__main__":
    runpy.run_path(
        str(Path(__file__).with_name("Ekitten Obfuscator.py")),
        run_name="__main__",
    )
