#!/usr/bin/env python3
"""Run the complete fixed local W3 verification catalogue once."""

from __future__ import annotations

import sys

from tidemark.verification.w3_runner import main


if __name__ == "__main__":
    raise SystemExit(main(tuple(sys.argv[1:])))
