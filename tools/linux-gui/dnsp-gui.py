#!/usr/bin/env python3
"""Compatibility entry point for the shared DNSProxy desktop GUI."""

from pathlib import Path
import runpy
import sys

source = Path(__file__).resolve().parents[1] / 'desktop-gui'
sys.path.insert(0, str(source))
runpy.run_path(str(source / 'dnsp-gui.py'), run_name='__main__')
