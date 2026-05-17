#!/usr/bin/env python3
"""Verify GUI syntax"""
import py_compile
import sys

try:
    py_compile.compile('cryptogo/gui.py', doraise=True)
    print("✓ gui.py syntax is valid")
    sys.exit(0)
except py_compile.PyCompileError as e:
    print(f"✗ Syntax error in gui.py:")
    print(e)
    sys.exit(1)
