#!/usr/bin/env python3
import sys
import os

# Add parent directory to sys.path so it works without setup.py install
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from jshound.cli import main

if __name__ == "__main__":
    main()
