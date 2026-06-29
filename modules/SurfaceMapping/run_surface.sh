#!/bin/bash
# Quick runner for SurfaceMapping
BIN_DIR="$(dirname "$0")/bin"

# Add bin directory to PATH
export PATH="$BIN_DIR:$PATH"

# Run surface mapping
python3 surface.py "$@"
