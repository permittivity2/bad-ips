#!/bin/bash
# Build script for bad-ips package
# Excludes development files from the package

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="/tmp/bad-ips-build"
VERSION=$(cat "$SCRIPT_DIR/DEBIAN/control" | grep "^Version:" | awk '{print $2}')
OUTPUT_DIR="${1:-$SCRIPT_DIR}"

echo "Building bad-ips v$VERSION..."

# Clean and create build directory
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Copy files, excluding development artifacts
rsync -a \
  --exclude='.git' \
  --exclude='*.deb' \
  --exclude='website' \
  --exclude='build' \
  --exclude='.vscode' \
  --exclude='README.md' \
  --exclude='LICENSE' \
  --exclude='.gitignore' \
  --exclude='build-package.sh' \
  "$SCRIPT_DIR/" "$BUILD_DIR/"

# Build package
dpkg-deb --build "$BUILD_DIR" "$OUTPUT_DIR/bad-ips_${VERSION}_all.deb"

# Cleanup
rm -rf "$BUILD_DIR"

echo "✓ Package built: $OUTPUT_DIR/bad-ips_${VERSION}_all.deb"
ls -lh "$OUTPUT_DIR/bad-ips_${VERSION}_all.deb"
