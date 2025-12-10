#!/bin/bash
# Build script for bad-ips package
# Automatically updates version numbers across all files

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="/tmp/bad-ips-build"

# Check if version was provided
if [ -z "$1" ]; then
    echo "Usage: $0 <version> [output-dir]"
    echo ""
    echo "Example: $0 2.0.10"
    echo "         $0 2.0.10 /path/to/output"
    echo ""
    echo "This will:"
    echo "  1. Update version in DEBIAN/control"
    echo "  2. Update version in man page"
    echo "  3. Update version in README.md"
    echo "  4. Update version in website/index.html"
    echo "  5. Update version in website/configuration.html"
    echo "  6. Build the package"
    echo ""
    CURRENT_VERSION=$(grep "^Version:" "$SCRIPT_DIR/DEBIAN/control" | awk '{print $2}')
    echo "Current version: $CURRENT_VERSION"
    exit 1
fi

VERSION="$1"
OUTPUT_DIR="${2:-$SCRIPT_DIR}"

# Validate version format (simple check for X.Y.Z)
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Version must be in format X.Y.Z (e.g., 2.0.10)"
    exit 1
fi

echo "============================================"
echo "Building bad-ips v$VERSION"
echo "============================================"
echo ""

# Update version in DEBIAN/control
echo "Updating DEBIAN/control..."
sed -i "s/^Version: .*/Version: $VERSION/" "$SCRIPT_DIR/DEBIAN/control"
echo "✓ DEBIAN/control updated"

# Update version in man page
echo "Updating man page..."
sed -i "s/\"Bad IPs [0-9.]*\"/\"Bad IPs $VERSION\"/" "$SCRIPT_DIR/usr/share/man/man8/bad_ips.8"
echo "✓ Man page updated"

# Update version in README.md
echo "Updating README.md..."
sed -i "s/version-[0-9.]*-blue/version-$VERSION-blue/" "$SCRIPT_DIR/README.md"
echo "✓ README.md updated"

# Update version in website/index.html (header and footer)
echo "Updating website/index.html..."
sed -i "s/v[0-9.]*\ -\ Distributed/v$VERSION - Distributed/" "$SCRIPT_DIR/website/index.html"
sed -i "s/Bad IPs v[0-9.]* - Silver Linings/Bad IPs v$VERSION - Silver Linings/" "$SCRIPT_DIR/website/index.html"
echo "✓ website/index.html updated"

# Update version in website/configuration.html
echo "Updating website/configuration.html..."
sed -i "s/Bad IPs v[0-9.]* - Silver Linings/Bad IPs v$VERSION - Silver Linings/" "$SCRIPT_DIR/website/configuration.html"
echo "✓ website/configuration.html updated"

echo ""
echo "Version updates complete!"
echo ""

# Show what changed
echo "Git status:"
git -C "$SCRIPT_DIR" status --short | grep -E "(DEBIAN/control|man8/bad_ips.8|README.md|website/)" || echo "  No changes detected"
echo ""

# Confirm before building
read -p "Proceed with package build? [Y/n] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]] && [[ -n $REPLY ]]; then
    echo "Build cancelled. Version files have been updated but package not built."
    exit 0
fi

echo "Building package..."
echo ""

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
  --exclude='.dpkg-ignore' \
  "$SCRIPT_DIR/" "$BUILD_DIR/"

# Build package
mkdir -p "$OUTPUT_DIR/pool/main"
dpkg-deb --build "$BUILD_DIR" "$OUTPUT_DIR/pool/main/bad-ips_${VERSION}_all.deb"

# Cleanup
rm -rf "$BUILD_DIR"

echo ""
echo "============================================"
echo "✓ Package built successfully!"
echo "============================================"
ls -lh "$OUTPUT_DIR/pool/main/bad-ips_${VERSION}_all.deb"
echo ""
echo "Next steps:"
echo "  1. Update apt repo:    cd ~/apt-repo && ./update-repo.sh"
echo "  2. Deploy to proxy:    rsync -av ~/apt-repo/ proxy:/var/www/projects.thedude.vip/apt/ --exclude='.git' --exclude='update-repo.sh'"
echo "  3. Deploy website:     rsync -av $SCRIPT_DIR/website/ proxy:/var/www/projects.thedude.vip/bad-ips/"
echo "  4. Commit changes:     git add -A && git commit -m 'Release v$VERSION' && git push"
echo ""

# Offer to automate deployment
read -p "Would you like to automatically deploy to proxy? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "Updating apt repository..."
    cd ~/apt-repo && ./update-repo.sh

    echo ""
    echo "Deploying apt repository to proxy..."
    rsync -av ~/apt-repo/ proxy:/var/www/projects.thedude.vip/apt/ --exclude='.git' --exclude='update-repo.sh'

    echo ""
    echo "Deploying website to proxy..."
    rsync -av "$SCRIPT_DIR/website/" proxy:/var/www/projects.thedude.vip/bad-ips/

    echo ""
    echo "✓ Deployment complete!"
    echo ""
    echo "Final step:"
    echo "  Commit changes:     git add -A && git commit -m 'Release v$VERSION' && git push"
else
    echo "Deployment skipped. Use the commands above to deploy manually."
fi
echo ""
