#!/bin/bash
# Build script for bad-ips package
# Automatically updates version numbers across all files

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="/tmp/bad-ips-build"
OUTPUT_DIR="$HOME/apt-repo"
VERSION=""
SKIP_CONFIRM=0
AUTO_DEPLOY=0

# Show help
show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] VERSION

Build the bad-ips Debian package with automatic version updates.

ARGUMENTS:
    VERSION             Package version in X.Y.Z format (e.g., 3.0.0)

OPTIONS:
    -o, --output DIR    Output directory (default: ~/apt-repo)
    -y, --yes          Skip build confirmation prompt
    -d, --deploy       Automatically deploy to proxy after build
    -h, --help         Show this help message

EXAMPLES:
    $(basename "$0") 3.0.0
    $(basename "$0") 3.0.1 --output /tmp/packages
    $(basename "$0") 3.0.2 --yes --deploy

WHAT IT DOES:
    1. Updates version in DEBIAN/control
    2. Updates version in man page
    3. Updates version in README.md
    4. Updates version in website/index.html
    5. Updates version in website/configuration.html
    6. Updates version in BadIPs.pm
    7. Builds the .deb package to OUTPUT_DIR/pool/main/

CURRENT VERSION:
    $(grep "^Version:" "$SCRIPT_DIR/DEBIAN/control" | awk '{print $2}')

OUTPUT:
    Package will be built to: $OUTPUT_DIR/pool/main/bad-ips_VERSION_all.deb
EOF
}

# Parse command line options
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help|-\?)
                show_help
                exit 0
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -y|--yes)
                SKIP_CONFIRM=1
                shift
                ;;
            -d|--deploy)
                AUTO_DEPLOY=1
                shift
                ;;
            -*)
                echo "Error: Unknown option: $1"
                echo "Try '$(basename "$0") --help' for more information."
                exit 1
                ;;
            *)
                if [ -z "$VERSION" ]; then
                    VERSION="$1"
                    shift
                else
                    echo "Error: Multiple version arguments provided"
                    exit 1
                fi
                ;;
        esac
    done

    # Check if version was provided
    if [ -z "$VERSION" ]; then
        echo "Error: VERSION is required"
        echo ""
        show_help
        exit 1
    fi

    # Validate version format
    if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Error: Version must be in format X.Y.Z (e.g., 3.0.0)"
        exit 1
    fi
}

# Update version in all files
update_versions() {
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

    # Update version in BadIPs.pm
    echo "Updating BadIPs.pm..."
    sed -i "s/^our \$VERSION = '[0-9.]*';/our \$VERSION = '$VERSION';/" "$SCRIPT_DIR/usr/local/lib/site_perl/BadIPs.pm"
    echo "✓ BadIPs.pm updated"

    # Update version in all BadIPs submodules
    echo "Updating BadIPs submodules..."
    local SUBMODULE_COUNT=0
    for module in "$SCRIPT_DIR/usr/local/lib/site_perl/BadIPs"/*.pm; do
        if [ -f "$module" ]; then
            sed -i "s/^our \$VERSION = '[0-9.]*';/our \$VERSION = '$VERSION';/" "$module"
            SUBMODULE_COUNT=$((SUBMODULE_COUNT + 1))
        fi
    done
    echo "✓ Updated $SUBMODULE_COUNT BadIPs submodule(s)"

    echo ""
    echo "Version updates complete!"
    echo ""

    # Show what changed
    echo "Git status:"
    git -C "$SCRIPT_DIR" status --short | grep -E "(DEBIAN/control|man8/bad_ips.8|README.md|website/|BadIPs)" || echo "  No changes detected"
    echo ""
}

# Build the package
build_package() {
    # Confirm before building unless --yes was passed
    if [ $SKIP_CONFIRM -eq 0 ]; then
        read -p "Proceed with package build? [Y/n] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]] && [[ -n $REPLY ]]; then
            echo "Build cancelled. Version files have been updated but package not built."
            exit 0
        fi
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
      --exclude='docs' \
      --exclude='scripts' \
      --exclude='pool' \
      --exclude='Makefile' \
      --exclude='VERSION' \
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
}

# Deploy to proxy
deploy_package() {
    if [ $AUTO_DEPLOY -eq 0 ]; then
        echo "Next steps:"
        echo "  1. Update apt repo:    cd ~/apt-repo && ./update-repo.sh"
        echo "  2. Deploy to proxy:    rsync -av ~/apt-repo/ proxy:/var/www/projects.thedude.vip/apt/ --exclude='.git' --exclude='update-repo.sh'"
        echo "  3. Deploy website:     rsync -av $SCRIPT_DIR/website/ proxy:/var/www/projects.thedude.vip/bad-ips/"
        echo "  4. Commit changes:     git add -A && git commit -m 'Release v$VERSION' && git push"
        echo ""

        # Offer to automate deployment
        read -p "Would you like to automatically deploy to proxy? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Deployment skipped. Use the commands above to deploy manually."
            echo ""
            return
        fi
    fi

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
    echo ""
}

# Main
parse_args "$@"
update_versions
build_package
deploy_package
