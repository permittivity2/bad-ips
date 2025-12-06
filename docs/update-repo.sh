#!/bin/bash
# Update apt repository metadata
# Usage: ./update-repo.sh

set -e

cd "$(dirname "$0")"

echo "Updating apt repository..."
echo ""

# Generate Packages files
echo "Generating Packages files..."
dpkg-scanpackages pool/ /dev/null > Packages
gzip -9c Packages > Packages.gz
echo "✓ Packages files generated"
echo ""

# Update Release file timestamp
echo "Updating Release file..."
sed -i "s/^Date:.*/Date: $(date -u '+%a, %d %b %Y %H:%M:%S UTC')/" Release
echo "✓ Release file updated"
echo ""

# Sign Release file with GPG
echo "Signing Release file with GPG..."
rm -f Release.gpg InRelease
gpg --default-key "Silver Linings, LLC" --armor --detach-sign --output Release.gpg Release
gpg --default-key "Silver Linings, LLC" --armor --clearsign --output InRelease Release
echo "✓ Release file signed"
echo ""

# Show stats
PACKAGE_COUNT=$(grep -c '^Package:' Packages || echo "0")
echo "Repository contains $PACKAGE_COUNT package(s)"
echo ""

# List packages
if [ "$PACKAGE_COUNT" -gt 0 ]; then
    echo "Packages in repository:"
    grep -E '^(Package|Version|Architecture):' Packages | paste -d' ' - - - | sed 's/Package: /  - /; s/ Version: / v/; s/ Architecture: / (/'  | sed 's/$/)/'
    echo ""
fi

echo "✓ Repository updated successfully"
echo ""
echo "To serve this repository:"
echo "  Option 1 (Python): python3 -m http.server 8080"
echo "  Option 2 (nginx): Copy to /var/www/html/apt/"
echo ""
