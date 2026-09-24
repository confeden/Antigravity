#!/usr/bin/env bash
# Packages Antigravity Unlocker for Linux release into .tar.gz archives.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="$ROOT_DIR/dist"

VERSION=$(grep -m1 '^version = ' "$ROOT_DIR/Cargo.toml" | cut -d'"' -f2)
echo "==> Packaging Antigravity Unlocker v${VERSION} for Linux (x86_64)..."

echo "==> Building release binary with cargo..."
cargo build --release

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

STAGE_DIR="$DIST_DIR/antigravity-unlocker-linux-x86_64"
ARCHIVE_NAME="antigravity-unlocker-linux-x86_64.tar.gz"

echo "==> Preparing release payload..."
mkdir -p "$STAGE_DIR"
cp "$ROOT_DIR/target/release/ag_unlocker" "$STAGE_DIR/ag_unlocker"
cp "$ROOT_DIR/linux/install.sh" "$STAGE_DIR/install.sh"
if [ -f "$ROOT_DIR/linux/uninstall.sh" ]; then
    cp "$ROOT_DIR/linux/uninstall.sh" "$STAGE_DIR/uninstall.sh"
fi
cp "$ROOT_DIR/linux/launch.sh" "$STAGE_DIR/launch.sh"
cp "$ROOT_DIR/linux/Antigravity-Unlocker.desktop" "$STAGE_DIR/Antigravity-Unlocker.desktop"
cp "$ROOT_DIR/linux/README.md" "$STAGE_DIR/README.md"
if [ -f "$ROOT_DIR/linux/icon.png" ]; then
    cp "$ROOT_DIR/linux/icon.png" "$STAGE_DIR/icon.png"
fi
chmod +x "$STAGE_DIR/ag_unlocker" "$STAGE_DIR/install.sh" "$STAGE_DIR/launch.sh"
if [ -f "$STAGE_DIR/uninstall.sh" ]; then
    chmod +x "$STAGE_DIR/uninstall.sh"
fi

echo "==> Packaging $ARCHIVE_NAME..."
tar -czf "$DIST_DIR/$ARCHIVE_NAME" -C "$DIST_DIR" "antigravity-unlocker-linux-x86_64"

# Standalone binary
cp "$ROOT_DIR/target/release/ag_unlocker" "$DIST_DIR/ag_unlocker"

echo
echo "✓ Release bundles created in $DIST_DIR:"
ls -lh "$DIST_DIR"/*.tar.gz "$DIST_DIR/ag_unlocker"
echo
sha256sum "$DIST_DIR"/*.tar.gz "$DIST_DIR/ag_unlocker"
