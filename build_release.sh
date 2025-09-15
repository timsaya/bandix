#!/bin/bash
set -e

# Define version number (get from Cargo.toml or specify manually)
VERSION=$(grep "^version" bandix/Cargo.toml | cut -d '"' -f2)
echo "Build version: $VERSION"

# Ensure target directory exists
RELEASE_DIR="release"
mkdir -p $RELEASE_DIR

# Ensure necessary tools are installed
echo "Checking and installing necessary tools..."

# Check and install bpf-linker
if ! command -v bpf-linker &> /dev/null; then
    echo "Installing bpf-linker..."
    cargo install bpf-linker
fi

# Build target platform list
TARGETS=(
  # x86_64 architecture
  "x86_64-unknown-linux-gnu"
  "x86_64-unknown-linux-musl"
  
  # AArch64 (ARM64) architecture
  "aarch64-unknown-linux-gnu"
  "aarch64-unknown-linux-musl"
  
  # ARM 32-bit architecture
  "armv7-unknown-linux-gnueabihf"
  "armv7-unknown-linux-musleabihf"
  "armv7-unknown-linux-musleabi"
  "armv7-unknown-linux-gnueabi"
  "armv5te-unknown-linux-gnueabi"
  "armv5te-unknown-linux-musleabi"
  "arm-unknown-linux-musleabi"
  "arm-unknown-linux-musleabihf"
  "arm-unknown-linux-gnueabi"
  "arm-unknown-linux-gnueabihf"
  
  # RISC-V architecture (emerging open source architecture)
  "riscv64gc-unknown-linux-gnu"
  "riscv64gc-unknown-linux-musl"
  
  # PowerPC architecture (some high-end routers)
  "powerpc64-unknown-linux-gnu"
  "powerpc64le-unknown-linux-gnu"
  "powerpc64le-unknown-linux-musl"

)

# Install target platforms
for TARGET in "${TARGETS[@]}"; do
  echo "Installing target platform: $TARGET"
  rustup target add $TARGET
done


# Build for each target platform
for TARGET in "${TARGETS[@]}"; do
  echo "Starting build for $TARGET..."
  
  # Build release version
  if ! cargo build --release --target "$TARGET"; then
    echo "cargo build failed, trying cargo zigbuild ..."
    cargo zigbuild --release --target "$TARGET"
  fi
  
  # Create release package directory
  TARGET_DIR="$RELEASE_DIR/bandix-$VERSION-$TARGET"
  mkdir -p $TARGET_DIR
  
  # Copy binary file
  cp "target/$TARGET/release/bandix" $TARGET_DIR/
  
  # Copy other necessary files
  cp LICENSE $TARGET_DIR/
  cp README.md $TARGET_DIR/
  
  # Create compressed package
  echo "Creating compressed package..."
  tar -czvf "$RELEASE_DIR/bandix-$VERSION-$TARGET.tar.gz" -C $RELEASE_DIR "bandix-$VERSION-$TARGET"
  
  # Clean up temporary files
  rm -rf $TARGET_DIR
  
  echo "Completed $TARGET build"
done

echo "All platform builds completed!"
echo "Release packages located in $RELEASE_DIR directory" 