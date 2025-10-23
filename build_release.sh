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
  # "x86_64-unknown-linux-gnu"
  "x86_64-unknown-linux-musl"
  
  # AArch64 (ARM64) architecture
  # "aarch64-unknown-linux-gnu"
  "aarch64-unknown-linux-musl"
  
  # ARM 32-bit architecture
  # "armv7-unknown-linux-gnueabihf"
  "armv7-unknown-linux-musleabihf"
  "armv7-unknown-linux-musleabi"
  # "armv7-unknown-linux-gnueabi"
  # "armv5te-unknown-linux-gnueabi"
  "armv5te-unknown-linux-musleabi"
  "arm-unknown-linux-musleabi"
  "arm-unknown-linux-musleabihf"
  # "arm-unknown-linux-gnueabi"
  # "arm-unknown-linux-gnueabihf"
  
  # RISC-V architecture (emerging open source architecture)
  # "riscv64gc-unknown-linux-gnu"
  "riscv64gc-unknown-linux-musl"
  
  # PowerPC architecture (some high-end routers)
  # "powerpc64-unknown-linux-gnu"
  # "powerpc64le-unknown-linux-gnu"
  "powerpc64le-unknown-linux-musl"

)

# Install target platforms
for TARGET in "${TARGETS[@]}"; do
  echo "Installing target platform: $TARGET"
  rustup target add $TARGET
done


# Build statistics
SUCCESS_COUNT=0
FAILED_COUNT=0
FAILED_TARGETS=()

echo "Starting build for all target platforms..."
echo "========================================"

# Build for each target platform
for TARGET in "${TARGETS[@]}"; do
  echo ""
  echo "Starting build for $TARGET..."
  
  # Build release version
  if cargo build --release --target "$TARGET" 2>/dev/null; then
    echo "✓ Build successful: $TARGET"
    
    # Create release package directory
    TARGET_DIR="$RELEASE_DIR/bandix-$VERSION-$TARGET"
    mkdir -p $TARGET_DIR
    
    # Copy binary file
    if [ -f "target/$TARGET/release/bandix" ]; then
      cp "target/$TARGET/release/bandix" $TARGET_DIR/
      
      # Copy other necessary files
      cp LICENSE $TARGET_DIR/ 2>/dev/null || echo "⚠ Warning: LICENSE file does not exist"
      cp README.md $TARGET_DIR/ 2>/dev/null || echo "⚠ Warning: README.md file does not exist"
      
      # Create compressed package
      echo "Creating compressed package..."
      tar -czvf "$RELEASE_DIR/bandix-$VERSION-$TARGET.tar.gz" -C $RELEASE_DIR "bandix-$VERSION-$TARGET" > /dev/null
      
      # Clean up temporary files
      rm -rf $TARGET_DIR
      
      echo "✓ Completed $TARGET build and packaging"
      SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
      echo "✗ Binary file does not exist: target/$TARGET/release/bandix"
      FAILED_COUNT=$((FAILED_COUNT + 1))
      FAILED_TARGETS+=("$TARGET")
    fi
  else
    echo "✗ cargo build failed, trying cargo zigbuild..."
    if cargo zigbuild --release --target "$TARGET" 2>/dev/null; then
      echo "✓ zigbuild successful: $TARGET"
      
      # Create release package directory
      TARGET_DIR="$RELEASE_DIR/bandix-$VERSION-$TARGET"
      mkdir -p $TARGET_DIR
      
      # Copy binary file
      if [ -f "target/$TARGET/release/bandix" ]; then
        cp "target/$TARGET/release/bandix" $TARGET_DIR/
        
        # Copy other necessary files
        cp LICENSE $TARGET_DIR/ 2>/dev/null || echo "⚠ Warning: LICENSE file does not exist"
        cp README.md $TARGET_DIR/ 2>/dev/null || echo "⚠ Warning: README.md file does not exist"
        
        # Create compressed package
        echo "Creating compressed package..."
        tar -czvf "$RELEASE_DIR/bandix-$VERSION-$TARGET.tar.gz" -C $RELEASE_DIR "bandix-$VERSION-$TARGET" > /dev/null
        
        # Clean up temporary files
        rm -rf $TARGET_DIR
        
        echo "✓ Completed $TARGET build and packaging"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
      else
        echo "✗ Binary file does not exist after zigbuild: target/$TARGET/release/bandix"
        FAILED_COUNT=$((FAILED_COUNT + 1))
        FAILED_TARGETS+=("$TARGET")
      fi
    else
      echo "✗ Both cargo build and zigbuild failed: $TARGET"
      FAILED_COUNT=$((FAILED_COUNT + 1))
      FAILED_TARGETS+=("$TARGET")
    fi
  fi
  
  echo "----------------------------------------"
done

echo ""
echo "Build completion summary:"
echo "========================================"
echo "✓ Successfully built: $SUCCESS_COUNT targets"
if [ $FAILED_COUNT -gt 0 ]; then
  echo "✗ Failed builds: $FAILED_COUNT targets"
  echo "Failed targets:"
  for target in "${FAILED_TARGETS[@]}"; do
    echo "  - $target"
  done
fi

echo ""
echo "Release packages located in $RELEASE_DIR directory"
if [ $SUCCESS_COUNT -gt 0 ]; then
  echo "Generated files:"
  ls -la $RELEASE_DIR/*.tar.gz 2>/dev/null | sed 's/^/  /' || echo "  No compressed packages generated"
fi

# Display disk usage
echo "Disk usage:"
du -sh $RELEASE_DIR 2>/dev/null | sed 's/^/  Total size: /'

if [ $FAILED_COUNT -eq 0 ]; then
  echo "🎉 All platforms built successfully!"
  exit 0
else
  echo "⚠ Some platforms failed to build, please check error messages"
  exit 1
fi 