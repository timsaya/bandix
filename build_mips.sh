#!/bin/bash
set -e

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored information
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Define version number (get from Cargo.toml or specify manually)
VERSION=$(grep "^version" bandix/Cargo.toml | cut -d '"' -f2)
print_info "Build version: $VERSION"

# Ensure target directory exists
RELEASE_DIR="release/mips"
mkdir -p $RELEASE_DIR

print_info "Starting build for MIPS series architectures..."

# Ensure necessary tools are installed
print_info "Checking and installing necessary tools..."

# Check and install bpf-linker
if ! command -v bpf-linker &> /dev/null; then
    print_info "Installing bpf-linker..."
    cargo install bpf-linker
fi

# Check nightly toolchain
if ! rustup toolchain list | grep -q "nightly"; then
    print_info "Installing nightly toolchain..."
    rustup toolchain install nightly
fi

# Check rust-src component
if ! rustup component list --toolchain nightly | grep -q "rust-src (installed)"; then
    print_info "Installing rust-src component..."
    rustup component add rust-src --toolchain nightly
fi

# MIPS architecture target platform list
MIPS_TARGETS=(
    # MIPS 32-bit big-endian
    "mips-unknown-linux-gnu"
    "mips-unknown-linux-musl"
    
    # MIPS 32-bit little-endian (MIPSEL)
    "mipsel-unknown-linux-gnu"
    "mipsel-unknown-linux-musl"
)

# Use cargo nightly + build-std, no cross-compilation toolchain needed
print_info "Using cargo nightly + build-std mode, no additional cross-compilation toolchain needed..."

# Note: When using -Z build-std, no need to pre-install target platforms
# Standard library will be compiled from source
print_info "Using build-std mode, will compile standard library from source..."

# Build statistics
SUCCESS_COUNT=0
FAILED_COUNT=0
FAILED_TARGETS=()

print_info "Starting build for all MIPS architectures..."
echo "========================================"

# Build for each target platform
for TARGET in "${MIPS_TARGETS[@]}"; do
    echo ""
    print_info "Starting build for $TARGET..."
    
    # Build release version (using nightly toolchain and build-std)
    print_info "Attempting build with cargo +nightly build -Z build-std..."
    if cargo +nightly build -Z build-std --release --target "$TARGET" 2>/dev/null; then
        print_success "Build successful: $TARGET"
        
        # Create release package directory
        TARGET_DIR="$RELEASE_DIR/bandix-$VERSION-$TARGET"
        mkdir -p $TARGET_DIR
        
        # Copy binary file
        if [ -f "target/$TARGET/release/bandix" ]; then
            cp "target/$TARGET/release/bandix" $TARGET_DIR/
            
            # Copy other necessary files
            cp LICENSE $TARGET_DIR/ 2>/dev/null || print_warning "LICENSE file does not exist"
            cp README.md $TARGET_DIR/ 2>/dev/null || print_warning "README.md file does not exist"
            
            # Display binary file information
            print_info "Binary file information:"
            file "target/$TARGET/release/bandix" | sed 's/^/  /'
            
            # Create compressed package
            print_info "Creating compressed package..."
            tar -czvf "$RELEASE_DIR/bandix-$VERSION-$TARGET.tar.gz" -C $RELEASE_DIR "bandix-$VERSION-$TARGET" > /dev/null
            
            # Clean up temporary files
            rm -rf $TARGET_DIR
            
            print_success "Completed $TARGET build and packaging"
            SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        else
            print_error "Binary file does not exist: target/$TARGET/release/bandix"
            print_error "Build may have succeeded but binary was not generated"
            FAILED_COUNT=$((FAILED_COUNT + 1))
            FAILED_TARGETS+=("$TARGET")
        fi
    else
        print_error "cargo +nightly build failed, trying alternative build methods..."
        
        # Try with regular cargo build
        print_info "Trying regular cargo build..."
        if cargo build --release --target "$TARGET" 2>/dev/null; then
            print_success "Regular cargo build successful: $TARGET"
            
            # Create release package directory
            TARGET_DIR="$RELEASE_DIR/bandix-$VERSION-$TARGET"
            mkdir -p $TARGET_DIR
            
            # Copy binary file
            if [ -f "target/$TARGET/release/bandix" ]; then
                cp "target/$TARGET/release/bandix" $TARGET_DIR/
                
                # Copy other necessary files
                cp LICENSE $TARGET_DIR/ 2>/dev/null || print_warning "LICENSE file does not exist"
                cp README.md $TARGET_DIR/ 2>/dev/null || print_warning "README.md file does not exist"
                
                # Display binary file information
                print_info "Binary file information:"
                file "target/$TARGET/release/bandix" | sed 's/^/  /'
                
                # Create compressed package
                print_info "Creating compressed package..."
                tar -czvf "$RELEASE_DIR/bandix-$VERSION-$TARGET.tar.gz" -C $RELEASE_DIR "bandix-$VERSION-$TARGET" > /dev/null
                
                # Clean up temporary files
                rm -rf $TARGET_DIR
                
                print_success "Completed $TARGET build and packaging"
                SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
            else
                print_error "Binary file does not exist after regular cargo build: target/$TARGET/release/bandix"
                FAILED_COUNT=$((FAILED_COUNT + 1))
                FAILED_TARGETS+=("$TARGET")
            fi
        else
            print_error "All build methods failed: $TARGET"
            print_error "This target may not be supported or requires additional dependencies"
            FAILED_COUNT=$((FAILED_COUNT + 1))
            FAILED_TARGETS+=("$TARGET")
        fi
    fi
    
    echo "----------------------------------------"
done

echo ""
print_info "Build completion summary:"
echo "========================================"
print_success "Successfully built: $SUCCESS_COUNT targets"
if [ $FAILED_COUNT -gt 0 ]; then
    print_error "Failed builds: $FAILED_COUNT targets"
    print_info "Failed targets:"
    for target in "${FAILED_TARGETS[@]}"; do
        echo "  - $target"
    done
fi

echo ""
print_info "Release packages located in: $RELEASE_DIR directory"
if [ $SUCCESS_COUNT -gt 0 ]; then
    print_info "Generated files:"
    ls -la $RELEASE_DIR/*.tar.gz 2>/dev/null | sed 's/^/  /' || print_info "No compressed packages generated"
fi

# Display disk usage
print_info "Disk usage:"
du -sh $RELEASE_DIR 2>/dev/null | sed 's/^/  Total size: /'

if [ $FAILED_COUNT -eq 0 ]; then
    print_success "All MIPS platforms built successfully! 🎉"
    exit 0
else
    print_warning "Some platforms failed to build, please check error messages"
    exit 1
fi
