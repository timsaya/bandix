#!/bin/bash
set -e

source ~/.cargo/env

# 强制使用指定目录下的交叉编译器，避免误用系统 linker
MUSL_CROSS_DIR="${MUSL_CROSS_DIR:-$HOME/musl-cross}"
set_linker_env() {
  local var_name="$1"
  local rel_path="$2"
  local linker_path="$MUSL_CROSS_DIR/$rel_path"

  if [ ! -x "$linker_path" ]; then
    echo "✗ Missing linker: $linker_path"
    echo "  Please set MUSL_CROSS_DIR correctly or install toolchains first."
    exit 1
  fi

  export "$var_name=$linker_path"
}

set_linker_env "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER" "x86_64-linux-musl-cross/bin/x86_64-linux-musl-gcc"
set_linker_env "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER" "aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc"
set_linker_env "CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER" "arm-linux-musleabihf-cross/bin/arm-linux-musleabihf-gcc"
set_linker_env "CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABI_LINKER" "arm-linux-musleabi-cross/bin/arm-linux-musleabi-gcc"
set_linker_env "CARGO_TARGET_ARMV5TE_UNKNOWN_LINUX_MUSLEABI_LINKER" "arm-linux-musleabi-cross/bin/arm-linux-musleabi-gcc"
set_linker_env "CARGO_TARGET_ARM_UNKNOWN_LINUX_MUSLEABI_LINKER" "arm-linux-musleabi-cross/bin/arm-linux-musleabi-gcc"
set_linker_env "CARGO_TARGET_ARM_UNKNOWN_LINUX_MUSLEABIHF_LINKER" "arm-linux-musleabihf-cross/bin/arm-linux-musleabihf-gcc"
set_linker_env "CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_MUSL_LINKER" "riscv64-linux-musl-cross/bin/riscv64-linux-musl-gcc"
set_linker_env "CARGO_TARGET_POWERPC64LE_UNKNOWN_LINUX_MUSL_LINKER" "powerpc64le-linux-musl-cross/bin/powerpc64le-linux-musl-gcc"
set_linker_env "CARGO_TARGET_MIPS_UNKNOWN_LINUX_MUSL_LINKER" "mips-linux-musl-cross/bin/mips-linux-musl-gcc"
set_linker_env "CARGO_TARGET_MIPSEL_UNKNOWN_LINUX_MUSL_LINKER" "mipsel-linux-musl-cross/bin/mipsel-linux-musl-gcc"

# 定义版本号（从 Cargo.toml 获取或手动指定）
VERSION=$(grep "^version" bandix/Cargo.toml | cut -d '"' -f2)
echo "Build version: $VERSION"

# 确保 release 目录存在
RELEASE_DIR="release"
mkdir -p $RELEASE_DIR


# 构建目标平台列表
DEFAULT_TARGETS=(
  # x86_64 架构
  "x86_64-unknown-linux-musl"
  
  # AArch64 (ARM64) 架构
  "aarch64-unknown-linux-musl"
  
  # ARM 32 位架构
  "armv7-unknown-linux-musleabihf"
  "armv7-unknown-linux-musleabi"
  "armv5te-unknown-linux-musleabi"
  "arm-unknown-linux-musleabi"
  "arm-unknown-linux-musleabihf"
  
  # RISC-V 架构（新兴开源架构）
  "riscv64gc-unknown-linux-musl"

  # PowerPC 架构（部分高端路由器）
  "powerpc64le-unknown-linux-musl"
)

MIPS_TARGETS=(
  # MIPS 32 位架构（使用 nightly + build-std 构建）
  "mips-unknown-linux-musl"
  "mipsel-unknown-linux-musl"
)

print_linker_for_target() {
  local target="$1"
  local env_key="CARGO_TARGET_${target//-/_}_LINKER"
  env_key="${env_key^^}"
  local linker="${!env_key:-}"

  if [ -n "$linker" ]; then
    echo "Linker for $target: $linker"
  else
    echo "⚠ Linker env not set for $target ($env_key)"
  fi
}

# 打包构建产物的辅助函数
package_target() {
  local TARGET="$1"
  local TARGET_DIR="$RELEASE_DIR/bandix-$VERSION-$TARGET"
  local BINARY_PATH="target/$TARGET/release/bandix"

  if [ -f "$BINARY_PATH" ]; then
    mkdir -p "$TARGET_DIR"
    cp "$BINARY_PATH" "$TARGET_DIR/"
    cp LICENSE "$TARGET_DIR/" 2>/dev/null || echo "⚠ Warning: LICENSE file does not exist"
    cp README.md "$TARGET_DIR/" 2>/dev/null || echo "⚠ Warning: README.md file does not exist"

    echo "Creating compressed package..."
    tar -czvf "$RELEASE_DIR/bandix-$VERSION-$TARGET.tar.gz" -C "$RELEASE_DIR" "bandix-$VERSION-$TARGET" > /dev/null
    rm -rf "$TARGET_DIR"

    echo "✓ Completed $TARGET build and packaging"
    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    return 0
  else
    echo "✗ Binary file does not exist: $BINARY_PATH"
    FAILED_COUNT=$((FAILED_COUNT + 1))
    FAILED_TARGETS+=("$TARGET")
    return 1
  fi
}

# 构建统计
SUCCESS_COUNT=0
FAILED_COUNT=0
FAILED_TARGETS=()

echo "Starting build for all target platforms..."
echo "========================================"

# 为每个默认目标平台构建
for TARGET in "${DEFAULT_TARGETS[@]}"; do
  echo ""
  echo "Starting build for $TARGET..."
  print_linker_for_target "$TARGET"
  
  # 构建 release 版本
  if cargo build -q --release --target "$TARGET"; then
    echo "✓ Build successful: $TARGET"
    package_target "$TARGET"
  else
    echo "✗ cargo build failed: $TARGET"
    FAILED_COUNT=$((FAILED_COUNT + 1))
    FAILED_TARGETS+=("$TARGET")
  fi
  
  echo "----------------------------------------"
done

# 为每个 MIPS 目标平台构建（nightly + build-std）
for TARGET in "${MIPS_TARGETS[@]}"; do
  echo ""
  echo "Starting build for $TARGET (nightly + build-std)..."
  print_linker_for_target "$TARGET"

  if cargo +nightly build -q -Z build-std --release --target "$TARGET"; then
    echo "✓ Build successful (nightly build-std): $TARGET"
    package_target "$TARGET"
  else
    echo "✗ cargo +nightly -Z build-std failed: $TARGET"
    FAILED_COUNT=$((FAILED_COUNT + 1))
    FAILED_TARGETS+=("$TARGET")
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

# 显示磁盘使用情况
echo "Disk usage:"
du -sh $RELEASE_DIR 2>/dev/null | sed 's/^/  Total size: /'

if [ $FAILED_COUNT -eq 0 ]; then
  echo "🎉 All platforms built successfully!"
  exit 0
else
  echo "⚠ Some platforms failed to build, please check error messages"
  exit 1
fi 
