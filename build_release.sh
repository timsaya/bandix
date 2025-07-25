#!/bin/bash
set -e

# 定义版本号（从Cargo.toml获取或手动指定）
VERSION=$(grep "^version" bandix/Cargo.toml | cut -d '"' -f2)
echo "构建版本: $VERSION"

# 确保目标目录存在
RELEASE_DIR="release"
mkdir -p $RELEASE_DIR

# 确保安装了必要的工具
echo "正在检查和安装必要的工具..."

# 检查和安装 bpf-linker
if ! command -v bpf-linker &> /dev/null; then
    echo "正在安装 bpf-linker..."
    cargo install bpf-linker
fi

# 构建目标平台列表
TARGETS=(
  "x86_64-unknown-linux-gnu"
  "x86_64-unknown-linux-musl"
  "aarch64-unknown-linux-gnu"
  "aarch64-unknown-linux-musl"
  "armv7-unknown-linux-gnueabihf"
  "armv7-unknown-linux-musleabihf"
  "armv5te-unknown-linux-gnueabi"
  "armv5te-unknown-linux-musleabi"
)

# 安装目标平台
for TARGET in "${TARGETS[@]}"; do
  echo "安装目标平台: $TARGET"
  rustup target add $TARGET
done


# 为每个目标平台构建
for TARGET in "${TARGETS[@]}"; do
  echo "开始为 $TARGET 构建..."
  
  # 构建发布版本
  cargo build --release --target $TARGET
  
  # 创建发布包目录
  TARGET_DIR="$RELEASE_DIR/bandix-$VERSION-$TARGET"
  mkdir -p $TARGET_DIR
  
  # 复制二进制文件
  cp "target/$TARGET/release/bandix" $TARGET_DIR/
  
  # 复制其他必要文件
  cp LICENSE $TARGET_DIR/
  cp README.md $TARGET_DIR/
  
  # 创建压缩包
  echo "创建压缩包..."
  tar -czvf "$RELEASE_DIR/bandix-$VERSION-$TARGET.tar.gz" -C $RELEASE_DIR "bandix-$VERSION-$TARGET"
  
  # 清理临时文件
  rm -rf $TARGET_DIR
  
  echo "完成 $TARGET 构建"
done

echo "所有平台构建完成！"
echo "发布包位于 $RELEASE_DIR 目录" 