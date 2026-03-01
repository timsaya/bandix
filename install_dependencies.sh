#!/bin/bash
# 安装所有交叉编译工具链及依赖
# 使用方法: ./install_cross_toolchains.sh

set -e

INSTALL_BASE="/opt/musl-cross"
MUSL_CC_BASE="https://github.com/timsaya/musl-cc/releases/download/v0.1.0/"
PACKAGE_MANAGER=""

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "安装交叉编译工具链"
echo "安装目录: $INSTALL_BASE"
echo "=========================================="

# 定义需要安装的工具链
# 格式: "工具链名称:链接器名称"
declare -A TOOLCHAINS=(
    ["arm-linux-musleabihf-cross"]="arm-linux-musleabihf-gcc"
    ["arm-linux-musleabi-cross"]="arm-linux-musleabi-gcc"
    ["aarch64-linux-musl-cross"]="aarch64-linux-musl-gcc"
    ["riscv64-linux-musl-cross"]="riscv64-linux-musl-gcc"
    ["powerpc64le-linux-musl-cross"]="powerpc64le-linux-musl-gcc"
    ["mips-linux-musl-cross"]="mips-linux-musl-gcc"
    ["mipsel-linux-musl-cross"]="mipsel-linux-musl-gcc"
    ["x86_64-linux-musl-cross"]="x86_64-linux-musl-gcc"
)

# 选择包管理器
detect_package_manager() {
    if command -v apt-get &> /dev/null; then
        PACKAGE_MANAGER="apt"
    elif command -v yum &> /dev/null; then
        PACKAGE_MANAGER="yum"
    elif command -v dnf &> /dev/null; then
        PACKAGE_MANAGER="dnf"
    elif command -v pacman &> /dev/null; then
        PACKAGE_MANAGER="pacman"
    else
        PACKAGE_MANAGER=""
    fi
}

install_system_packages() {
    case "$PACKAGE_MANAGER" in
        apt)
            apt-get update
            apt-get install -y build-essential curl tar gzip xz-utils pkg-config gcc file wget
            ;;
        *)
            echo -e "${RED}错误: 未能识别的包管理器，仅支持 Ubuntu/Debian 编译环境"
            exit 1
            ;;
    esac
}

echo ""
echo -e "${YELLOW}[1/4] 安装系统依赖 (gcc/curl 等)...${NC}"
detect_package_manager
install_system_packages

# 创建安装目录
mkdir -p "$INSTALL_BASE"
chown "$(whoami)":"$(whoami)" "$INSTALL_BASE" 2>/dev/null || true

# 安装 Rust 工具链
echo ""
echo -e "${YELLOW}[2/4] 安装 Rust 工具链...${NC}"
if ! command -v rustup &> /dev/null; then
    echo "安装 rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi

if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1090
    source "$HOME/.cargo/env"
fi
export PATH="$HOME/.cargo/bin:$PATH"

echo "安装 Rust 1.91.1 工具链..."
rustup toolchain install 1.91.1-x86_64-unknown-linux-gnu

echo "设置默认工具链为 1.91.1..."
rustup default 1.91.1-x86_64-unknown-linux-gnu

echo "安装/更新 nightly 工具链..."
rustup toolchain install nightly

echo "添加 rust-src 组件 (nightly)..."
rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu

echo "安装 bpf-linker (v0.10.1) ..."
cargo install bpf-linker@0.10.1

RUST_TARGETS=(
    "x86_64-unknown-linux-musl"
    "aarch64-unknown-linux-musl"
    "armv7-unknown-linux-musleabihf"
    "armv7-unknown-linux-musleabi"
    "armv5te-unknown-linux-musleabi"
    "arm-unknown-linux-musleabi"
    "arm-unknown-linux-musleabihf"
    "riscv64gc-unknown-linux-musl"
    "powerpc64le-unknown-linux-musl"
)

echo "安装/更新 Rust 交叉目标..."
for TARGET in "${RUST_TARGETS[@]}"; do
    echo "  rustup target add $TARGET"
    rustup target add "$TARGET"
done

# 安装每个工具链
echo ""
echo -e "${YELLOW}[3/4] 下载并安装交叉工具链...${NC}"
INSTALLED_COUNT=0
SKIPPED_COUNT=0

for toolchain_name in "${!TOOLCHAINS[@]}"; do
    linker_name="${TOOLCHAINS[$toolchain_name]}"
    install_dir="$INSTALL_BASE/$toolchain_name"
    download_url="$MUSL_CC_BASE/$toolchain_name.tgz"
    
    echo -n "  检查 $toolchain_name ... "
    
    # 检查工具链是否已完整安装（检查目录和链接器都存在）
    if [ -d "$install_dir" ] && [ -f "$install_dir/bin/$linker_name" ] && [ -x "$install_dir/bin/$linker_name" ]; then
        echo -e "${GREEN}已存在，跳过${NC}"
        SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
        continue
    fi
    
    # 如果目录存在但链接器不存在，可能是损坏的安装，先清理
    if [ -d "$install_dir" ]; then
        echo -n "清理损坏的安装... "
        rm -rf "$install_dir"
    fi
    
    # 下载并安装
    echo "下载并安装..."
    cd /tmp
    if curl -L -o "${toolchain_name}.tgz" "$download_url" && [ -f "${toolchain_name}.tgz" ] && [ -s "${toolchain_name}.tgz" ]; then
        tar -xzf "${toolchain_name}.tgz" -C "$INSTALL_BASE"
        rm -f "${toolchain_name}.tgz"
        
        # 验证安装
        if [ -d "$install_dir" ] && [ -f "$install_dir/bin/$linker_name" ] && [ -x "$install_dir/bin/$linker_name" ]; then
            echo -e "${GREEN}成功${NC}"
            INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
        else
            echo -e "${RED}失败 (安装后验证失败)${NC}"
        fi
    else
        echo -e "${RED}失败 (下载或解压错误)${NC}"
    fi
done

# 验证所有工具链
echo ""
echo -e "${YELLOW}[4/4] 验证安装...${NC}"
for toolchain_name in "${!TOOLCHAINS[@]}"; do
    linker_name="${TOOLCHAINS[$toolchain_name]}"
    install_dir="$INSTALL_BASE/$toolchain_name"
    
    if [ -d "$install_dir" ] && [ -f "$install_dir/bin/$linker_name" ] && [ -x "$install_dir/bin/$linker_name" ]; then
        version=$("$install_dir/bin/$linker_name" --version 2>&1 | head -1 || echo "无法获取版本")
        echo -e "  ${GREEN}✓${NC} $linker_name: $version"
    else
        echo -e "  ${RED}✗${NC} $linker_name: 未安装或损坏"
    fi
done

source ~/.cargo/env

# 总结
echo ""
echo "=========================================="
echo "安装完成"
echo "=========================================="
echo "新安装: $INSTALLED_COUNT"
echo "已存在: $SKIPPED_COUNT"
echo "总计: ${#TOOLCHAINS[@]}"
echo ""
echo "工具链位置: $INSTALL_BASE"
echo ""

