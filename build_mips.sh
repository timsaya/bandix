#!/bin/bash
set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 打印带颜色的信息
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

# 定义版本号（从Cargo.toml获取或手动指定）
VERSION=$(grep "^version" bandix/Cargo.toml | cut -d '"' -f2)
print_info "构建版本: $VERSION"

# 确保目标目录存在
RELEASE_DIR="release/mips"
mkdir -p $RELEASE_DIR

print_info "开始构建 MIPS 系列架构..."

# 确保安装了必要的工具
print_info "正在检查和安装必要的工具..."

# 检查和安装 bpf-linker
if ! command -v bpf-linker &> /dev/null; then
    print_info "正在安装 bpf-linker..."
    cargo install bpf-linker
fi

# 检查 nightly 工具链
if ! rustup toolchain list | grep -q "nightly"; then
    print_info "正在安装 nightly 工具链..."
    rustup toolchain install nightly
fi

# 检查 rust-src 组件
if ! rustup component list --toolchain nightly | grep -q "rust-src (installed)"; then
    print_info "正在安装 rust-src 组件..."
    rustup component add rust-src --toolchain nightly
fi

# MIPS 架构目标平台列表
MIPS_TARGETS=(
    # MIPS 32位 大端序
    "mips-unknown-linux-gnu"
    "mips-unknown-linux-musl"
    
    # MIPS 32位 小端序 (MIPSEL)
    "mipsel-unknown-linux-gnu"
    "mipsel-unknown-linux-musl"
)

# 使用 cargo nightly + build-std，无需交叉编译工具链
print_info "使用 cargo nightly + build-std 模式，无需额外交叉编译工具链..."

# 注意: 使用 -Z build-std 时不需要预安装目标平台
# 标准库将从源码编译
print_info "使用 build-std 模式，将从源码编译标准库..."

# 构建统计
SUCCESS_COUNT=0
FAILED_COUNT=0
FAILED_TARGETS=()

print_info "开始构建所有 MIPS 架构..."
echo "========================================"

# 为每个目标平台构建
for TARGET in "${MIPS_TARGETS[@]}"; do
    echo ""
    print_info "开始为 $TARGET 构建..."
    
    # 构建发布版本（使用 nightly 工具链和 build-std）
    if cargo +nightly build -Z build-std --release --target "$TARGET"; then
        print_success "构建成功: $TARGET"
        
        # 创建发布包目录
        TARGET_DIR="$RELEASE_DIR/bandix-$VERSION-$TARGET"
        mkdir -p $TARGET_DIR
        
        # 复制二进制文件
        if [ -f "target/$TARGET/release/bandix" ]; then
            cp "target/$TARGET/release/bandix" $TARGET_DIR/
            
            # 复制其他必要文件
            cp LICENSE $TARGET_DIR/ 2>/dev/null || print_warning "LICENSE 文件不存在"
            cp README.md $TARGET_DIR/ 2>/dev/null || print_warning "README.md 文件不存在"
            
            # 显示二进制文件信息
            print_info "二进制文件信息:"
            file "target/$TARGET/release/bandix" | sed 's/^/  /'
            
            # 创建压缩包
            print_info "创建压缩包..."
            tar -czvf "$RELEASE_DIR/bandix-$VERSION-$TARGET.tar.gz" -C $RELEASE_DIR "bandix-$VERSION-$TARGET" > /dev/null
            
            # 清理临时文件
            rm -rf $TARGET_DIR
            
            print_success "完成 $TARGET 构建和打包"
            SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        else
            print_error "二进制文件不存在: target/$TARGET/release/bandix"
            FAILED_COUNT=$((FAILED_COUNT + 1))
            FAILED_TARGETS+=("$TARGET")
        fi
    else
        print_error "构建失败: $TARGET"
        FAILED_COUNT=$((FAILED_COUNT + 1))
        FAILED_TARGETS+=("$TARGET")
    fi
    
    echo "----------------------------------------"
done

echo ""
print_info "构建完成总结:"
echo "========================================"
print_success "成功构建: $SUCCESS_COUNT 个目标"
if [ $FAILED_COUNT -gt 0 ]; then
    print_error "失败构建: $FAILED_COUNT 个目标"
    print_info "失败的目标:"
    for target in "${FAILED_TARGETS[@]}"; do
        echo "  - $target"
    done
fi

echo ""
print_info "发布包位于: $RELEASE_DIR 目录"
if [ $SUCCESS_COUNT -gt 0 ]; then
    print_info "生成的文件:"
    ls -la $RELEASE_DIR/*.tar.gz 2>/dev/null | sed 's/^/  /' || print_info "没有生成压缩包"
fi

# 显示磁盘使用情况
print_info "磁盘使用情况:"
du -sh $RELEASE_DIR 2>/dev/null | sed 's/^/  总大小: /'

if [ $FAILED_COUNT -eq 0 ]; then
    print_success "所有 MIPS 平台构建成功！🎉"
    exit 0
else
    print_warning "部分平台构建失败，请检查错误信息"
    exit 1
fi
