#!/usr/bin/env bash
# samples/realworld/build_apk.sh — Qsafe VMP 真实环境加固案例（端到端）。
#
# 流程：
#   1) 用 NDK 把 librealworld.c 编成 arm64-v8a 的 .so（PIC，shared）
#   2) 调 vmp protect 生成 .qvmp blob
#   3) 调 vmp rewrite 把 blob 嵌入 .so（写跳板 + 嵌 blob + armor + imports.tbl）
#   4) （可选）把 cdylib runtime libqvmp_runtime.so 也交叉编译出来
#   5) 写一个最小 APK 目录结构，把两个 .so 放进 lib/arm64-v8a/
#   6) 给加固后的 .so 算 SHA-256 / readelf -S/-s 检查段名 / 符号
#
# 使用：
#   export NDK=/path/to/android-ndk-r26d
#   bash samples/realworld/build_apk.sh
#
# 不在你机器上时本脚本只会做 protect + 报告步骤，不调 NDK；可以先跑一遍看 vmp CLI
# 是否工作。

set -euo pipefail

cd "$(dirname "$0")/../.."   # 切到 workspace root
WORKSPACE=$(pwd)
SAMPLE_DIR="$WORKSPACE/samples/realworld"
OUT_DIR="$SAMPLE_DIR/out"
mkdir -p "$OUT_DIR"

# ========= 1) 选 NDK =========
NDK="${NDK:-${ANDROID_NDK_HOME:-}}"
if [ -z "$NDK" ] || [ ! -d "$NDK" ]; then
    echo "[!] NDK 未设置 / 不存在；跳过 NDK 编译，仅做 vmp 工具链测试。"
    NDK=""
fi
HOST=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$HOST" in
    linux)   HOST_TAG="linux-x86_64";;
    darwin)  HOST_TAG="darwin-x86_64";;
    msys*|mingw*|cygwin*) HOST_TAG="windows-x86_64";;
    *)       HOST_TAG="linux-x86_64";;
esac

# ========= 2) 编译 vmp CLI / cdylib runtime =========
echo "[*] 构建 vmp CLI（host）"
cargo build --release -p vmp-cli
VMP="$WORKSPACE/target/release/vmp"

if [ -n "$NDK" ]; then
    NDK_BIN="$NDK/toolchains/llvm/prebuilt/$HOST_TAG/bin"
    CC="$NDK_BIN/aarch64-linux-android35-clang"
    if [ ! -x "$CC" ]; then
        echo "[!] 找不到 $CC；请确认 NDK_HOST_TAG 设置正确。"
        exit 1
    fi
    echo "[*] 编译 librealworld.so (arm64-v8a, PIC)"
    "$CC" -O2 -fPIC -shared "$SAMPLE_DIR/realworld.c" -o "$OUT_DIR/librealworld.so"

    echo "[*] 交叉编译 libqvmp_runtime.so (cdylib, aarch64-linux-android)"
    rustup target add aarch64-linux-android >/dev/null 2>&1 || true
    export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CC"
    export CC_aarch64_linux_android="$CC"
    cargo build --release -p vmp-runtime --target aarch64-linux-android \
        --no-default-features
    cp "$WORKSPACE/target/aarch64-linux-android/release/libqvmp_runtime.so" \
        "$OUT_DIR/libqvmp_runtime.so"
fi

# 占位：如果没有 NDK，用 host-side .so 走 vmp 链路（验证不依赖 NDK 的部分能过）
if [ ! -f "$OUT_DIR/librealworld.so" ]; then
    echo "[*] 占位：用 host x86_64 静态构建一个示例 .so 走 vmp 链路"
    cc -O2 -fPIC -shared "$SAMPLE_DIR/realworld.c" -o "$OUT_DIR/librealworld.so"
fi

# ========= 3) vmp protect → 出 .qvmp blob =========
echo "[*] vmp protect"
"$VMP" protect "$OUT_DIR/librealworld.so" \
    -o "$OUT_DIR/realworld.qvmp" \
    --level heavy

# ========= 4) vmp rewrite → 嵌 blob + 写跳板 + armor =========
echo "[*] vmp rewrite (默认开 strip + xor_payload；按 clap flag 语法 --no-* 关闭)"
"$VMP" rewrite "$OUT_DIR/librealworld.so" "$OUT_DIR/realworld.qvmp" \
    -o "$OUT_DIR/librealworld-vmp.so"

# ========= 5) 检查 =========
echo "[*] vmp inspect"
"$VMP" inspect "$OUT_DIR/realworld.qvmp" || true

if command -v readelf >/dev/null; then
    echo "[*] readelf -S（段名是否被剥）"
    readelf -S "$OUT_DIR/librealworld-vmp.so" | head -40
    echo "[*] readelf -d（动态段）"
    readelf -d "$OUT_DIR/librealworld-vmp.so" | head -20
fi

echo "[*] sha256sum 对比"
if command -v sha256sum >/dev/null; then
    sha256sum "$OUT_DIR/librealworld.so"
    sha256sum "$OUT_DIR/librealworld-vmp.so"
fi

# ========= 6) APK 占位结构 =========
APK_DIR="$OUT_DIR/apk_unpacked"
mkdir -p "$APK_DIR/lib/arm64-v8a"
cp "$OUT_DIR/librealworld-vmp.so" "$APK_DIR/lib/arm64-v8a/librealworld.so"
if [ -f "$OUT_DIR/libqvmp_runtime.so" ]; then
    cp "$OUT_DIR/libqvmp_runtime.so" "$APK_DIR/lib/arm64-v8a/"
fi
echo "[*] APK 解包目录已就绪：$APK_DIR"
echo "    用法（caller 自行 zip + apksigner）:"
echo "      cd $APK_DIR && zip -r ../app-vmp.apk ."
echo "      apksigner sign --ks debug.keystore --out signed.apk ../app-vmp.apk"

echo "[OK] realworld 加固流程完成。产物在 $OUT_DIR/"
