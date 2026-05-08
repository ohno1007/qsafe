#!/usr/bin/env bash
# samples/realworld/harden_so.sh — 单 .so 加固脚本
#
# 用途：对一个 arm64 .so 跑完整流水线（protect → rewrite → armor → 校验），
# 输出 `<input>-vmp.so` + 一份诊断报告。
#
# 用法：
#   bash samples/realworld/harden_so.sh path/to/lib.so [--level heavy] [--no-strip] [--keep-debug]
#
# 环境变量：
#   QVMP_DEBUG=1  打开 vmp CLI 的 debug 日志
#   QVMP_SEED=N   固定随机种子（默认随机，便于复现）

set -euo pipefail

cd "$(dirname "$0")/../.."
WORKSPACE=$(pwd)
VMP="$WORKSPACE/target/release/vmp"

INPUT="${1:?用法: $0 <path/to/lib.so> [--level heavy|paranoid] [--no-strip]}"
shift
LEVEL="heavy"
STRIP_NAMES=true
KEEP_DEBUG=false
SKIP_TRAP_PCT=30
while [ $# -gt 0 ]; do
    case "$1" in
        --level) LEVEL="$2"; shift 2 ;;
        --no-strip) STRIP_NAMES=false; shift ;;
        --keep-debug) KEEP_DEBUG=true; shift ;;
        --skip-trap-pct) SKIP_TRAP_PCT="$2"; shift 2 ;;
        *) echo "[!] 未知参数: $1"; exit 2 ;;
    esac
done

if [ ! -f "$INPUT" ]; then
    echo "[!] 找不到输入文件: $INPUT"; exit 1
fi
if [ ! -x "$VMP" ]; then
    echo "[*] 构建 vmp CLI（host release）"
    cargo build --release -p vmp-cli
fi

OUT_DIR=$(mktemp -d -t qvmp-harden.XXXXXX)
INPUT_BASE=$(basename "$INPUT")
INPUT_NAME="${INPUT_BASE%.so}"
BLOB="$OUT_DIR/$INPUT_NAME.qvmp"
OUT_SO="$OUT_DIR/$INPUT_NAME-vmp.so"

echo "[*] 输入: $INPUT ($(stat -c %s "$INPUT" 2>/dev/null || stat -f %z "$INPUT") bytes)"
echo "[*] 输出目录: $OUT_DIR"

LOG_LEVEL="info"
[ "${QVMP_DEBUG:-0}" = "1" ] && LOG_LEVEL="debug"
SEED_ARG=""
[ -n "${QVMP_SEED:-}" ] && SEED_ARG="--seed $QVMP_SEED"

echo
echo "==== Stage 1: vmp protect ===="
"$VMP" --log "$LOG_LEVEL" protect "$INPUT" \
    -o "$BLOB" \
    --level "$LEVEL" \
    --skip-trap-pct "$SKIP_TRAP_PCT" \
    $SEED_ARG 2>&1 | tee "$OUT_DIR/protect.log"

echo
echo "==== Stage 2: vmp rewrite (armor: strip=$STRIP_NAMES, xor_payload=on) ===="
REWRITE_ARGS=()
[ "$STRIP_NAMES" = "false" ] && REWRITE_ARGS+=("--no-strip-names")
"$VMP" --log "$LOG_LEVEL" rewrite "$INPUT" "$BLOB" \
    -o "$OUT_SO" "${REWRITE_ARGS[@]}" 2>&1 | tee "$OUT_DIR/rewrite.log"

echo
echo "==== Stage 3: 体积 / 段名 / SHA-256 对比 ===="
SIZE_BEFORE=$(stat -c %s "$INPUT" 2>/dev/null || stat -f %z "$INPUT")
SIZE_AFTER=$(stat -c %s "$OUT_SO" 2>/dev/null || stat -f %z "$OUT_SO")
echo "before: $SIZE_BEFORE bytes"
echo "after:  $SIZE_AFTER bytes"
echo "delta:  $((SIZE_AFTER - SIZE_BEFORE)) bytes ($(echo "scale=1; ($SIZE_AFTER - $SIZE_BEFORE) * 100 / $SIZE_BEFORE" | bc 2>/dev/null || echo "?")%)"

if command -v readelf >/dev/null; then
    echo
    echo "[*] 加固后段名（应大量空白即剥离成功）"
    readelf -S "$OUT_SO" | head -20
    echo
    echo "[*] 加固后导入符号（应仅剩 bootstrap 符号 + 少量未保护项）"
    readelf -d "$OUT_SO" | grep -i needed | head -10
fi

if command -v sha256sum >/dev/null; then
    echo
    sha256sum "$INPUT" "$OUT_SO"
fi

echo
echo "==== Stage 4: vmp inspect blob 元数据 ===="
"$VMP" --log warn inspect "$BLOB" || true

echo
echo "==== Stage 5: 已保护函数清单 ===="
grep -E "^.*lift .* skipped=" "$OUT_DIR/protect.log" | head -20 || true
echo
PROTECTED_COUNT=$(grep -c "保护完成" "$OUT_DIR/protect.log" || echo "0")
SKIP_COUNT=$(grep -cE "跳过.*Trap" "$OUT_DIR/protect.log" || echo "0")
echo "lift 失败跳过函数数：$SKIP_COUNT"

echo
echo "[OK] 完成。产物在 $OUT_DIR/"
echo "  - $OUT_SO       （加固后 .so）"
echo "  - $BLOB         （独立 blob，便于 vmp inspect）"
echo "  - protect.log / rewrite.log（详细日志）"
echo
echo "下一步：把 $OUT_SO 替换原 .so 投入测试环境运行；"
echo "若是 APK 内 .so，参考 docs/APK_PACKING.md 重新打包 + apksigner 签名。"
