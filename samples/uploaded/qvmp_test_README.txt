qvmp_test.zip — diagnostic v7 (bootstrap stage bisect)
======================================================

之前 v6 结果:
  4_onlytramp        Trap 133 (预期, 无 handler)
  5_embedonly        SEGV 139 ★ 即使无 armor 也 SEGV
  6_full             SEGV 139

x21/x22 ABI 修复没解决 SEGV 问题。需要再细分 bootstrap 内部哪一步触发。

新增两个梯度版本:

  7_bootstrap_noop.hardened
    bootstrap 替换成只有 RET 的 stub。
    wrapper → bl noop → 立即 ret → wrapper b orig_init
    完全没做任何 syscall / dlopen。
    如果 SEGV → wrapper plumbing / INIT_ARRAY hijack 本身有 bug
    如果 Trap 133 → wrapper 没问题，bug 在 bootstrap 内部 syscall/dlopen

  8_bootstrap_dlopenonly.hardened
    bootstrap 只做 dlopen("/data/local/tmp/.cachelib", RTLD_NOW) 然后 ret。
    没 open/write/decrypt syscall，只 dlopen。
    .cachelib 文件不存在 → dlopen 应返回 NULL，不 crash。
    如果 SEGV → dlopen 在 INIT_ARRAY 上下文下 crash 是凶手
    如果 Trap 133 → dlopen 调用 OK，bug 在 bootstrap 的 open+write 路径

跑 1-8 顺序，特别看 7 和 8 的结果:

  7 → ?
  8 → ?

把每个 binary 的终端输出原样发回来，特别是有没有 [qvmp] 这种行。

MD5:
  1e33950ddd0f3ca282d638ba92b892ba  1_original.bin
  ff98505ec005b03664f03caf7e2882c6  2_onebyte.hardened
  92fca783ef3b1bfa17e59f4f45e57698  3_notramp.hardened
  51041fee2e9f20a1206369d9c78d43cb  4_onlytramp.hardened
  286b4a41e66bba541141fc941348632a  5_embedonly.hardened
  4d621c59a17a315661d3adb8dadedfe5  6_full.hardened
  f1771a998df01db44c918f2517636d20  7_bootstrap_noop.hardened
  c8b51a47c07cfc920053f4b93837ddc4  8_bootstrap_dlopenonly.hardened
