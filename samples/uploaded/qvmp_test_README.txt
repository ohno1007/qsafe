qvmp_test.zip — v40 三连定位包 (全 standard 强度, 三种保护子集对照)
======================================================================

v39 出 UI 确认 bug 在 trampoline + VM, 不在基础设施.
v38 leaf-only 同样位置挂确认 bug 不在间接调用.

audit 444 个 leaf region 的 VOp 频率, 高度怀疑两类:
  - FP 操作 (FLoad/FStore/FCmp/FAdd/FSub/FMul/FCvtZS/FMovR 等): 累计~30 region
  - CSel (条件选择): 6 region

v40 出三个全 standard 强度的对照包:
  - 40A_no_fp.hardened: 全 standard, 但 **不保护任何用 FP 的 region**
    (499 regions, dropped FP-using = 35 个)
  - 40B_first_half.hardened: 只保护 region 0..250
  - 40C_second_half.hardened: 只保护 region 250..534

测试顺序:
  1. 先跑 **40A_no_fp**. 如果出 UI → bug 锁定在 FP 操作的 VM 实现.
     下一步我专门去 audit FP lifter + interpreter.
  2. 再跑 **40B_first_half**. 出 UI / 挂同位置 → 二分到一半区间.
  3. 再跑 **40C_second_half** (跟 40B 互斥). 必有一个挂.

报告格式 (3 行就行):
  40A: 出 UI 了 / 挂在 SIGSEGV
  40B: 出 UI 了 / 挂在 SIGSEGV
  40C: 出 UI 了 / 挂在 SIGSEGV

不用粘日志, 我下一步基于这三个结果做更精确定位.

部署 (每个包都用同一份 .so):
  1. libqvmp_runtime.so → /data/local/tmp/  (沿用之前的, md5 不重要)
  2. 40A_no_fp.hardened / 40B_first_half.hardened / 40C_second_half.hardened
     选一个放 /data/ 双击, 测完再换下一个
  3. 报告结果

MD5:
  40A_no_fp.hardened          c7c09aa7ea1e3fa9229051a8d66acf80
  40B_first_half.hardened     360b044b7cd46471f8e556b3704a041f
  40C_second_half.hardened    e6cdfa0abe938521dd79380850213c9e
