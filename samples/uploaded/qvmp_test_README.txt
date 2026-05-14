qvmp_test.zip — v33 BR Rn (tail-call) 后面补 Ret
==================================================

v32 反馈:
  [qvmp] dispatching region=124
  [qvmp] vm: BLR x20 target=0x55... x0=0x55...      ← PIE 重定位生效了
  [qvmp] vm: BLR x20 ...        (三次)
  [qvmp] VM returned region=124                      ← region 124 通了
  [qvmp] dispatching region=8
  [qvmp] vm: BLR x2 target=0x55dfccd180 ...
  [qvmp] VM ERR region=8 err=Eb2:E:E6                ← E6 = PC 超出字节码

region 8 (vaddr 0x108278) 是 5 条指令的 tail-call 蹦床:
  adrp x8, ...
  adrp x9, ...
  ldr  x1, [x8, #N]
  ldr  x2, [x9, #M]
  br   x2          ← BR (没 link), tail-call

lifter 之前把 BR 编成跟 BLR 一样的 `NativeCall { rd: rn }`. NativeCall
执行完 PC 继续往下走 IR, 但 BR 是函数末尾的 tail-call, 后面没指令了, PC
越过末尾就抛 E6.

v33 修 (vmp-arch/src/arm64/decode.rs):
  - BR Rn:
      NativeCall rd: rn
      Ret                    ← 新增, 把 NativeCall 的返回值当当前 region 的返回
  - BLR Rn 不变 (正常调用, 继续执行)

Ret 已有的语义: 栈空时返回 regs[0] (会被 dispatch_vm_fp 当 region 返回值).
Tail-call 语义完全对上.

部署:
  1. libqvmp_runtime.so → /data/local/tmp/  (跟 v32 同一份, MD5 一样可不更新)
  2. 33_br_tailret.hardened → 任意位置
  3. MT 双击

期望 region 124 + region 8 都通过, 后续 region 继续 dispatch. 如果出
新错就把日志整段粘.

MD5:
  33_br_tailret.hardened  f301e2f92f65f0fd6e4d650ade424c3b
  libqvmp_runtime.so      ae803cacd1d87aaa0eb1be3687e3ad41  (跟 v32 同)
