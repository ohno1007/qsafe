qvmp_test.zip — v37 加 BLR 返回值 trace + 同时出 light/standard 两个包对照
============================================================================

v36 反馈:
  region 124 70+ BLR 全过, malloc/free 多轮, region 8/9/12/25/3/13/6/2
  /105/127/183/161/178/233/326/344/151/396/401/353/145 等等都通了.
  挂在 region 127 返回后. SEGV pc=addr=0x6EF06E5520 (exec fault).
  FP-chain 走 12 层但 lr vaddr (0xf54cc, 0x739bc 等) 都落在 .eh_frame
  范围 — 数据当代码, 不是真 frame.

  意思是: fp chain 在 SEGV 那一刻已经被踩烂, 或者那个函数没按 AAPCS
  保留 fp. Backtrace 没法直接反推调用栈.

v37 不改修复路径, 加两手诊断:

1. **VOp::NativeCall 多打一行 return 值** (crates/vmp-interpreter/src/lib.rs)
   每次 BLR 完都打:
     [qvmp] vm: <- ret=0x... (from target=0x...)
   能让我顺着 ret 看哪次 native call 返回的不像正经指针 — 比如返回 0
   或低地址或不在任何 r-x 映射, 早晚某次 caller `blr <stored_ret>` 就
   炸到 0x6E.../0x7B... 之类地方.

2. **同时出 light 包 (37_light.hardened)**
   light 预设: insert_junk=false, handler_duplication=1.
   把 protection 强度降到最低. 如果 light 跑得过去出 ImGui, standard
   出不去 → 残留 bug 在 junk 或 dup. 如果 light 也挂同一个地方 →
   bug 在 VM 核心路径.

部署 (任选一):
  方案 A: 测 standard
    1. libqvmp_runtime.so → /data/local/tmp/
    2. 37_std_retlog.hardened → 任意位置
    3. MT 双击, 把整段日志粘回来

  方案 B: 测 light (强烈推荐先跑这个对照)
    1. libqvmp_runtime.so → /data/local/tmp/
    2. 37_light.hardened → 任意位置
    3. MT 双击, 看是否能起 ImGui

  方案 C: 两个都跑, 报告 light 是否能起 UI

MD5:
  37_std_retlog.hardened  7e12b735c4fcdc3a33012025d8eb3473
  37_light.hardened       756c5b314aab9cf3dcf89bcf432b7ace
  libqvmp_runtime.so      f06a1ee8de96935d7ea8740eb3b874db
