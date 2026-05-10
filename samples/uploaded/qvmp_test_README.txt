qvmp_test.zip — 16KB-page alignment fix v2
==========================================

之前所有加固版都报 PIE error 是因为新 LOAD vaddr (0x2ab000) 在 16KB 页系统里
和原 LOAD #4 的最后一页冲突。这版改成 16KB 对齐 (0x2ac000)，page_align 也
从 0x1000 改成 0x4000 跟原 binary 一致。

跑法跟之前一样。理论上现在所有 hardened 版本都能起来：
  - onlytrampolines / strip_only / xor_only: 不会跑保护函数 (无 SIGTRAP handler) →
    起 GUI 后第一次命中保护函数会 SIGSEGV，但能起来证明 ELF 加载正常
  - rodata_only: rodata 加密但没人解密，起 GUI 用到 rodata 字符串时会乱码/崩
  - no_embed: 同上，加上 payload+strip
  - hardened: 完整版，理应跑通

最关键的是 onlytrampolines 能不能起来 —— 它是「ELF 结构没问题」的判定基线。

MD5 manifest:
  1e33950ddd0f3ca282d638ba92b892ba  AndroidSurfaceImguiEnhanced
  5c590dcf7b8c59c440f6ed24b520a62a  AndroidSurfaceImguiEnhanced.hardened
  9193f873c75d27140ab071eb7911405d  AndroidSurfaceImguiEnhanced.no_embed.hardened
  58f902ceca15052006a41e2d3e69d328  AndroidSurfaceImguiEnhanced.onlytrampolines.hardened
  f603507157a2b916940bc7f758756d07  AndroidSurfaceImguiEnhanced.rodata_only.hardened
  a44d74b7d6dd769c205f67566eaa9497  AndroidSurfaceImguiEnhanced.strip_only.hardened
  4cca6e24ffce68e65ceba402d9124cbb  AndroidSurfaceImguiEnhanced.xor_only.hardened
