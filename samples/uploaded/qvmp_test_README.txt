qvmp_test.zip — v19 DT_NEEDED 方案
====================================

之前所有 dlopen 路径都触发栈金丝雀 (134). 换完全不同的方案:

  - 在 .dynamic 里加 DT_NEEDED 条目, 让 Android linker 自动加载
    libqvmp_runtime.so, 时机是 main exec 的 INIT_ARRAY 跑之前.
  - 这是个"安全的 dlopen 时机", 跟我们手动 dlopen 完全不同.
  - libqvmp_runtime.so 的 qvmp_init 在 linker setup 阶段跑, 在那里装
    SIGTRAP handler.
  - 然后 main exec INIT_ARRAY 跑, 撞到保护函数 BRK, handler dispatch.

部署要求 (★ 两个文件):

  1. 把 libqvmp_runtime.so 放到 /data/local/tmp/libqvmp_runtime.so
     (绝对路径写在 binary 里了, 必须是这个位置)
  2. 把 23_dt_needed.hardened 放到任意位置 (你目前 /data/ 也行)
  3. MT 管理器双击 23_dt_needed.hardened

  Android linker 启动时看到 DT_NEEDED, 去加载
  /data/local/tmp/libqvmp_runtime.so. 它的 init_array 跑 qvmp_init.
  装好 SIGTRAP handler. 然后主 exec 继续, INIT_ARRAY 撞到保护函数,
  handler 接住, dispatch VM, ImGui GUI 起来.

期望:

  ImGui GUI 起来       → ★ 完全跑通
  CANNOT LINK 找不到 .so → 你忘了放 libqvmp_runtime.so 到 /data/local/tmp/
  CANNOT LINK 其他错误 → 告诉我具体错误文本
  SIGTRAP/SEGV         → 告诉我 error code

MD5:
  23_dt_needed.hardened   38c462247de8c6810b8862608b638d3a
  libqvmp_runtime.so      f840ec8a5f5ac492ff8a4335efb6f074
