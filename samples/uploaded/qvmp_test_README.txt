qvmp_test.zip — v20 dispatch_vm logging
========================================

v19 进展: cdylib qvmp_init 全部跑通, SIGTRAP handler 装好. 然后 SEGV.
说明 SEGV 在 dispatch_vm 内部 (VM 解释器跑某个 region 时崩).

v20 给 cdylib 加了详细日志:

  [qvmp] qvmp_runtime: dispatching region=N
  [qvmp] qvmp_runtime: VM returned region=N      (成功)
  [qvmp] qvmp_runtime: VM ERROR for region=N    (dispatch_vm 返回 Err)
  
  如果 dispatch 中间 SEGV, 我们会看到 "dispatching" 但没有 "returned/ERROR"
  → 知道是哪个 region_id 触发的崩, 后面能定位.

部署 (跟 v19 一样, 两个文件):
  
  /data/local/tmp/libqvmp_runtime.so   (★ 这版新)
  23_dt_needed.hardened                 (可以原地址,没改)
  
  MT 管理器双击 hardened, 看输出.

我希望看到的:

  情景 A — 多条 dispatching/returned 配对, ImGui GUI 起来
           → ★ 全部跑通, region 都顺序处理
  情景 B — 单条 "dispatching region=X" 然后 SEGV
           → region X 内部某个 VOp 崩, 我可以加更细 log 进 dispatch_vm
  情景 C — 多条 dispatching/returned 然后 SEGV
           → 某个 region 跑完后才崩, 可能 PC=LR 跳到错地方
  情景 D — 一条 dispatching 都没看到, 直接 SEGV
           → handler 自己崩 (FPSIMD 偏移、ucontext 解析等)

MD5:
  23_dt_needed.hardened   38c462247de8c6810b8862608b638d3a
  libqvmp_runtime.so      6e07c5c5e0d66b2d8c930cdeef38af9e

把整段 [qvmp] 日志 + 后面的错误一起贴回来.
