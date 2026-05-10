qvmp_test.zip — diagnostic v12 (退出码编码进度，无需手动 cat)
==============================================================

直接 MT 管理器双击运行 16_stage_exitcode.hardened 就行，
进程结束对话框会显示 "error <数字>"，那个数字就告诉我们 bootstrap
跑到哪一步:

  error 11  bootstrap 进了，但 openat /data/local/tmp/.cachelib 失败
            (路径写不进去) → 换路径
  error 12  openat OK 但 write 解密循环里崩 → 不太可能
  error 13  write 完了，close 崩 → 不可能
  error 14  close 完了，dlopen 调用准备阶段崩
  error 15  dlopen 返回了，x0=0 (理论上不该出现，cbz 路径会跑到 16/17)
  error 16  ★ dlopen 返回非 NULL — cdylib 加载成功
  error 17  dlopen 返回 NULL — 文件路径或格式问题
  error 18  全程跑通 (bootstrap 返回到 shim，shim 立即 exit_group)

  error 133  SIGTRAP (kernel 杀 - 不是预期，因为 shim 直接 exit 不会
             跑到 INIT_ARRAY 的保护函数)
  error 134  SIGABRT (栈金丝雀又触发了？)
  error 139  SIGSEGV (bootstrap 内部崩)

注意: 因为 shim 改成在 bootstrap 返回后直接 exit_group，**不会** 启动
原 _start，所以 ImGui GUI **不会**起来。这只是一个诊断版本，跑完
告诉我 error 多少就行。

如果 error 是 16 → bootstrap 完美工作，说明问题在 cdylib 内部某处
                  没装上 SIGTRAP handler。下一步是查 cdylib。
如果 error 是 17 → dlopen 失败，调整路径/写入策略。
如果 error 是 133/139/134 → bootstrap 内部某步崩了。

直接 MT 管理器跑。看 error 数字。告诉我数字。

MD5: bad84cb63a8ab302a531fb025b930b01
