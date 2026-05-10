qvmp_test.zip — diagnostic v11 (trace to file)
==============================================

v10 你说终端 0 输出，连一个调试字母都没有。可能你 launcher 不接 stderr。
这次 bootstrap 改成把进度字符**直接写到磁盘文件**:

  /sdcard/qvmp_trace.txt           (主选)
  /data/local/tmp/qvmp_trace.txt    (副选,如果 /sdcard/ 写不进去)

bootstrap 跑完之后，cat 这个文件:

  cat /sdcard/qvmp_trace.txt
  # 或
  cat /data/local/tmp/qvmp_trace.txt

预期内容: BOWCDd+U  (B=进bootstrap, O=open OK, W=write done, C=close,
                     D=dlopen前, d=dlopen返回, +=dlopen返回非NULL,
                     -=dlopen返回NULL, U=unlink, F=open失败)

跑法:
  chmod +x 15_trace_to_file.hardened
  ./15_trace_to_file.hardened
  # 进程死了之后:
  cat /sdcard/qvmp_trace.txt 2>/dev/null || cat /data/local/tmp/qvmp_trace.txt 2>/dev/null
  ls -la /sdcard/qvmp_trace.txt /data/local/tmp/qvmp_trace.txt 2>&1

把 cat 出来的内容 + ls -la 输出贴回来。

如果两个 trace 文件都不存在:
  → bootstrap 完全没跑 (e_entry shim 没起作用)
  → 我换思路：可能 hijack INIT_ARRAY[last] 或者改 _start 第一条指令

如果存在但内容是 BF\n:
  → bootstrap 跑了，但 /data/local/tmp/.cachelib 写不进去
  → 改用 memfd_create 或换路径

如果是 BOWCDd+:
  → 全成功，但 cdylib qvmp_init 没起来 (哪怕 dlopen 返回非 NULL)
  → 需要查 cdylib 内部

如果是 BOWCDd-:
  → dlopen 返回 NULL，文件路径或格式问题

MD5: d2b27a70682d00ae3dd3bcaabf654812
