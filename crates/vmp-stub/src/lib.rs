//! vmp-stub
//!
//! 「运行时 stub」是被加壳器嵌入到受保护二进制里的**模块**。
//! 它包含两部分：
//!
//! 1. **包格式（StubBlob）**：序列化后的 ISA 规范 + 字节码集合 + 元信息。
//!    这是加壳器的输出，运行时 stub 会反序列化后构造解释器。
//! 2. **运行时入口（dispatch_vm）**：被原函数入口处的跳板调用，按 region id
//!    定位字节码、进入解释器、再把返回值写回宿主调用约定。
//!
//! 真实工程里 stub 还要：
//! - 用纯 `no_std` 编译，避免拖入 std 体积
//! - 提供与目标 OS 适配的 `HostBridge` 实现（Linux mmap / Windows VirtualAlloc 等）
//!
//! 当前文件提供 `serde` 风格的手写打包格式（不依赖 serde crate，二进制尺寸更可控）。

pub mod blob;
pub mod entry;
pub mod linux;

pub use blob::{pack_blob, unpack_blob, DataSegment, StubBlob, StubRegion};
pub use entry::{dispatch_vm, dispatch_vm_fp, StubError};
