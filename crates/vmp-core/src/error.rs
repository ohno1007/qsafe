use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("不支持的架构: {0:?}")]
    UnsupportedArch(crate::Arch),

    #[error("不支持的对象格式: {0:?}")]
    UnsupportedFormat(crate::ObjectFormat),

    #[error("解析对象文件失败: {0}")]
    Parse(String),

    #[error("Lift 失败 @ 0x{addr:x}: {msg}")]
    Lift { addr: u64, msg: String },

    #[error("E:{0}")]
    VmRuntime(String),

    #[error("配置错误: {0}")]
    Config(String),

    #[error("内部错误: {0}")]
    Internal(String),
}

impl Error {
    pub fn parse<S: Into<String>>(msg: S) -> Self {
        Error::Parse(msg.into())
    }
    pub fn lift<S: Into<String>>(addr: u64, msg: S) -> Self {
        Error::Lift { addr, msg: msg.into() }
    }
    pub fn vm<S: Into<String>>(msg: S) -> Self {
        Error::VmRuntime(msg.into())
    }
    pub fn config<S: Into<String>>(msg: S) -> Self {
        Error::Config(msg.into())
    }
    pub fn internal<S: Into<String>>(msg: S) -> Self {
        Error::Internal(msg.into())
    }
}
