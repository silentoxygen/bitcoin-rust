use core::fmt;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Msg(&'static str),
    InvalidInput(&'static str),
    Io(std::io::Error),
    Utf8(std::str::Utf8Error),
}

impl Error {
    pub fn msg(s: &'static str) -> Self {
        Error::Msg(s)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Msg(m) => write!(f, "{m}"),
            Error::InvalidInput(m) => write!(f, "invalid input: {m}"),
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::Utf8(e) => write!(f, "utf8 error: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(e: std::str::Utf8Error) -> Self {
        Error::Utf8(e)
    }
}
