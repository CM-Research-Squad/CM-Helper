use std::fmt;
use std::error::Error;

#[derive(Debug, Clone)]
pub struct DeserializeError<Err> {
    pub url: String,
    pub data: String,
    pub source: Err
}

impl<Err: serde::de::Error + 'static> Error for DeserializeError<Err> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

impl<Err> fmt::Display for DeserializeError<Err> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Internal error: Invalid server response")
    }
}

#[derive(Debug, Clone)]
pub struct FormError {
    pub url: String,
    pub code: u32,
    pub msg: String,
    pub details: String,
}
impl fmt::Display for FormError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.details != "" {
            writeln!(f, "[{}] {}: {}", self.code, self.msg, self.details)
        } else {
            writeln!(f, "[{}] {}", self.code, self.msg)
        }
    }
}
impl Error for FormError {}

#[derive(Debug, Clone)]
pub struct MyError(String);
impl MyError {
    pub fn new(s: &str) -> MyError {
        MyError(s.to_string())
    }
}
impl std::fmt::Display for MyError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "{}", self.0)
    }
}
impl Error for MyError {}