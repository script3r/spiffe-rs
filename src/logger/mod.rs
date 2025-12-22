use std::fmt;
use std::io::{self, Write};
use std::sync::Mutex;

/// A trait for logging in the SPIFFE library.
pub trait Logger: Send + Sync {
    /// Logs a debug message.
    fn debugf(&self, args: fmt::Arguments<'_>);
    /// Logs an info message.
    fn infof(&self, args: fmt::Arguments<'_>);
    /// Logs a warning message.
    fn warnf(&self, args: fmt::Arguments<'_>);
    /// Logs an error message.
    fn errorf(&self, args: fmt::Arguments<'_>);
}

/// A logger that writes to standard error.
pub struct StdLogger;

impl Logger for StdLogger {
    fn debugf(&self, args: fmt::Arguments<'_>) {
        let _ = writeln!(io::stderr(), "[DEBUG] {}", args);
    }

    fn infof(&self, args: fmt::Arguments<'_>) {
        let _ = writeln!(io::stderr(), "[INFO] {}", args);
    }

    fn warnf(&self, args: fmt::Arguments<'_>) {
        let _ = writeln!(io::stderr(), "[WARN] {}", args);
    }

    fn errorf(&self, args: fmt::Arguments<'_>) {
        let _ = writeln!(io::stderr(), "[ERROR] {}", args);
    }
}

/// A logger that discards all messages.
pub struct NullLogger;

impl Logger for NullLogger {
    fn debugf(&self, _args: fmt::Arguments<'_>) {}
    fn infof(&self, _args: fmt::Arguments<'_>) {}
    fn warnf(&self, _args: fmt::Arguments<'_>) {}
    fn errorf(&self, _args: fmt::Arguments<'_>) {}
}

/// A logger that writes to a `std::io::Write` implementation.
pub struct WriterLogger<W: Write + Send + Sync> {
    writer: Mutex<W>,
}

impl<W: Write + Send + Sync> WriterLogger<W> {
    /// Creates a new `WriterLogger` for the given writer.
    pub fn new(writer: W) -> Self {
        Self {
            writer: Mutex::new(writer),
        }
    }
}

impl<W: Write + Send + Sync> Logger for WriterLogger<W> {
    fn debugf(&self, args: fmt::Arguments<'_>) {
        if let Ok(mut writer) = self.writer.lock() {
            let _ = writeln!(&mut *writer, "[DEBUG] {}", args);
        }
    }

    fn infof(&self, args: fmt::Arguments<'_>) {
        if let Ok(mut writer) = self.writer.lock() {
            let _ = writeln!(&mut *writer, "[INFO] {}", args);
        }
    }

    fn warnf(&self, args: fmt::Arguments<'_>) {
        if let Ok(mut writer) = self.writer.lock() {
            let _ = writeln!(&mut *writer, "[WARN] {}", args);
        }
    }

    fn errorf(&self, args: fmt::Arguments<'_>) {
        if let Ok(mut writer) = self.writer.lock() {
            let _ = writeln!(&mut *writer, "[ERROR] {}", args);
        }
    }
}

pub fn std_logger() -> StdLogger {
    StdLogger
}

pub fn null_logger() -> NullLogger {
    NullLogger
}

pub fn writer_logger<W: Write + Send + Sync>(writer: W) -> WriterLogger<W> {
    WriterLogger::new(writer)
}
