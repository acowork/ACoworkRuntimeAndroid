//! Cross-platform CRLF line-ending adapter for tracing output.
//!
//! On Windows, Rust writes `\n` byte-for-byte to stderr which results in
//! unix-style line endings that most Windows terminal emulators render
//! incorrectly (staircase effect).  `CrlfWriter` intercepts every `write()`
//! call and inserts `\r` before each `\n`, producing proper CRLF output.
//! On non-Windows platforms it passes through unchanged (zero overhead).

/// Wraps any [`std::io::Write`] and inserts `\r` before `\n` on Windows.
///
/// On Unix (Linux / macOS) the adapter is a transparent pass-through.
pub struct CrlfWriter<W: std::io::Write> {
    pub inner: W,
}

impl<W: std::io::Write> std::io::Write for CrlfWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // On non-Windows platforms, pass through unchanged.
        // \n is the native line ending on Unix (Linux/macOS).
        if cfg!(not(windows)) {
            return self.inner.write(buf);
        }

        // On Windows: scan for \n bytes and insert \r before each.
        let mut start = 0;
        for (i, &b) in buf.iter().enumerate() {
            if b == b'\n' {
                if i > start {
                    self.inner.write_all(&buf[start..i])?;
                }
                self.inner.write_all(b"\r\n")?;
                start = i + 1;
            }
        }
        if start < buf.len() {
            self.inner.write_all(&buf[start..])?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
