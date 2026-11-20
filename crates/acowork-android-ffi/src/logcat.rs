//! Route `tracing` output into the Android logcat.
//!
//! WHY THIS EXISTS
//!   An app process inherits its stderr from Zygote, and there it points at
//!   `/dev/null`. Writing logs there is not a degraded fallback — it is
//!   deletion. On a release build the consequences compound: the package is
//!   not debuggable, so `adb shell run-as` cannot read the app's private
//!   files, and the node's own error output is gone at the same time. Every
//!   gateway rejection, every failed CONNECT, every dropped session becomes
//!   unrecoverable, and the only observable symptom is a port number changing
//!   twice a second in `netstat`.
//!
//!   logcat is the one channel that survives a device the developer cannot
//!   shell into, so it is not a convenience here; it is the difference between
//!   a diagnosable product and an undiagnosable one.
//!
//! LEVEL
//!   `MakeWriter` is handed no level, so priority is read back from the
//!   formatted line's leading token instead of adding a second formatting
//!   path. The level therefore travels as text (authoritative) and as
//!   logcat priority (best effort, for filtering).

use std::ffi::CString;
use std::io::{self, Write};
use std::os::raw::{c_char, c_int};

unsafe extern "C" {
    fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
}

/// Same tag the Kotlin host uses, so `adb logcat -s ACoworkNode` catches both
/// halves of the runtime in one view.
const TAG: &str = "ACoworkNode";

const ANDROID_LOG_INFO: c_int = 4;
const ANDROID_LOG_WARN: c_int = 5;
const ANDROID_LOG_ERROR: c_int = 6;

/// `tracing_subscriber` writer factory for logcat.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct LogcatWriter;

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogcatWriter {
    type Writer = LogcatSink;

    fn make_writer(&'a self) -> Self::Writer {
        LogcatSink::default()
    }
}

/// Collects one formatted event and emits it line by line.
///
/// The formatter does not promise a `flush`, and an event may arrive in
/// several `write` calls, so lines are emitted on newline and anything still
/// buffered is emitted on drop.
#[derive(Debug, Default)]
pub(crate) struct LogcatSink {
    buf: Vec<u8>,
}

impl Write for LogcatSink {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        while let Some(idx) = self.buf.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.buf.drain(..idx).collect();
            self.buf.drain(..1); // the newline itself
            emit(&line);
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            let line = std::mem::take(&mut self.buf);
            emit(&line);
        }
        Ok(())
    }
}

impl Drop for LogcatSink {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

fn emit(raw: &[u8]) {
    let text = String::from_utf8_lossy(raw);
    let text = text.trim();
    if text.is_empty() {
        return;
    }
    // CString cannot carry an interior NUL; a log line that would otherwise be
    // lost entirely is worth one mangled character.
    let cleaned: String = text.replace('\0', "?");
    let (Ok(c_text), Ok(c_tag)) = (CString::new(cleaned), CString::new(TAG)) else {
        return;
    };
    // SAFETY: both pointers come from live CStrings, and __android_log_write
    // only reads them.
    unsafe { __android_log_write(prio_for(text), c_tag.as_ptr(), c_text.as_ptr()) };
}

/// Best-effort logcat priority from the level token.
///
/// The token is not at the start of the line — the formatter puts a timestamp
/// (and, for spans, a target) before it — so scan a prefix long enough to
/// clear the timestamp instead of assuming column zero. A level match inside
/// message text is a cosmetic mispriority at worst, which is the right trade
/// for not reimplementing the formatter.
fn prio_for(line: &str) -> c_int {
    let head = line.get(..64).unwrap_or(line).to_ascii_uppercase();
    if head.contains("ERROR") {
        ANDROID_LOG_ERROR
    } else if head.contains("WARN") {
        ANDROID_LOG_WARN
    } else {
        // INFO, DEBUG and TRACE all land here: logcat has no use for the
        // distinction, and dropping a TRACE to ANDROID_LOG_ERROR would make
        // the priority field actively misleading.
        ANDROID_LOG_INFO
    }
}
