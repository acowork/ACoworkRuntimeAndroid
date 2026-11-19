//! PDF text extraction with layered fallback.
//!
//! **Primary**: `pdf_extract` (font-rendered via `pdf` + `fontdue`).
//! Handles Type1, CFF, TrueType, and CID-keyed fonts correctly —
//! including academic papers with mathematical symbol fonts.
//!
//! **Fallback**: `lopdf` (content-stream extraction).
//! Activated when `pdf_extract` panics (e.g. unsupported CMap encodings
//! like GBK-EUC-H in Chinese PDFs) or returns an error.  `lopdf` reads
//! text directly from PDF content streams without font rendering, so it
//! is immune to CMap encoding issues.

use std::path::Path;

use super::ExtractOptions;

/// Maximum pages to process (safety cap).
const MAX_PAGES: usize = 200;

/// Extract text content from a PDF file.
///
/// Tries `pdf_extract` first for best quality; falls back to `lopdf` on
/// failure (panic or error).  Both paths run synchronously — the caller
/// (`DocReaderTool::execute`) wraps this in `spawn_blocking` +
/// `catch_unwind` for extra safety.
pub fn extract_text(path: &Path, opts: &ExtractOptions) -> Result<String, String> {
    // ── Primary: pdf_extract (font-rendered) ──
    let primary_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        pdf_extract::extract_text_by_pages(path)
    }));

    match primary_result {
        Ok(Ok(pages)) => {
            // Success — format with page markers
            return format_pdf_pages(&pages, opts, "pdf_extract");
        }
        Ok(Err(e)) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "pdf_extract failed, falling back to lopdf"
            );
        }
        Err(panic_payload) => {
            let msg = extract_panic_message(&panic_payload);
            tracing::warn!(
                path = %path.display(),
                panic_msg = %msg,
                "pdf_extract panicked, falling back to lopdf"
            );
        }
    }

    // ── Fallback: lopdf (content-stream extraction) ──
    let doc = lopdf::Document::load(path).map_err(|e| format!("lopdf failed to load PDF: {e}"))?;

    let pages = doc.get_pages();
    if pages.is_empty() {
        return Ok("(empty PDF)".to_string());
    }

    // Build page range respecting opts
    let total_pages = pages.len() as u32;
    let start = opts
        .start_page
        .unwrap_or(1)
        .max(1)
        .min(total_pages as usize);
    let end = opts
        .end_page
        .unwrap_or(total_pages as usize)
        .max(start)
        .min(total_pages as usize);
    let max_pages = end.saturating_sub(start).saturating_add(1).min(MAX_PAGES);

    let mut output = String::from("[Extracted via lopdf — content-stream fallback]\n");
    let mut count = 0;
    // Page numbers in PDF dictionaries are 1-based but stored as keys in the
    // BTreeMap.  lopdf::extract_text concatenates all requested pages, so we
    // extract page-by-page to preserve page markers.
    for page_num in start..=end {
        if count >= max_pages {
            break;
        }
        let text = doc
            .extract_text(&[page_num as u32])
            .unwrap_or_default()
            .trim()
            .to_string();
        if text.is_empty() {
            continue;
        }
        output.push_str(&format!("\n[Page {page_num}]\n"));
        output.push_str(&text);
        output.push('\n');
        count += 1;
    }

    if output.is_empty() || output == "[Extracted via lopdf — content-stream fallback]\n" {
        return Ok("(no extractable text in PDF)".to_string());
    }

    let summary = if end - start + 1 < total_pages as usize {
        format!("\n[Extracted pages {start}-{end} of {total_pages}]\n")
    } else {
        format!("\n[{total_pages} pages total]\n")
    };
    output.push_str(&summary);

    Ok(output)
}

/// Format pages extracted by `pdf_extract` (or any per-page `Vec<String>`).
fn format_pdf_pages(
    pages: &[String],
    opts: &ExtractOptions,
    _source: &str,
) -> Result<String, String> {
    let total_pages = pages.len();
    if total_pages == 0 {
        return Ok("(empty PDF)".to_string());
    }

    let start = opts.start_page.unwrap_or(1).max(1).min(total_pages);
    let end = opts
        .end_page
        .unwrap_or(total_pages)
        .max(start)
        .min(total_pages);
    let max_pages = end.saturating_sub(start).saturating_add(1).min(MAX_PAGES);

    let mut output = String::new();
    let mut count = 0;

    for page_num in start..=end {
        if count >= max_pages {
            break;
        }
        let idx = page_num.saturating_sub(1);
        let text = match pages.get(idx) {
            Some(t) => t.trim(),
            None => continue,
        };
        if text.is_empty() {
            continue;
        }

        output.push_str(&format!("\n[Page {page_num}]\n"));
        output.push_str(text);
        output.push('\n');
        count += 1;
    }

    if output.is_empty() {
        return Ok("(no extractable text in PDF)".to_string());
    }

    let summary = if end - start + 1 < total_pages {
        format!("\n[Extracted pages {start}-{end} of {total_pages}]\n")
    } else {
        format!("\n[{total_pages} pages total]\n")
    };
    output.push_str(&summary);

    Ok(output)
}

/// Extract a human-readable message from a panic payload.
fn extract_panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = payload.downcast_ref::<&str>() {
        s.to_string()
    } else {
        "Unknown panic during PDF extraction".to_string()
    }
}
