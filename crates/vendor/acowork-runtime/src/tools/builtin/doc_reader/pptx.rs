//! PPTX text extraction via ZIP + XML parsing.
//!
//! A PPTX file is a ZIP archive containing per-slide XML files under
//! `ppt/slides/slideN.xml`. We extract text from `<a:t>` elements and
//! nest slide notes when available.

use std::io::Read;
use std::path::Path;

use super::ExtractOptions;

/// Extract text content from a PPTX file.
pub fn extract_text(path: &Path, opts: &ExtractOptions) -> Result<String, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("Failed to open PPTX: {e}"))?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|e| format!("Failed to read PPTX as ZIP: {e}"))?;

    // Collect slide entry indices (sorted by name: slide1..slideN)
    let mut slide_indices: Vec<(usize, usize)> = Vec::new();
    for i in 0..archive.len() {
        if let Ok(entry) = archive.by_index(i) {
            let name = entry.name().to_string();
            if name.starts_with("ppt/slides/slide")
                && name.ends_with(".xml")
                && let Some(num_str) = name
                    .strip_prefix("ppt/slides/slide")
                    .and_then(|s| s.strip_suffix(".xml"))
                && let Ok(num) = num_str.parse::<usize>()
            {
                slide_indices.push((i, num));
            }
        }
    }
    slide_indices.sort_by_key(|(_, n)| *n);

    let total = slide_indices.len();
    if total == 0 {
        return Ok("(no slides found in PPTX)".to_string());
    }

    let start = opts.start_page.unwrap_or(1).max(1);
    let end = opts.end_page.unwrap_or(total).max(start).min(total);

    let mut output = String::new();
    let mut buf = Vec::new();

    for (slide_idx, slide_num) in &slide_indices {
        if *slide_num < start || *slide_num > end {
            continue;
        }

        // Read slide XML
        let mut xml_bytes = Vec::new();
        {
            let mut entry = archive
                .by_index(*slide_idx)
                .map_err(|e| format!("Failed to read slide {slide_num}: {e}"))?;
            entry
                .read_to_end(&mut xml_bytes)
                .map_err(|e| format!("Failed to read slide {slide_num}: {e}"))?;
        }
        let xml_str =
            String::from_utf8(xml_bytes).unwrap_or_else(|_| "(non-UTF-8 slide)".to_string());

        let text = extract_shape_text(&xml_str, &mut buf);
        if text.is_empty() {
            continue;
        }

        output.push_str(&format!("\n[Slide {slide_num}]\n"));
        output.push_str(&text);
        output.push('\n');
    }

    if output.is_empty() {
        return Ok(format!("[No text in slides {start}-{end}]"));
    }

    let summary = if end - start + 1 < total {
        format!("\n[Extracted slides {start}-{end} of {total}]\n")
    } else {
        format!("\n[{total} slides total]\n")
    };
    output.push_str(&summary);

    Ok(output)
}

/// Extract text from `<a:t>` elements in a slide/note XML string.
fn extract_shape_text(xml_str: &str, buf: &mut Vec<u8>) -> String {
    let mut reader = quick_xml::Reader::from_str(xml_str);
    reader.config_mut().trim_text(true);

    let mut output = String::new();

    loop {
        use quick_xml::events::Event;
        match reader.read_event_into(buf) {
            Ok(Event::Start(ref e))
                if e.name().as_ref() == b"a:p" && !output.is_empty() && !output.ends_with('\n') =>
            {
                output.push('\n');
            }
            Ok(Event::Text(ref e)) => {
                let text = e.unescape().unwrap_or_default();
                output.push_str(&text);
            }
            Ok(Event::Eof) => break,
            Err(_) => return output,
            _ => {}
        }
        buf.clear();
    }

    output.trim().to_string()
}
