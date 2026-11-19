//! DOCX text extraction via ZIP + XML parsing.
//!
//! A DOCX file is a ZIP archive containing XML parts. The main content
//! lives in `word/document.xml`. We extract `<w:t>` text nodes and
//! `<w:tbl>` table structures, rendering tables as Markdown when
//! `include_tables` is true.

use std::io::Read;
use std::path::Path;

use super::ExtractOptions;

/// Extract text content from a DOCX file.
pub fn extract_text(path: &Path, opts: &ExtractOptions) -> Result<String, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("Failed to open DOCX: {e}"))?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|e| format!("Failed to read DOCX as ZIP: {e}"))?;

    // Read the main document XML
    let mut doc_entry = archive
        .by_name("word/document.xml")
        .map_err(|_| "DOCX missing word/document.xml — invalid file?".to_string())?;

    let mut xml_bytes = Vec::new();
    doc_entry
        .read_to_end(&mut xml_bytes)
        .map_err(|e| format!("Failed to read document.xml: {e}"))?;

    let xml_str = String::from_utf8(xml_bytes)
        .map_err(|e| format!("document.xml is not valid UTF-8: {e}"))?;

    // Parse XML and extract text
    let mut reader = quick_xml::Reader::from_str(&xml_str);
    reader.config_mut().trim_text(true);

    let mut output = String::new();
    let mut buf = Vec::new();
    let mut depth = 0u32;
    let mut in_paragraph = false;
    let mut paragraph_lines: Vec<String> = Vec::new();
    let mut in_table = false;
    let mut table_rows: Vec<Vec<String>> = Vec::new();
    let mut current_row: Vec<String> = Vec::new();
    let mut current_cell: Vec<String> = Vec::new();

    loop {
        use quick_xml::events::Event;
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                depth += 1;
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();

                match (name.as_str(), depth) {
                    ("w:p", _) => {
                        in_paragraph = true;
                        paragraph_lines.clear();
                    }
                    ("w:tbl", _) => {
                        in_table = true;
                        table_rows.clear();
                    }
                    ("w:tr", _) if in_table => {
                        current_row.clear();
                    }
                    ("w:tc", _) if in_table => {
                        current_cell.clear();
                    }
                    _ => {}
                }
            }
            Ok(Event::End(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();

                match (name.as_str(), depth) {
                    ("w:p", _) if in_paragraph => {
                        in_paragraph = false;
                        let line = paragraph_lines.join("");
                        if !line.is_empty() {
                            output.push_str(&line);
                            output.push('\n');
                        }
                    }
                    ("w:tbl", _) if in_table && opts.include_tables => {
                        in_table = false;
                        render_markdown_table(&mut output, &table_rows);
                        output.push('\n');
                    }
                    ("w:tr", _) if in_table => {
                        table_rows.push(std::mem::take(&mut current_row));
                    }
                    ("w:tc", _) if in_table => {
                        let cell_text = current_cell.join("").trim().to_string();
                        current_row.push(cell_text);
                    }
                    _ => {}
                }
                depth = depth.saturating_sub(1);
            }
            Ok(Event::Text(ref e)) => {
                let text = e.unescape().unwrap_or_default();
                if in_table {
                    current_cell.push(text.into_owned());
                } else if in_paragraph {
                    paragraph_lines.push(text.into_owned());
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(format!("XML parse error in document.xml: {e}"));
            }
            _ => {}
        }
        buf.clear();
    }

    if output.is_empty() {
        return Ok("(no extractable text in DOCX)".to_string());
    }

    let start = opts.start_page.unwrap_or(1);
    let end = opts.end_page.unwrap_or(usize::MAX);
    let lines: Vec<&str> = output.lines().collect();
    let total = lines.len();
    let s = (start.saturating_sub(1)).min(total);
    let e = end.min(total);

    if s >= e {
        return Ok(format!("[No content in range, document has {total} lines]"));
    }

    let sliced: String = lines[s..e].join("\n");
    let summary = if e - s < total {
        format!("\n[Lines {}-{} of {total}]", s + 1, e)
    } else {
        format!("\n[{total} lines total]")
    };
    Ok(format!("{sliced}{summary}"))
}

fn render_markdown_table(output: &mut String, rows: &[Vec<String>]) {
    if rows.is_empty() {
        return;
    }
    let col_count = rows.iter().map(|r| r.len()).max().unwrap_or(0);
    if col_count == 0 {
        return;
    }

    // Header
    let header = &rows[0];
    output.push('|');
    for c in 0..col_count {
        output.push_str(&format!(
            " {} |",
            header.get(c).map(|s| s.as_str()).unwrap_or("")
        ));
    }
    output.push('\n');

    // Separator
    output.push('|');
    for _ in 0..col_count {
        output.push_str(" --- |");
    }
    output.push('\n');

    // Body
    for row in &rows[1..] {
        output.push('|');
        for c in 0..col_count {
            output.push_str(&format!(
                " {} |",
                row.get(c).map(|s| s.as_str()).unwrap_or("")
            ));
        }
        output.push('\n');
    }
}
