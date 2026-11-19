//! XLSX text extraction via `calamine`.
//!
//! Reads sheets / rows / cells and formats them as plain text, with
//! optional Markdown table rendering when `include_tables` is true.

use std::path::Path;

use calamine::Reader;

use super::ExtractOptions;

/// Maximum rows per sheet (safety cap).
const MAX_ROWS: usize = 10_000;
/// Maximum columns per sheet (safety cap).
const MAX_COLS: usize = 200;

/// Extract text content from an XLSX file.
pub fn extract_text(path: &Path, opts: &ExtractOptions) -> Result<String, String> {
    let mut workbook: calamine::Xlsx<_> =
        calamine::open_workbook(path).map_err(|e| format!("Failed to open XLSX: {e}"))?;

    let sheet_names = workbook.sheet_names().to_vec();
    if sheet_names.is_empty() {
        return Ok("(empty XLSX)".to_string());
    }

    let start = opts.start_page.unwrap_or(1).max(1);
    let end = opts.end_page.unwrap_or(sheet_names.len()).max(start);

    let mut output = String::new();

    for (i, name) in sheet_names.iter().enumerate() {
        let sheet_num = i + 1;
        if sheet_num < start || sheet_num > end {
            continue;
        }

        let range = match workbook.worksheet_range(name) {
            Ok(r) => r,
            Err(_) => continue,
        };

        if range.rows().next().is_none() {
            continue;
        }

        output.push_str(&format!("\n[Sheet: {name}]\n"));

        let rows: Vec<&[calamine::Data]> = range.rows().collect();
        if opts.include_tables {
            render_sheet_as_table(&mut output, &rows);
        } else {
            render_sheet_as_text(&mut output, &rows);
        }
        output.push('\n');
    }

    if output.is_empty() {
        return Ok(format!("[No data in sheets {start}-{end}]"));
    }

    let total = sheet_names.len();
    let summary = if end - start + 1 < total {
        format!("\n[Extracted sheets {start}-{end} of {total}]\n")
    } else {
        format!("\n[{total} sheets total]\n")
    };
    output.push_str(&summary);

    Ok(output)
}

fn render_sheet_as_text(output: &mut String, rows: &[&[calamine::Data]]) {
    let max_rows = rows.len().min(MAX_ROWS);
    let mut _row_count = 0usize;

    for row in rows.iter().take(max_rows) {
        let max_cols = (*row).len().min(MAX_COLS);
        let cells: Vec<String> = (*row)[..max_cols].iter().map(cell_to_string).collect();
        if cells.iter().all(|s| s.is_empty()) {
            continue;
        }
        output.push_str(&cells.join("\t"));
        output.push('\n');
        _row_count += 1;
    }

    if rows.len() > MAX_ROWS {
        output.push_str(&format!(
            "\n[Truncated: showing {MAX_ROWS} of {} rows]\n",
            rows.len()
        ));
    }
}

fn render_sheet_as_table(output: &mut String, rows: &[&[calamine::Data]]) {
    let max_rows = rows.len().min(MAX_ROWS);
    if max_rows == 0 {
        return;
    }

    let col_count = rows[0].len().min(MAX_COLS);
    if col_count == 0 {
        return;
    }

    let mut cells: Vec<Vec<String>> = Vec::new();
    for row in rows.iter().take(max_rows) {
        let max_cols = (*row).len().min(MAX_COLS);
        let row_cells: Vec<String> = (*row)[..max_cols].iter().map(cell_to_string).collect();
        if !row_cells.iter().all(|s| s.is_empty()) {
            cells.push(row_cells);
        }
    }

    if cells.is_empty() {
        return;
    }

    // Find actual column count
    let actual_cols = cells.iter().map(|r| r.len()).max().unwrap_or(col_count);

    // Header
    output.push('|');
    for c in 0..actual_cols {
        let val = cells[0].get(c).map(|s| s.as_str()).unwrap_or("");
        output.push_str(&format!(" {} |", val));
    }
    output.push('\n');

    // Separator
    output.push('|');
    for _ in 0..actual_cols {
        output.push_str(" --- |");
    }
    output.push('\n');

    // Body
    for row in &cells[1..] {
        output.push('|');
        for c in 0..actual_cols {
            let val = row.get(c).map(|s| s.as_str()).unwrap_or("");
            output.push_str(&format!(" {} |", val));
        }
        output.push('\n');
    }

    if rows.len() > MAX_ROWS {
        output.push_str(&format!(
            "\n[Truncated: showing {MAX_ROWS} of {} rows]\n",
            rows.len()
        ));
    }
}

fn cell_to_string(cell: &calamine::Data) -> String {
    match cell {
        calamine::Data::Empty => String::new(),
        calamine::Data::String(s) => s.clone(),
        calamine::Data::Float(f) => {
            // Avoid scientific notation for reasonable numbers
            if *f == (*f as i64) as f64 && f.abs() < 1e15 {
                format!("{}", *f as i64)
            } else {
                format!("{f}")
            }
        }
        calamine::Data::Int(i) => format!("{i}"),
        calamine::Data::Bool(b) => format!("{b}"),
        calamine::Data::DateTime(d) => format!("{d}"),
        calamine::Data::DateTimeIso(d) => d.clone(),
        calamine::Data::DurationIso(d) => d.clone(),
        calamine::Data::Error(e) => format!("#ERR:{e:?}"),
    }
}
