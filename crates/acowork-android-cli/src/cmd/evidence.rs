//! `acowork-android evidence` — capture one evidence source into the workspace.

use acowork_android::host::{ApprovalToken, EvidenceSource};

use crate::session::{CommonArgs, Session};

pub struct EvidenceArgs {
    pub common: CommonArgs,
    pub source: EvidenceSource,
    pub assume_yes: bool,
}

pub async fn run(args: EvidenceArgs) -> Result<(), String> {
    let session = Session::open(&args.common).await?;
    session.print_banner(&args.common.root);

    let needs_write = matches!(args.source, EvidenceSource::Bugreport);
    let token = if needs_write {
        if !args.assume_yes {
            return Err(
                "bugreport is a write-tier capture; pass --yes to approve it for this run"
                    .to_string(),
            );
        }
        Some(ApprovalToken::new("operator-terminal"))
    } else {
        None
    };

    println!("evidence   {}", args.source.describe());
    let artifact = session
        .prepared
        .capture(
            &session.inner,
            &args.source,
            &args.common.session,
            token.as_ref(),
        )
        .await
        .map_err(|e| e.to_string())?;
    println!(
        "           wrote {} ({} bytes, sha256 {})",
        artifact.host_path.display(),
        artifact.bytes,
        artifact.digest
    );
    Ok(())
}

pub fn parse_source(raw: &str) -> Result<EvidenceSource, String> {
    let mut parts = raw.splitn(2, ':');
    let kind = parts.next().unwrap_or("");
    let rest = parts.next();
    match (kind, rest) {
        ("screenshot", None) => Ok(EvidenceSource::Screenshot),
        ("bugreport", None) => Ok(EvidenceSource::Bugreport),
        ("logcat", None) => Ok(EvidenceSource::Logcat {
            buffer: None,
            filter: Vec::new(),
            tail: None,
        }),
        ("logcat", Some(buffer)) => Ok(EvidenceSource::Logcat {
            buffer: Some(buffer.to_string()),
            filter: Vec::new(),
            tail: None,
        }),
        ("dumpsys", Some(service)) if !service.is_empty() => Ok(EvidenceSource::Dumpsys {
            service: service.to_string(),
        }),
        ("file", Some(path)) if path.starts_with('/') => Ok(EvidenceSource::DeviceFile {
            path: path.to_string(),
        }),
        _ => Err(format!(
            "unknown evidence source `{raw}` \
             (expected screenshot|bugreport|logcat[:buffer]|dumpsys:SERVICE|file:/ABS/PATH)"
        )),
    }
}
