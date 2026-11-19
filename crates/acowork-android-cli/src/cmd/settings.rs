//! `acowork-android settings` — init / show / catalog the HostConfig document.

use std::path::Path;

use acowork_android::host::{HostConfig, LoadSource, catalog};

use crate::session::CommonArgs;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsCmd {
    Init,
    Show,
    Catalog,
}

pub fn run(common: &CommonArgs, cmd: SettingsCmd) -> Result<(), String> {
    match cmd {
        SettingsCmd::Init => init(&common.root),
        SettingsCmd::Show => show(&common.root),
        SettingsCmd::Catalog => {
            for row in catalog() {
                println!("{:<28}  {:?}  default={:?}", row.id, row.kind, row.default);
            }
            Ok(())
        }
    }
}

fn init(root: &Path) -> Result<(), String> {
    let loaded = HostConfig::load(root).map_err(|e| e.to_string())?;
    if matches!(loaded.source, LoadSource::File(_)) {
        return Err(format!(
            "{} already exists — delete it first if you want defaults rewritten",
            HostConfig::settings_file(root).display()
        ));
    }
    let path = loaded.config.save(root).map_err(|e| e.to_string())?;
    println!("wrote {}", path.display());
    Ok(())
}

fn show(root: &Path) -> Result<(), String> {
    let loaded = HostConfig::load(root).map_err(|e| e.to_string())?;
    match &loaded.source {
        LoadSource::File(path) => println!("# from {}", path.display()),
        LoadSource::Defaults => println!(
            "# defaults — {} does not exist yet",
            HostConfig::settings_file(root).display()
        ),
    }
    let json = loaded.config.to_json().map_err(|e| e.to_string())?;
    println!("{json}");
    Ok(())
}
