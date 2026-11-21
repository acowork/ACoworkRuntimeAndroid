//! Node reverse proxy + `/fs/browse` + `/health` (ADR-055 §6.4 / L7-1).
//!
//! Bound on `0.0.0.0:{proxy_port}` (default 19900). Fail-closed on the
//! `X-ACowork-Node-Token` header once a node_token exists. Routes:
//! - `GET /health`
//! - `GET /fs/browse?path=&show_hidden=`
//! - `PATCH /node/name` — rename this node (ADR-075 D4)
//! - `ANY /agents/{instance_id}/{*rest}` → `http://127.0.0.1:{http_port}/{rest}`

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Notify, RwLock};

use super::identity::{IdentityError, NodeIdentity};
use super::mqtt::SharedIdentity;

/// Live map of instance_id → loopback HTTP port.
pub type PortTable = Arc<Mutex<HashMap<String, u16>>>;

/// Shared state for the proxy task.
pub struct ProxyState {
    /// Persisted identity (for token check).
    pub identity: SharedIdentity,
    /// Running runtimes' loopback ports.
    pub ports: PortTable,
    /// Where `identity.json` lives — a rename must survive the process.
    pub home: PathBuf,
    /// Fired after a rename so the host loop republishes the retained
    /// `info` snapshot; without it the Gateway keeps serving the old name
    /// until the next heartbeat.
    pub republish: Arc<Notify>,
}

/// Handle for the background proxy listener.
pub struct ProxyHandle {
    shutdown: Arc<Notify>,
    /// Bound address.
    pub addr: SocketAddr,
}

impl ProxyHandle {
    /// Stop accepting.
    pub fn stop(&self) {
        self.shutdown.notify_waiters();
    }
}

/// Bind and serve until [`ProxyHandle::stop`].
pub async fn start(bind: SocketAddr, state: ProxyState) -> Result<ProxyHandle, ProxyError> {
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|e| ProxyError::Bind(format!("{bind}: {e}")))?;
    let addr = listener
        .local_addr()
        .map_err(|e| ProxyError::Bind(e.to_string()))?;
    let shutdown = Arc::new(Notify::new());
    let shutdown_task = Arc::clone(&shutdown);
    let state = Arc::new(state);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_task.notified() => break,
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, _)) => {
                            let state = Arc::clone(&state);
                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(stream, &state).await {
                                    eprintln!("acowork-android proxy: {e}");
                                }
                            });
                        }
                        Err(e) => eprintln!("acowork-android proxy accept: {e}"),
                    }
                }
            }
        }
    });

    Ok(ProxyHandle { shutdown, addr })
}

/// Proxy failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyError {
    /// Bind failed.
    Bind(String),
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyError::Bind(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ProxyError {}

async fn handle_connection(mut stream: TcpStream, state: &ProxyState) -> Result<(), String> {
    let raw = read_http_request(&mut stream).await?;
    let (method, path_q, headers, body) = parse_http_request(&raw)?;
    let (path, query) = split_path_query(&path_q);

    // `/health` stays open so a local watchdog (and pre-enroll diagnostics)
    // can probe without a node_token. Everything else is an auth boundary.
    if method == "GET" && path == "/health" {
        let body = r#"{"ok":true,"role":"node"}"#;
        let resp = http_response(200, "application/json", body);
        stream
            .write_all(resp.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        return Ok(());
    }

    if let Some(resp) = authorize(state, &headers).await {
        stream
            .write_all(resp.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        return Ok(());
    }

    if method == "GET" && path == "/fs/browse" {
        let show_hidden = query
            .iter()
            .any(|(k, v)| k == "show_hidden" && (v == "true" || v == "1"));
        let browse_path = query
            .iter()
            .find(|(k, _)| k == "path")
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        let body = match browse_fs(browse_path, show_hidden) {
            Ok(json) => http_response(200, "application/json", &json),
            Err(msg) => http_response(400, "application/json", &format!(r#"{{"error":"{msg}"}}"#)),
        };
        stream
            .write_all(body.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        return Ok(());
    }

    if method == "PATCH" && path == "/node/name" {
        let resp = handle_rename(state, &body).await;
        stream
            .write_all(resp.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        return Ok(());
    }

    if let Some(rest) = path.strip_prefix("/agents/") {
        let (instance_id, suffix) = match rest.split_once('/') {
            Some((id, rest)) => (id, rest),
            None => (rest, ""),
        };
        let port = {
            let ports = state.ports.lock().await;
            ports.get(instance_id).copied()
        };
        let Some(port) = port else {
            let body =
                format!(r#"{{"error":"agent not running on this node","id":"{instance_id}"}}"#);
            let resp = http_response_extra(
                503,
                "application/json",
                &body,
                &[("x-error-origin", "node")],
            );
            stream
                .write_all(resp.as_bytes())
                .await
                .map_err(|e| e.to_string())?;
            return Ok(());
        };
        let query_suffix = if path_q.contains('?') {
            format!("?{}", path_q.split_once('?').map(|(_, q)| q).unwrap_or(""))
        } else {
            String::new()
        };
        let target = if suffix.is_empty() {
            format!("http://127.0.0.1:{port}/{query_suffix}")
        } else {
            format!("http://127.0.0.1:{port}/{suffix}{query_suffix}")
        };
        return forward(&mut stream, &method, &target, &headers, &body).await;
    }

    let resp = http_response(404, "text/plain", "not found");
    stream
        .write_all(resp.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Read one HTTP/1.x request (headers + body per Content-Length).
async fn read_http_request(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut buf = Vec::with_capacity(8 * 1024);
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(header_end) = find_header_end(&buf) {
            let content_length = content_length_of(&buf[..header_end]).unwrap_or(0);
            while buf.len() - header_end < content_length {
                let n = stream
                    .read(&mut tmp)
                    .await
                    .map_err(|e| format!("read body: {e}"))?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            break;
        }
        if buf.len() > 1024 * 1024 {
            return Err("request headers too large".into());
        }
    }
    if buf.is_empty() {
        return Err("empty request".into());
    }
    Ok(buf)
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn content_length_of(headers: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(headers).ok()?;
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("content-length:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

fn parse_http_request(raw: &[u8]) -> Result<(String, String, RequestHeaders, Vec<u8>), String> {
    let header_end = find_header_end(raw).ok_or_else(|| "incomplete headers".to_string())?;
    let header_text =
        std::str::from_utf8(&raw[..header_end]).map_err(|e| format!("utf8 headers: {e}"))?;
    let (method, path, headers) = parse_request_line(header_text)?;
    let body = raw[header_end..].to_vec();
    Ok((method, path, headers, body))
}

/// `PATCH /node/name` — `{ "nodeName": "gpu-2" }` (ADR-075 D4).
///
/// The node owns the file being written, so validation and persistence live
/// here; the Gateway only proxies. This mirrors the PC node's
/// `node_api::rename_node` — Desktop's node settings dialog speaks that one
/// contract to whichever kind of node it is pointed at, and an Android node
/// that does not answer it surfaces the node's own 404 in the dialog.
async fn handle_rename(state: &ProxyState, body: &[u8]) -> String {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RenameBody {
        node_name: String,
    }
    let requested = match serde_json::from_slice::<RenameBody>(body) {
        Ok(b) => b.node_name,
        Err(e) => {
            return http_response(
                400,
                "application/json",
                &serde_json::json!({ "error": format!("invalid body: {e}") }).to_string(),
            );
        }
    };
    let (status, payload) = {
        let mut id = state.identity.write().await;
        match id.set_name(&state.home, &requested) {
            Ok(changed) => {
                let name = id.node_name.clone();
                drop(id);
                if changed {
                    // Persisted first, announced second: a rename that reached
                    // the file but not the broker still survives the restart,
                    // while the republish is only what makes Desktop converge
                    // before the next heartbeat.
                    state.republish.notify_one();
                }
                (200, serde_json::json!({ "node_name": name }))
            }
            Err(IdentityError::Invalid(msg)) => (400, serde_json::json!({ "error": msg })),
            Err(e) => (500, serde_json::json!({ "error": e.to_string() })),
        }
    };
    http_response(status, "application/json", &payload.to_string())
}

async fn authorize(state: &ProxyState, headers: &[(String, String)]) -> Option<String> {
    let expected = {
        let id = state.identity.read().await;
        id.node_token.clone()
    };
    let Some(expected) = expected else {
        // Not enrolled yet — fail closed for anything that reached us
        // over the LAN (Gateway learns the endpoint from enroll).
        return Some(http_response(
            403,
            "application/json",
            r#"{"error":"node not enrolled"}"#,
        ));
    };
    let presented = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-acowork-node-token"))
        .map(|(_, v)| v.as_str());
    if presented == Some(expected.as_str()) {
        None
    } else {
        Some(http_response(
            403,
            "application/json",
            r#"{"error":"invalid node token"}"#,
        ))
    }
}

async fn forward(
    client: &mut TcpStream,
    method: &str,
    target: &str,
    headers: &RequestHeaders,
    body: &[u8],
) -> Result<(), String> {
    let url = target
        .strip_prefix("http://")
        .ok_or_else(|| format!("bad target {target}"))?;
    let (hostport, path) = url
        .split_once('/')
        .map(|(h, p)| (h, format!("/{p}")))
        .unwrap_or((url, "/".into()));
    let mut upstream = TcpStream::connect(hostport)
        .await
        .map_err(|e| format!("connect {hostport}: {e}"))?;

    let mut out = format!("{method} {path} HTTP/1.1\r\nHost: {hostport}\r\nConnection: close\r\n");
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if lower == "host"
            || lower == "connection"
            || lower == "keep-alive"
            || lower == "transfer-encoding"
            || lower == "te"
            || lower == "trailer"
            || lower == "upgrade"
            || lower == "proxy-connection"
            || lower == "content-length"
        {
            continue;
        }
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    out.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    upstream
        .write_all(out.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    if !body.is_empty() {
        upstream.write_all(body).await.map_err(|e| e.to_string())?;
    }
    let mut resp = Vec::new();
    upstream
        .read_to_end(&mut resp)
        .await
        .map_err(|e| e.to_string())?;
    client.write_all(&resp).await.map_err(|e| e.to_string())?;
    Ok(())
}

type RequestHeaders = Vec<(String, String)>;

fn parse_request_line(req: &str) -> Result<(String, String, RequestHeaders), String> {
    let mut lines = req.split("\r\n");
    let first = lines.next().ok_or_else(|| "empty request".to_string())?;
    let mut parts = first.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "missing method".to_string())?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| "missing path".to_string())?
        .to_string();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok((method, path, headers))
}

fn split_path_query(path_q: &str) -> (&str, Vec<(String, String)>) {
    match path_q.split_once('?') {
        Some((path, q)) => {
            let pairs = q
                .split('&')
                .filter_map(|pair| {
                    let (k, v) = pair.split_once('=')?;
                    Some((k.to_string(), urlencoding_decode(v)))
                })
                .collect();
            (path, pairs)
        }
        None => (path_q, Vec::new()),
    }
}

fn urlencoding_decode(s: &str) -> String {
    // Minimal: replace %2F and '+' — enough for fs browse paths.
    s.replace("%2F", "/").replace("%2f", "/").replace('+', " ")
}

fn http_response(status: u16, content_type: &str, body: &str) -> String {
    http_response_extra(status, content_type, body, &[])
}

fn http_response_extra(
    status: u16,
    content_type: &str,
    body: &str,
    extra: &[(&str, &str)],
) -> String {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (k, v) in extra {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    out.push_str(body);
    out
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FsBrowseEntry {
    name: String,
    #[serde(rename = "type")]
    entry_type: String,
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    children_count: Option<usize>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FsBrowseResponse {
    path: String,
    entries: Vec<FsBrowseEntry>,
}

fn browse_fs(requested: &str, show_hidden: bool) -> Result<String, String> {
    let requested = requested.trim();
    // Same contract as PC `acowork-node` / Gateway: empty and `/` are the
    // shortcut set, not a listing of `/`. Putting `/` in that set loops
    // RemoteFolderPicker, so volume roots have to appear as siblings of
    // HOME (Windows already does this with drive letters).
    if requested.is_empty() || requested == "/" {
        let resp = FsBrowseResponse {
            path: requested.to_string(),
            entries: root_entries(show_hidden),
        };
        return serde_json::to_string(&resp).map_err(|e| e.to_string());
    }
    if requested.contains("..") {
        return Err("path traversal rejected".into());
    }
    let dir = Path::new(requested);
    if !dir.is_dir() {
        return Err(format!("not a directory: {requested}"));
    }
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    let rd = std::fs::read_dir(dir).map_err(|e| e.to_string())?;
    for entry in rd.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !show_hidden && name.starts_with('.') {
            continue;
        }
        let meta = entry.metadata().ok();
        let is_dir = meta.as_ref().is_some_and(|m| m.is_dir());
        let abs = entry.path().to_string_lossy().replace('\\', "/");
        if is_dir {
            dirs.push(FsBrowseEntry {
                name,
                entry_type: "directory".into(),
                path: abs,
                size: None,
                children_count: Some(count_children(&entry.path(), show_hidden)),
            });
        } else {
            files.push(FsBrowseEntry {
                name,
                entry_type: "file".into(),
                path: abs,
                size: meta.map(|m| m.len()),
                children_count: None,
            });
        }
    }
    dirs.sort_by_key(|a| a.name.to_lowercase());
    files.sort_by_key(|a| a.name.to_lowercase());
    dirs.extend(files);
    let resp = FsBrowseResponse {
        path: requested.replace('\\', "/"),
        entries: dirs,
    };
    serde_json::to_string(&resp).map_err(|e| e.to_string())
}

/// Well-known Unix volume paths. Each is offered only when it exists —
/// `/var` on a PC node, `/sdcard` on a phone, nothing invented.
fn unix_volume_candidates() -> &'static [(&'static str, &'static str)] {
    &[
        ("tmp", "/tmp"),
        ("/var", "/var"),
        ("/opt", "/opt"),
        ("sdcard", "/sdcard"),
        ("storage", "/storage"),
    ]
}

/// A volume path is present if it is a directory we can stat, or a
/// symlink that exists in the namespace. Android `/sdcard` is a public
/// symlink whose target is often EACCES for `stat` under scoped storage;
/// `is_dir()` is then false even though the volume is the one users pick.
fn volume_exists(path: &Path) -> bool {
    if path.is_dir() {
        return true;
    }
    path.symlink_metadata()
        .map(|m| m.is_dir() || m.file_type().is_symlink())
        .unwrap_or(false)
}

fn push_browse_root(
    entries: &mut Vec<FsBrowseEntry>,
    name: String,
    path: &Path,
    show_hidden: bool,
) {
    if !volume_exists(path) {
        return;
    }
    let path_str = path.to_string_lossy().replace('\\', "/");
    if entries.iter().any(|e| e.path == path_str) {
        return;
    }
    entries.push(FsBrowseEntry {
        name,
        entry_type: "directory".into(),
        path: path_str,
        size: None,
        children_count: Some(count_children(path, show_hidden)),
    });
}

/// Starting points for empty/`/` browse. Same JSON shape and the same
/// empty-or-`/` shortcut contract as PC `acowork-node`. Unix extras are
/// probed with `is_dir` (like Windows drive letters): `/tmp` `/var`
/// `/opt` on a PC, `/sdcard` `/storage` when those volumes exist here.
fn root_entries(show_hidden: bool) -> Vec<FsBrowseEntry> {
    let mut entries = Vec::new();

    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .or_else(|_| {
            std::env::var("HOMEDRIVE")
                .and_then(|d| std::env::var("HOMEPATH").map(|p| format!("{d}{p}")))
        })
        .ok();

    if let Some(home_str) = &home {
        let home_path = Path::new(home_str);
        let name = home_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "Home".to_string());
        push_browse_root(&mut entries, name, home_path, show_hidden);
    }

    for (label, path) in unix_volume_candidates() {
        push_browse_root(&mut entries, (*label).into(), Path::new(path), show_hidden);
    }

    #[cfg(windows)]
    {
        for letter in 'A'..='Z' {
            let drive = format!("{letter}:/");
            let drive_path = Path::new(&drive);
            if drive_path.is_dir() {
                let children_count = count_children(drive_path, show_hidden);
                entries.push(FsBrowseEntry {
                    name: format!("{letter}:"),
                    entry_type: "directory".into(),
                    path: drive,
                    size: None,
                    children_count: Some(children_count),
                });
            }
        }
    }

    entries
}

fn count_children(path: &Path, show_hidden: bool) -> usize {
    std::fs::read_dir(path)
        .ok()
        .map(|rd| {
            rd.filter(|e| {
                e.as_ref()
                    .map(|e| show_hidden || !e.file_name().to_string_lossy().starts_with('.'))
                    .unwrap_or(false)
            })
            .count()
        })
        .unwrap_or(0)
}

/// Sync the port table from a process-table listing.
pub async fn sync_ports(ports: &PortTable, rows: &[(String, u16)]) {
    let mut map = ports.lock().await;
    map.clear();
    for (id, port) in rows {
        map.insert(id.clone(), *port);
    }
}

/// Helper to wrap identity in the shared cell.
pub fn shared_identity(identity: NodeIdentity) -> SharedIdentity {
    Arc::new(RwLock::new(identity))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Mutex;

    // Env mutation is process-global; serialize HOME-dependent tests.
    static HOME_LOCK: Mutex<()> = Mutex::new(());

    fn rename_state(tag: &str, node_name: &str) -> (ProxyState, Arc<Notify>, PathBuf) {
        let home = std::env::temp_dir().join(format!(
            "acowork-rename-{tag}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(&home).unwrap();
        let identity = NodeIdentity {
            node_id: "00000000-0000-4000-8000-000000000001".into(),
            node_name: node_name.into(),
            node_token: Some("nd-1".into()),
            gateway_addr: Some("127.0.0.1:19875".into()),
            enrollment: crate::node::EnrollmentState::Enrolled,
            created_at: 0,
            enrolled_at: None,
            enrolled_with: None,
        };
        identity.save(&home).unwrap();
        let republish = Arc::new(Notify::new());
        let state = ProxyState {
            identity: shared_identity(identity),
            ports: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            home: home.clone(),
            republish: Arc::clone(&republish),
        };
        (state, republish, home)
    }

    async fn wait_notified(notify: &Notify) -> bool {
        tokio::time::timeout(std::time::Duration::from_millis(50), notify.notified())
            .await
            .is_ok()
    }

    #[tokio::test]
    async fn rename_persists_and_asks_for_a_reannounce() {
        let (state, republish, home) = rename_state("ok", "phone-1");
        let resp = handle_rename(&state, br#"{"nodeName":"gpu-2"}"#).await;
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert!(resp.contains(r#""node_name":"gpu-2""#), "{resp}");

        // The file is the source of truth across a restart — that is the whole
        // point of letting the node, not the Gateway, perform the write.
        let on_disk = NodeIdentity::load(&home).unwrap().unwrap();
        assert_eq!(on_disk.node_name, "gpu-2");
        assert!(
            wait_notified(&republish).await,
            "a rename must republish info, or Desktop shows the old name until the next heartbeat"
        );
        let _ = fs::remove_dir_all(&home);
    }

    #[tokio::test]
    async fn rename_rejects_an_invalid_slug_without_touching_the_file() {
        let (state, republish, home) = rename_state("bad", "phone-1");
        let resp = handle_rename(&state, br#"{"nodeName":"Bad Name!"}"#).await;
        assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");
        assert!(resp.contains("error"), "{resp}");
        assert_eq!(state.identity.read().await.node_name, "phone-1");
        assert_eq!(NodeIdentity::load(&home).unwrap().unwrap().node_name, "phone-1");
        assert!(!wait_notified(&republish).await, "a rejected rename announces nothing");
        let _ = fs::remove_dir_all(&home);
    }

    #[tokio::test]
    async fn rename_to_the_current_name_is_a_quiet_success() {
        // ADR-075 D4 idempotence: the Gateway may retry, and a no-op must not
        // churn the retained snapshot.
        let (state, republish, home) = rename_state("same", "phone-1");
        let resp = handle_rename(&state, br#"{"nodeName":"phone-1"}"#).await;
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert!(!wait_notified(&republish).await);
        let _ = fs::remove_dir_all(&home);
    }

    #[tokio::test]
    async fn rename_without_the_camel_case_field_is_a_bad_request() {
        // The Gateway sends `nodeName`; a `node_name` body would silently
        // rename nothing if the field were optional.
        let (state, _republish, home) = rename_state("missing", "phone-1");
        let resp = handle_rename(&state, br#"{"node_name":"gpu-2"}"#).await;
        assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");
        assert_eq!(NodeIdentity::load(&home).unwrap().unwrap().node_name, "phone-1");
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn root_entries_include_home() {
        let _guard = HOME_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!(
            "acowork-fs-browse-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("marker.txt"), b"x").unwrap();

        unsafe {
            std::env::set_var("HOME", &dir);
        }
        let entries = root_entries(false);
        let want = dir.to_string_lossy().replace('\\', "/");
        assert!(
            entries.iter().any(|e| e.path == want),
            "expected HOME {want} in {entries:?}"
        );

        let json = browse_fs("", false).unwrap();
        assert!(json.contains(&want), "browse JSON missing HOME: {json}");
        let _ = fs::remove_dir_all(&dir);
    }

    fn entry_paths(json: &str) -> Vec<String> {
        serde_json::from_str::<serde_json::Value>(json)
            .ok()
            .and_then(|v| v.get("entries").cloned())
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|e| e.get("path")?.as_str().map(str::to_string))
            .collect()
    }

    #[test]
    fn empty_and_slash_share_shortcut_set() {
        let _guard = HOME_LOCK.lock().unwrap();
        let empty = entry_paths(&browse_fs("", false).unwrap());
        let slash = entry_paths(&browse_fs("/", false).unwrap());
        assert_eq!(
            empty, slash,
            "empty and `/` must match PC node shortcut contract"
        );
        assert!(
            !empty.iter().any(|p| p == "/"),
            "shortcut set must not contain `/` (RemoteFolderPicker loop)"
        );
    }

    #[test]
    fn existing_unix_volumes_are_offered() {
        let _guard = HOME_LOCK.lock().unwrap();
        assert!(
            unix_volume_candidates()
                .iter()
                .any(|(name, path)| *name == "sdcard" && *path == "/sdcard")
        );
        let entries = root_entries(false);
        for (name, path) in unix_volume_candidates() {
            let p = Path::new(path);
            if volume_exists(p) {
                assert!(
                    entries.iter().any(|e| e.path == *path),
                    "{name} ({path}) exists but is missing from {entries:?}"
                );
            }
        }
    }

    #[test]
    fn root_entries_paths_unique() {
        let _guard = HOME_LOCK.lock().unwrap();
        let entries = root_entries(true);
        let mut seen = std::collections::HashSet::new();
        for e in &entries {
            assert!(seen.insert(e.path.clone()), "duplicate path {}", e.path);
        }
    }
}
