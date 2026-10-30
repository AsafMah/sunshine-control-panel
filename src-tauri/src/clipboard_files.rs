//! Host -> client file copy/paste (copy-then-paste, not lazy virtual files).
//!
//! When the host user copies files in Explorer, the agent registers one
//! file-transfer offer per file, bound to the single paired client that is
//! streaming, and sends that client a FILE_LIST frame (wire kind 5) naming
//! them. The client downloads the files to a temporary folder and puts them
//! on its own clipboard. With no stream, or more than one, nothing is sent.
//!
//! Files this agent itself placed on the clipboard (received from the client,
//! see file_upload_inbox) are never offered back.

use log::{debug, info, warn};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::sunshine::{SessionInfo, create_https_client, get_local_sunshine_url};

/// Files copied on the host are downloaded eagerly by the client, so keep
/// copies small; larger transfers should use the Explorer "send to client" entry.
pub const MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_ITEMS: usize = 200;
const MAX_DEPTH: usize = 8;
/// Leaves room for the 10-byte wire header inside one control packet.
const MAX_PAYLOAD_BYTES: usize = 60_000;

static LAST_WRITTEN: Mutex<Option<Vec<String>>> = Mutex::new(None);

/// Bumped on every file clipboard change; an offer task only posts its file
/// list if no newer copy happened meanwhile, so the client ends up with the
/// host's latest copy even when an older, larger copy finishes later.
static OFFER_GENERATION: AtomicU64 = AtomicU64::new(0);

pub fn next_generation() -> u64 {
    OFFER_GENERATION.fetch_add(1, Ordering::SeqCst) + 1
}

pub fn is_current(generation: u64) -> bool {
    OFFER_GENERATION.load(Ordering::SeqCst) == generation
}

fn normalize(paths: &[String]) -> Vec<String> {
    let mut out: Vec<String> = paths
        .iter()
        .map(|p| p.trim_end_matches(['\\', '/']).to_lowercase())
        .collect();
    out.sort();
    out
}

/// Records the file list the agent just put on the clipboard.
pub fn remember_written(paths: &[PathBuf]) {
    let list: Vec<String> = paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    *LAST_WRITTEN.lock().unwrap_or_else(|e| e.into_inner()) = Some(normalize(&list));
}

/// True when `paths` is exactly what the agent itself last wrote.
pub fn is_own_write(paths: &[String]) -> bool {
    LAST_WRITTEN
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .is_some_and(|last| *last == normalize(paths))
}

#[derive(Debug, Clone, PartialEq)]
pub struct LocalFile {
    pub path: PathBuf,
    pub name: String,
    pub rel: String,
    pub size: u64,
}

#[cfg(windows)]
fn is_reparse_point(path: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    std::fs::symlink_metadata(path)
        .map(|m| m.file_attributes() & 0x400 != 0)
        .unwrap_or(true)
}

#[cfg(not(windows))]
fn is_reparse_point(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(true)
}

fn walk(
    dir: &Path,
    rel: &str,
    depth: usize,
    out: &mut Vec<LocalFile>,
    total: &mut u64,
) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err("folders are nested too deeply".to_string());
    }
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| format!("read {}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        if is_reparse_point(&path) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            walk(&path, &format!("{rel}/{name}"), depth + 1, out, total)?;
        } else if path.is_file() {
            add(out, total, path, name, rel.to_string())?;
        }
    }
    Ok(())
}

fn add(
    out: &mut Vec<LocalFile>,
    total: &mut u64,
    path: PathBuf,
    name: String,
    rel: String,
) -> Result<(), String> {
    let size = std::fs::metadata(&path)
        .map(|m| m.len())
        .map_err(|e| e.to_string())?;
    *total += size;
    out.push(LocalFile {
        path,
        name,
        rel,
        size,
    });
    if out.len() > MAX_ITEMS {
        return Err(format!("more than {MAX_ITEMS} files"));
    }
    if *total > MAX_TOTAL_BYTES {
        return Err("more than 512 MB".to_string());
    }
    Ok(())
}

/// Expands the copied paths (folders keep their structure; links are skipped).
pub fn plan_files(paths: &[String]) -> Result<Vec<LocalFile>, String> {
    let mut out = Vec::new();
    let mut total = 0u64;
    for raw in paths {
        let path = PathBuf::from(raw);
        if is_reparse_point(&path) {
            continue;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .ok_or_else(|| format!("unsupported path {raw}"))?;
        if path.is_dir() {
            walk(&path, &name, 1, &mut out, &mut total)?;
        } else if path.is_file() {
            add(&mut out, &mut total, path, name, String::new())?;
        }
    }
    if out.is_empty() {
        return Err("no files".to_string());
    }
    Ok(out)
}

/// The one running session to send to: (session id, client uuid).
pub fn single_target(sessions: &[SessionInfo]) -> Option<(u32, String)> {
    let running: Vec<&SessionInfo> = sessions
        .iter()
        .filter(|s| s.state == "RUNNING" && !s.client_uuid.is_empty() && s.session_id > 0)
        .collect();
    match running.as_slice() {
        [only] => Some((only.session_id as u32, only.client_uuid.clone())),
        _ => None,
    }
}

#[derive(Debug, Serialize, PartialEq)]
pub struct OfferedItem {
    pub id: String,
    pub name: String,
    pub rel: String,
    pub size: u64,
}

pub fn build_payload(items: &[OfferedItem]) -> Result<Vec<u8>, String> {
    let total: u64 = items.iter().map(|i| i.size).sum();
    let payload = serde_json::to_vec(&serde_json::json!({
        "intent": "clipboard",
        "count": items.len(),
        "total_size": total,
        "items": items,
    }))
    .map_err(|e| e.to_string())?;
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err("file list too long for one clipboard frame".to_string());
    }
    Ok(payload)
}

async fn register_offer(
    client: &reqwest::Client,
    base: &str,
    file: &LocalFile,
    client_uuid: &str,
) -> Result<String, String> {
    let resp = client
        .post(format!(
            "{}/api/v1/file-transfer/offers",
            base.trim_end_matches('/')
        ))
        .json(
            &serde_json::json!({ "path": file.path.to_string_lossy(), "client_uuid": client_uuid }),
        )
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!(
            "HTTP {status} {}",
            body["error"].as_str().unwrap_or("")
        ));
    }
    body["id"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| "offer response without id".to_string())
}

async fn offer(paths: Vec<String>, generation: u64) -> Result<(), String> {
    let sessions = crate::sunshine::get_active_sessions().await?;
    let Some((sid, client_uuid)) = single_target(&sessions) else {
        debug!("file clipboard: not exactly one running stream; not offered");
        return Ok(());
    };
    let files = tauri::async_runtime::spawn_blocking(move || plan_files(&paths))
        .await
        .map_err(|e| e.to_string())??;

    let base = get_local_sunshine_url().await?;
    let client = create_https_client()?;
    let mut items = Vec::with_capacity(files.len());
    for file in &files {
        let id = register_offer(&client, &base, file, &client_uuid).await?;
        items.push(OfferedItem {
            id,
            name: file.name.clone(),
            rel: file.rel.clone(),
            size: file.size,
        });
    }
    let payload = build_payload(&items)?;
    if !is_current(generation) {
        debug!("file clipboard changed while offering; this copy is no longer sent");
        return Ok(());
    }
    crate::clipboard::post_file_list_payload(payload, sid).await?;
    info!(
        "offered {} copied file(s) to the streaming client",
        items.len()
    );
    Ok(())
}

/// Called by the clipboard watcher for a clipboard holding only files.
pub fn handle_local_files(paths: Vec<String>) {
    // Any file clipboard, ours included, supersedes offers still in flight.
    let generation = next_generation();
    if is_own_write(&paths) {
        debug!("file clipboard is our own received files; not offered back");
        return;
    }
    tauri::async_runtime::spawn(async move {
        if let Err(e) = offer(paths, generation).await {
            warn!("offering copied files to the client failed: {e}");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(id: i32, state: &str, uuid: &str) -> SessionInfo {
        SessionInfo {
            session_id: id,
            state: state.to_string(),
            client_uuid: uuid.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn needs_exactly_one_running_session() {
        assert_eq!(single_target(&[]), None);
        assert_eq!(
            single_target(&[session(3, "RUNNING", "a"), session(4, "STOPPED", "b")]),
            Some((3, "a".to_string()))
        );
        assert_eq!(
            single_target(&[session(3, "RUNNING", "a"), session(4, "RUNNING", "b")]),
            None
        );
        assert_eq!(single_target(&[session(3, "RUNNING", "")]), None);
    }

    #[test]
    fn plans_files_and_folders_with_caps() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"hello").unwrap();
        std::fs::create_dir_all(dir.path().join("Saves/slot")).unwrap();
        std::fs::write(dir.path().join("Saves/slot/g.sav"), b"123").unwrap();
        let p = |s: &str| dir.path().join(s).to_string_lossy().into_owned();
        let files = plan_files(&[p("a.txt"), p("Saves")]).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[1].rel, "Saves/slot");
        assert_eq!(files[1].size, 3);

        for i in 0..=MAX_ITEMS {
            std::fs::write(dir.path().join(format!("many{i}")), b"").unwrap();
        }
        assert!(plan_files(&[dir.path().to_string_lossy().into_owned()]).is_err());
    }

    #[test]
    fn payload_fits_one_frame() {
        let item = |n: usize| OfferedItem {
            id: "a".repeat(64),
            name: format!("file{n}.bin"),
            rel: String::new(),
            size: 1,
        };
        let small: Vec<_> = (0..3).map(item).collect();
        let json: serde_json::Value =
            serde_json::from_slice(&build_payload(&small).unwrap()).unwrap();
        assert_eq!(json["intent"], "clipboard");
        assert_eq!(json["count"], 3);
        assert_eq!(json["total_size"], 3);
        let huge: Vec<_> = (0..1000).map(item).collect();
        assert!(build_payload(&huge).is_err());
    }

    #[test]
    fn only_the_newest_copy_is_offered() {
        let first = next_generation();
        let second = next_generation();
        assert!(!is_current(first));
        assert!(is_current(second));
    }

    #[test]
    fn own_writes_are_not_offered_back() {
        remember_written(&[PathBuf::from(
            "C:\\Users\\x\\Downloads\\Moonlight Received\\a.txt",
        )]);
        assert!(is_own_write(&[
            "c:\\users\\x\\downloads\\moonlight received\\A.TXT".to_string()
        ]));
        assert!(!is_own_write(&["C:\\other.txt".to_string()]));
    }
}
