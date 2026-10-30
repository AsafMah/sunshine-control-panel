//! Client-to-host file uploads, agent side (wire kind 5, FILE_LIST).
//!
//! Sunshine (running as SYSTEM) stages the bytes a paired client uploads and,
//! after the client commits the batch, the client sends a small FILE_LIST
//! frame `{manifest, intent, count, total_size, x?, y?}` through the clipboard
//! channel. This module runs as the signed-in user: it resolves the manifest
//! over the loopback web API (bound to the stream session that delivered the
//! frame), copies every file into `Downloads\Moonlight Received`, marks each
//! one as downloaded from the internet, releases the manifest, and places the
//! received entries on the clipboard as CF_HDROP so the user can paste them.
//! Nothing is ever opened or executed.

use futures_util::StreamExt;
use log::{info, warn};
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;

use crate::sunshine::{create_https_client, get_local_sunshine_url};

const MAX_NAME_BYTES: usize = 180;
const MAX_REL_BYTES: usize = 240;
const MAX_REL_DEPTH: usize = 8;
const MAX_ITEMS: usize = 1000;
const RECEIVED_DIR: &str = "Moonlight Received";

#[derive(Debug, Deserialize, PartialEq)]
pub struct FileListFrame {
    pub manifest: String,
    pub intent: String,
    pub count: u64,
    pub total_size: u64,
    #[serde(default)]
    pub x: Option<f64>,
    #[serde(default)]
    pub y: Option<f64>,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct ManifestItem {
    pub index: u64,
    pub name: String,
    #[serde(default)]
    pub rel: String,
    pub size: u64,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    items: Vec<ManifestItem>,
}

/// One file to receive, already validated: `dir` is relative to the batch root.
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedItem {
    pub index: u64,
    pub dir: Vec<String>,
    pub name: String,
    pub size: u64,
}

fn is_forbidden(c: char) -> bool {
    let u = c as u32;
    u < 0x20
        || u == 0x7F
        || u == 0x200E
        || u == 0x200F
        || (0x202A..=0x202E).contains(&u)
        || (0x2066..=0x2069).contains(&u)
        || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
}

/// CON, PRN, AUX, NUL, COM0-9/¹²³, LPT0-9/¹²³, with or without an extension.
fn is_reserved_device(segment: &str) -> bool {
    let base: String = segment
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    if matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL") {
        return true;
    }
    let chars: Vec<char> = base.chars().collect();
    chars.len() == 4
        && (base.starts_with("COM") || base.starts_with("LPT"))
        && (chars[3].is_ascii_digit() || matches!(chars[3], '\u{00B9}' | '\u{00B2}' | '\u{00B3}'))
}

/// Same rules as Sunshine's file_upload_store::sanitize_name; returns None
/// when nothing safe remains.
pub fn sanitize_name(name: &str) -> Option<String> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let mut out: String = base
        .chars()
        .map(|c| if is_forbidden(c) { '_' } else { c })
        .collect();
    out = out.trim_start_matches(' ').to_string();
    while out.ends_with('.') || out.ends_with(' ') {
        out.pop();
    }
    if out.is_empty() {
        return None;
    }
    if is_reserved_device(&out) {
        out.insert(0, '_');
    }
    if out.len() > MAX_NAME_BYTES {
        let suffix = match out.rfind('.') {
            Some(i) if out.len() - i <= 16 && i > 0 => out[i..].to_string(),
            _ => String::new(),
        };
        let mut stem = String::new();
        for c in out.chars() {
            if stem.len() + c.len_utf8() + suffix.len() > MAX_NAME_BYTES {
                break;
            }
            stem.push(c);
        }
        while stem.ends_with('.') || stem.ends_with(' ') {
            stem.pop();
        }
        if stem.is_empty() {
            return None;
        }
        out = stem + &suffix;
    }
    Some(out)
}

/// Validates a relative directory (empty allowed) and returns its segments.
pub fn validate_rel(rel: &str) -> Option<Vec<String>> {
    if rel.is_empty() {
        return Some(Vec::new());
    }
    if rel.len() > MAX_REL_BYTES {
        return None;
    }
    let segments: Vec<&str> = rel.split(['/', '\\']).collect();
    if segments.len() > MAX_REL_DEPTH {
        return None;
    }
    let mut out = Vec::with_capacity(segments.len());
    for segment in segments {
        if segment.is_empty()
            || segment.starts_with(' ')
            || segment.ends_with('.')
            || segment.ends_with(' ')
            || segment.chars().any(is_forbidden)
            || is_reserved_device(segment)
        {
            return None;
        }
        out.push(segment.to_string());
    }
    Some(out)
}

/// Validates every manifest item again (the agent does not trust Sunshine's
/// copy of client-supplied names) and rejects case-insensitive collisions.
pub fn plan_items(items: &[ManifestItem]) -> Result<Vec<PlannedItem>, String> {
    if items.is_empty() || items.len() > MAX_ITEMS {
        return Err(format!("bad item count {}", items.len()));
    }
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let name = sanitize_name(&item.name).ok_or_else(|| "unsafe file name".to_string())?;
        if name != item.name {
            return Err(format!("file name changed by validation: {:?}", item.name));
        }
        let dir = validate_rel(&item.rel).ok_or_else(|| format!("unsafe folder {:?}", item.rel))?;
        let mut key = dir.join("/");
        key.push('/');
        key.push_str(&name);
        if !seen.insert(key.to_lowercase()) {
            return Err(format!("duplicate path {key:?}"));
        }
        out.push(PlannedItem {
            index: item.index,
            dir,
            name,
            size: item.size,
        });
    }
    Ok(out)
}

/// Whether the received files get their own folder (several files, or any
/// folder structure) instead of landing directly in the received directory.
pub fn needs_batch_folder(items: &[PlannedItem]) -> bool {
    items.len() > 1 || items.iter().any(|i| !i.dir.is_empty())
}

/// `dir/name`, or `dir/stem (n).ext` when that already exists (files or
/// pending ".part" downloads). Never returns an existing path.
pub fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    for n in 0..10_000u32 {
        let candidate = if n == 0 {
            name.to_string()
        } else {
            format!("{stem} ({n}){ext}")
        };
        let path = dir.join(&candidate);
        let part = dir.join(format!("{candidate}.part"));
        if !path.exists() && !part.exists() {
            return path;
        }
    }
    dir.join(format!("{stem}-{}{ext}", uuid::Uuid::new_v4()))
}

/// Paths to place on the clipboard: files directly under the root plus each
/// distinct top-level folder.
pub fn top_level_entries(
    root: &Path,
    items: &[PlannedItem],
    final_names: &[String],
) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut folders = HashSet::new();
    for (item, final_name) in items.iter().zip(final_names) {
        match item.dir.first() {
            None => out.push(root.join(final_name)),
            Some(top) => {
                if folders.insert(top.to_lowercase()) {
                    out.push(root.join(top));
                }
            }
        }
    }
    out
}

fn batch_folder_name() -> String {
    chrono::Local::now()
        .format("Moonlight %Y-%m-%d %H%M%S")
        .to_string()
}

#[cfg(windows)]
fn is_reparse_point(path: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    std::fs::symlink_metadata(path)
        .map(|m| m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
        .unwrap_or(false)
}

#[cfg(not(windows))]
fn is_reparse_point(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

/// Creates `root/segments...` one level at a time, refusing to traverse any
/// existing reparse point (junction/symlink) planted inside the tree.
fn create_dirs_safely(root: &Path, segments: &[String]) -> Result<PathBuf, String> {
    let mut dir = root.to_path_buf();
    for segment in segments {
        dir.push(segment);
        if dir.exists() {
            if is_reparse_point(&dir) || !dir.is_dir() {
                return Err(format!("refusing to write through {}", dir.display()));
            }
        } else {
            std::fs::create_dir(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        }
    }
    Ok(dir)
}

/// Mark-of-the-Web: Windows treats the file as downloaded from the internet.
#[cfg(windows)]
pub fn mark_from_internet(path: &Path) -> Result<(), String> {
    let mut stream = path.as_os_str().to_owned();
    stream.push(":Zone.Identifier");
    std::fs::write(PathBuf::from(stream), b"[ZoneTransfer]\r\nZoneId=3\r\n")
        .map_err(|e| format!("Zone.Identifier: {e}"))
}

#[cfg(not(windows))]
pub fn mark_from_internet(_path: &Path) -> Result<(), String> {
    Ok(())
}

/// Writes CF_HDROP plus "Preferred DropEffect" = DROPEFFECT_COPY in one
/// clipboard transaction.
#[cfg(windows)]
pub fn set_clipboard_files(paths: &[PathBuf]) -> Result<(), String> {
    use clipboard_win::{Clipboard, raw};
    const DROPEFFECT_COPY: u32 = 1;
    let strings: Vec<String> = paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    let _clip = Clipboard::new_attempts(10).map_err(|e| format!("open clipboard: {e}"))?;
    raw::empty().map_err(|e| format!("empty clipboard: {e}"))?;
    raw::set_file_list(&strings).map_err(|e| format!("set CF_HDROP: {e}"))?;
    if let Some(format) = raw::register_format("Preferred DropEffect") {
        raw::set_without_clear(format.get(), &DROPEFFECT_COPY.to_le_bytes())
            .map_err(|e| format!("set Preferred DropEffect: {e}"))?;
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn set_clipboard_files(_paths: &[PathBuf]) -> Result<(), String> {
    Err("file clipboard is only supported on Windows".to_string())
}

#[cfg(windows)]
fn notify(title: &str, body: &str) {
    let result = tauri_winrt_notification::Toast::new("com.212333.app")
        .title(title)
        .text1(body)
        .show();
    if let Err(e) = result {
        warn!("file upload toast failed: {e}");
    }
}

#[cfg(not(windows))]
fn notify(title: &str, body: &str) {
    info!("{title}: {body}");
}

pub fn parse_frame(payload: &[u8]) -> Result<FileListFrame, String> {
    let frame: FileListFrame =
        serde_json::from_slice(payload).map_err(|e| format!("bad FILE_LIST JSON: {e}"))?;
    let hex = frame.manifest.len() == 64
        && frame
            .manifest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !hex {
        return Err("bad manifest id".to_string());
    }
    if frame.intent != "drop" && frame.intent != "clipboard" {
        return Err(format!("unknown intent {:?}", frame.intent));
    }
    Ok(frame)
}

async fn local_url(path: &str, sid: u32) -> Result<String, String> {
    let base = get_local_sunshine_url().await?;
    Ok(format!("{}{path}?sid={sid}", base.trim_end_matches('/')))
}

async fn download_item(
    client: &reqwest::Client,
    manifest: &str,
    sid: u32,
    item: &PlannedItem,
    target: &Path,
) -> Result<(), String> {
    let url = local_url(
        &format!(
            "/api/v1/file-transfer/manifests/{manifest}/items/{}",
            item.index
        ),
        sid,
    )
    .await?;
    let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }

    let mut part = target.as_os_str().to_owned();
    part.push(".part");
    let part = PathBuf::from(part);
    let result = async {
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&part)
            .await
            .map_err(|e| format!("create {}: {e}", part.display()))?;
        let mut written: u64 = 0;
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| e.to_string())?;
            written += chunk.len() as u64;
            if written > item.size {
                return Err("host sent more data than announced".to_string());
            }
            file.write_all(&chunk).await.map_err(|e| e.to_string())?;
        }
        file.flush().await.map_err(|e| e.to_string())?;
        drop(file);
        if written != item.size {
            return Err(format!("incomplete ({written} of {} bytes)", item.size));
        }
        if let Err(e) = mark_from_internet(&part) {
            // FAT and some network volumes have no alternate data streams.
            warn!("could not mark {} as downloaded: {e}", part.display());
        }
        if target.exists() {
            return Err(format!("{} appeared while downloading", target.display()));
        }
        std::fs::rename(&part, target).map_err(|e| format!("rename: {e}"))
    }
    .await;
    if result.is_err() {
        let _ = std::fs::remove_file(&part);
    }
    result
}

async fn receive(frame: FileListFrame, sid: u32) -> Result<Vec<PathBuf>, String> {
    let client = create_https_client()?;
    let manifest_url = local_url(
        &format!("/api/v1/file-transfer/manifests/{}", frame.manifest),
        sid,
    )
    .await?;
    let resp = client
        .get(&manifest_url)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("manifest lookup: HTTP {}", resp.status()));
    }
    let manifest: Manifest = resp
        .json()
        .await
        .map_err(|e| format!("manifest JSON: {e}"))?;
    let items = plan_items(&manifest.items)?;

    let downloads = dirs::download_dir()
        .or_else(dirs::home_dir)
        .ok_or_else(|| "no Downloads folder".to_string())?;
    let received = create_dirs_safely(&downloads, &[RECEIVED_DIR.to_string()])?;
    let root = if needs_batch_folder(&items) {
        let folder = unique_path(&received, &batch_folder_name());
        std::fs::create_dir(&folder).map_err(|e| format!("create {}: {e}", folder.display()))?;
        folder
    } else {
        received
    };

    let mut final_names = Vec::with_capacity(items.len());
    for item in &items {
        let dir = create_dirs_safely(&root, &item.dir)?;
        let target = unique_path(&dir, &item.name);
        download_item(&client, &frame.manifest, sid, item, &target).await?;
        final_names.push(
            target
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        );
    }

    let _ = client.delete(&manifest_url).send().await;
    Ok(top_level_entries(&root, &items, &final_names))
}

/// Entry point from the clipboard SSE pump for a kind-5 frame. `sid` is the
/// stream session from the SSE event id; frames without one are dropped.
pub fn handle_file_list(payload: Vec<u8>, sid: Option<u32>) {
    let Some(sid) = sid else {
        warn!("FILE_LIST without a stream session id; dropped");
        return;
    };
    let frame = match parse_frame(&payload) {
        Ok(f) => f,
        Err(e) => {
            warn!("FILE_LIST rejected: {e}");
            return;
        }
    };
    tauri::async_runtime::spawn(async move {
        let count = frame.count;
        match receive(frame, sid).await {
            Ok(entries) => {
                let placed =
                    tauri::async_runtime::spawn_blocking(move || set_clipboard_files(&entries))
                        .await
                        .map_err(|e| e.to_string())
                        .and_then(|r| r);
                match placed {
                    Ok(()) => {
                        info!("received {count} file(s) from the client; placed on the clipboard");
                        notify(
                            "Files received from Moonlight",
                            &format!(
                                "{count} file(s) saved to Downloads\\{RECEIVED_DIR}. Paste with Ctrl+V."
                            ),
                        );
                    }
                    Err(e) => {
                        warn!("received files but could not set the clipboard: {e}");
                        notify(
                            "Files received from Moonlight",
                            &format!("{count} file(s) saved to Downloads\\{RECEIVED_DIR}."),
                        );
                    }
                }
            }
            Err(e) => {
                warn!("receiving files from the client failed: {e}");
                notify("Couldn't receive files from Moonlight", &e);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(index: u64, name: &str, rel: &str, size: u64) -> ManifestItem {
        ManifestItem {
            index,
            name: name.to_string(),
            rel: rel.to_string(),
            size,
        }
    }

    #[test]
    fn sanitizes_names_like_sunshine() {
        assert_eq!(sanitize_name("save.sav").as_deref(), Some("save.sav"));
        assert_eq!(
            sanitize_name("..\\..\\evil.exe").as_deref(),
            Some("evil.exe")
        );
        assert_eq!(sanitize_name("a:b*c?.txt").as_deref(), Some("a_b_c_.txt"));
        assert_eq!(sanitize_name("con.txt").as_deref(), Some("_con.txt"));
        assert_eq!(
            sanitize_name("COM\u{00B9}.bin").as_deref(),
            Some("_COM\u{00B9}.bin")
        );
        assert_eq!(sanitize_name("trail. . ").as_deref(), Some("trail"));
        assert_eq!(
            sanitize_name("x\u{202E}txt.exe").as_deref(),
            Some("x_txt.exe")
        );
        assert_eq!(sanitize_name(".."), None);
        assert!(sanitize_name(&("a".repeat(400) + ".txt")).unwrap().len() <= MAX_NAME_BYTES);
    }

    #[test]
    fn rejects_unsafe_relative_folders() {
        assert_eq!(validate_rel(""), Some(vec![]));
        assert_eq!(
            validate_rel("Saves\\slot1"),
            Some(vec!["Saves".into(), "slot1".into()])
        );
        for bad in [
            "..",
            "a/../b",
            "/abs",
            "\\\\server\\share",
            "C:x",
            "a//b",
            "a/b.",
            "a/CON",
            "a/nul.txt",
            "a:s",
            "a/\u{0001}",
            "a/b/c/d/e/f/g/h/i",
        ] {
            assert_eq!(validate_rel(bad), None, "{bad}");
        }
    }

    #[test]
    fn plans_items_and_rejects_tampering() {
        let plan = plan_items(&[item(0, "a.txt", "", 1), item(1, "b.sav", "Saves/x", 2)]).unwrap();
        assert_eq!(plan[1].dir, vec!["Saves".to_string(), "x".to_string()]);
        assert!(needs_batch_folder(&plan));
        assert!(!needs_batch_folder(&plan[..1]));
        assert!(plan_items(&[item(0, "Save.txt", "", 1), item(1, "save.TXT", "", 1)]).is_err());
        assert!(
            plan_items(&[item(0, "../x", "", 1)]).is_err(),
            "name not already sanitized"
        );
        assert!(plan_items(&[item(0, "x", "../up", 1)]).is_err());
        assert!(plan_items(&[]).is_err());
    }

    #[test]
    fn unique_paths_never_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"x").unwrap();
        std::fs::write(dir.path().join("a (1).txt.part"), b"x").unwrap();
        assert_eq!(unique_path(dir.path(), "b.txt"), dir.path().join("b.txt"));
        assert_eq!(
            unique_path(dir.path(), "a.txt"),
            dir.path().join("a (2).txt")
        );
        assert_eq!(unique_path(dir.path(), "noext"), dir.path().join("noext"));
    }

    #[test]
    fn top_level_entries_collapse_folders() {
        let plan = plan_items(&[
            item(0, "a.txt", "", 1),
            item(1, "b", "Saves", 1),
            item(2, "c", "saves/deep", 1),
            item(3, "d", "Other", 1),
        ])
        .unwrap();
        let root = Path::new("R");
        let names: Vec<String> = vec!["a (1).txt".into(), "b".into(), "c".into(), "d".into()];
        assert_eq!(
            top_level_entries(root, &plan, &names),
            vec![
                root.join("a (1).txt"),
                root.join("Saves"),
                root.join("Other")
            ]
        );
    }

    #[test]
    fn parses_frames() {
        let m = "a".repeat(64);
        let ok = format!(
            r#"{{"manifest":"{m}","intent":"drop","count":2,"total_size":9,"x":0.5,"y":0.25}}"#
        );
        let f = parse_frame(ok.as_bytes()).unwrap();
        assert_eq!(f.x, Some(0.5));
        assert!(
            parse_frame(br#"{"manifest":"../x","intent":"drop","count":1,"total_size":1}"#)
                .is_err()
        );
        let bad_intent = format!(r#"{{"manifest":"{m}","intent":"run","count":1,"total_size":1}}"#);
        assert!(parse_frame(bad_intent.as_bytes()).is_err());
    }

    #[test]
    fn refuses_to_write_through_existing_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Saves"), b"x").unwrap();
        assert!(create_dirs_safely(dir.path(), &["Saves".into(), "a".into()]).is_err());
        let made = create_dirs_safely(dir.path(), &["New".into(), "a".into()]).unwrap();
        assert!(made.is_dir());
    }

    #[cfg(windows)]
    #[test]
    fn marks_files_from_the_internet() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.bin");
        std::fs::write(&path, b"x").unwrap();
        mark_from_internet(&path).unwrap();
        let mut stream = path.as_os_str().to_owned();
        stream.push(":Zone.Identifier");
        let zone = std::fs::read_to_string(PathBuf::from(stream)).unwrap();
        assert!(zone.contains("ZoneId=3"));
    }
}
