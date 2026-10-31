//! Upgrade installed components through the existing installer and rollback path.

use super::COMPONENT_VERSION;
use super::packages::InstalledComponentManifest;

/// Last automatic-update outcome that needs the user's attention; empty when
/// the update succeeded or was not needed. Surfaced in `DualSenseStatus`.
static LAST_AUTO_UPDATE_ISSUE: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());

pub(crate) fn last_auto_update_issue() -> String {
    LAST_AUTO_UPDATE_ISSUE
        .lock()
        .map(|issue| issue.clone())
        .unwrap_or_default()
}

pub(crate) fn record_auto_update_issue(issue: Option<String>) {
    if let Some(issue) = issue.as_deref() {
        log::warn!("{issue}");
    }
    if let Ok(mut current) = LAST_AUTO_UPDATE_ISSUE.lock() {
        *current = issue.unwrap_or_default();
    }
}

/// Explains why the idle-time update did not run, or how it failed.
pub(crate) fn auto_update_issue(installed: &str, blocker: AutoUpdateBlocker<'_>) -> String {
    let target = COMPONENT_VERSION;
    match blocker {
        AutoUpdateBlocker::NoPackage => format!(
            "DS5-UPD-001: the DualSense component {installed} was not updated to {target} automatically: this Sunshine build has no {target} package source; update manually from a local package"
        ),
        AutoUpdateBlocker::Transport(detail) => format!(
            "DS5-UPD-002: the DualSense component {installed} was not updated to {target} automatically because shared USB/IP is not ready: {detail}"
        ),
        AutoUpdateBlocker::Failed(error) => format!(
            "DS5-UPD-003: the automatic DualSense component update {installed} -> {target} failed and was rolled back: {error}"
        ),
    }
}

pub(crate) enum AutoUpdateBlocker<'a> {
    NoPackage,
    Transport(&'a str),
    Failed(&'a str),
}

/// Parses the three numeric release components used for component upgrade ordering.
fn version(value: &str) -> Option<(u32, u32, u32)> {
    let mut parts = value.split('.');
    let result = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    );
    parts.next().is_none().then_some(result)
}

/// Offers upgrades only for a known sidecar protocol/file with a strictly older component version.
fn needs_update(manifest: Option<&InstalledComponentManifest>) -> bool {
    manifest.is_some_and(|manifest| {
        manifest.protocol == super::PROTOCOL_VERSION
            && manifest.sidecar_file == super::SIDECAR_EXE
            && version(&manifest.component_version)
                .zip(version(COMPONENT_VERSION))
                .is_some_and(|(installed, available)| installed < available)
    })
}

#[cfg(target_os = "windows")]
pub(crate) fn installed_update_needed() -> bool {
    use super::packages::{active_dir, component_root};
    // A previous directory is also an installed component when an interrupted
    // activation left active absent. The installer already knows how to recover it.
    let active = active_dir();
    let directory = if active.exists() {
        active
    } else {
        component_root().join("previous")
    };
    if !directory.join(super::SIDECAR_EXE).is_file() {
        return false;
    }
    let manifest = std::fs::read(directory.join("component.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok());
    needs_update(manifest.as_ref())
}

#[cfg(target_os = "windows")]
fn installed_component_version() -> String {
    super::packages::installed_component_manifest()
        .map(|manifest| manifest.component_version)
        .filter(|version| !version.is_empty())
        .unwrap_or_else(|| "(unknown)".to_string())
}

/// Updates an existing component only while idle and the shared transport is ready.
/// Automatic updates never deploy or repair the shared driver.
#[cfg(target_os = "windows")]
pub(crate) fn start_installed_component_update(app: tauri::AppHandle) {
    use super::COMPONENT_OPERATION;
    use super::elevated::{ElevatedOperation, run_elevated_operation};
    use super::packages::{manually_placed_sidecar_package, sidecar_package_manifest};
    use super::probe::ensure_no_active_session;
    use log::info;

    tauri::async_runtime::spawn(async move {
        loop {
            let Ok(operation) = COMPONENT_OPERATION.try_lock() else {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                continue;
            };
            if !installed_update_needed() {
                record_auto_update_issue(None);
                return;
            }
            let installed = installed_component_version();
            let Ok(package) = sidecar_package_manifest() else {
                // The host package, not the optional component installer,
                // supplies this pin. A newer standalone GUI must wait for a
                // matching Sunshine update; never reuse an older URL/digest.
                record_auto_update_issue(Some(auto_update_issue(
                    &installed,
                    AutoUpdateBlocker::NoPackage,
                )));
                return;
            };
            if package.download_url.is_empty() && manually_placed_sidecar_package().is_none() {
                record_auto_update_issue(Some(auto_update_issue(
                    &installed,
                    AutoUpdateBlocker::NoPackage,
                )));
                return;
            }
            if ensure_no_active_session().await.is_err() {
                drop(operation);
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                continue;
            }
            // Updates never repair shared drivers. Check before elevation and
            // download so an incompatible/busy transport cannot cause a dead end.
            let transport = crate::usbip::usbip_get_status().await;
            let transport_blocker = match &transport {
                Ok(status) if status.ready && status.attached_devices.is_empty() => None,
                Ok(status) if status.ready => {
                    Some("imported USB/IP devices must be released first".to_string())
                }
                Ok(status) if status.detail.is_empty() => {
                    Some("the transport check did not pass".to_string())
                }
                Ok(status) => Some(status.detail.clone()),
                Err(error) => Some(error.clone()),
            };
            if let Some(detail) = transport_blocker {
                record_auto_update_issue(Some(auto_update_issue(
                    &installed,
                    AutoUpdateBlocker::Transport(&detail),
                )));
                return;
            }
            info!("Updating the installed DualSense component to {COMPONENT_VERSION}");
            // Reuse the same authorization, verified download, staging and
            // rollback as manual updates. This mode never installs USB/IP.
            match run_elevated_operation(Some(&app), ElevatedOperation::Update, &[]).await {
                Ok(_) => {
                    info!("DualSense component update completed");
                    record_auto_update_issue(None);
                }
                Err(error) => record_auto_update_issue(Some(auto_update_issue(
                    &installed,
                    AutoUpdateBlocker::Failed(&error),
                ))),
            }
            // Never repeatedly prompt for elevation or retry a failed download
            // in the background. A later launch or manual update can retry.
            return;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_installed_older_components_are_automatically_updated() {
        assert!(!needs_update(None));
        let mut manifest = InstalledComponentManifest {
            protocol: super::super::PROTOCOL_VERSION,
            sidecar_file: super::super::SIDECAR_EXE.into(),
            ..Default::default()
        };
        for installed in ["1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0", "1.4.1", "1.4.2"] {
            manifest.component_version = installed.into();
            assert!(needs_update(Some(&manifest)));
        }
        for installed in [
            COMPONENT_VERSION,
            "1.5.0",
            "2.0.0",
            "invalid",
            "1.2.0-dev",
            "1.2",
        ] {
            manifest.component_version = installed.into();
            assert!(!needs_update(Some(&manifest)));
        }
        manifest.component_version = "1.2.0".into();
        manifest.protocol += 1;
        assert!(!needs_update(Some(&manifest)));
    }
}
