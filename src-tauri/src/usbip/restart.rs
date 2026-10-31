//! Detects a USB/IP driver change that only completes after Windows restarts.
//!
//! A vetoed driver removal leaves the usbip2 services pended for deletion.
//! Reinstalling then "reactivates" them, which clears every live marker while
//! the running driver still cannot be replaced. `usbip.exe port` succeeding
//! and file hashes matching are therefore not proof of availability, so the
//! elevated maintenance paths record what they observed, keyed to this boot.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub(crate) const RESTART_CODE: &str = "USBIP-SETUP-010";
const MARKER_NAME: &str = "usbip-restart-required.json";
/// Boot time is derived from wall clock minus uptime; allow for clock adjustments.
const BOOT_TOLERANCE_SECS: i64 = 120;
pub(crate) const DRIVER_SERVICES: [&str; 2] = ["usbip2_ude", "usbip2_filter"];
/// DN_NEED_RESTART and CM_PROB_NEED_RESTART from cfg.h.
const DN_NEED_RESTART: u32 = 0x0000_0100;
const CM_PROB_NEED_RESTART: u32 = 14;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct RestartMarker {
    pub(crate) boot_epoch_secs: i64,
    pub(crate) reason: String,
}

/// Everything the decision needs, gathered separately so it can be faked in tests.
#[derive(Clone, Debug, Default)]
pub(crate) struct RestartEvidence {
    /// Services whose `DeleteFlag` is set (pended for deletion).
    pub(crate) services_pending_deletion: Vec<String>,
    /// (instance id, devnode status flags, problem code) of the VHCI devnodes.
    pub(crate) devnodes: Vec<(String, u32, u32)>,
    pub(crate) marker: Option<RestartMarker>,
    pub(crate) boot_epoch_secs: i64,
}

pub(crate) fn pending_restart_reason(evidence: &RestartEvidence) -> Option<String> {
    if !evidence.services_pending_deletion.is_empty() {
        return Some(format!(
            "driver service {} is pending deletion",
            evidence.services_pending_deletion.join(", ")
        ));
    }
    if let Some((instance, _, _)) = evidence.devnodes.iter().find(|(_, status, problem)| {
        status & DN_NEED_RESTART != 0 || *problem == CM_PROB_NEED_RESTART
    }) {
        return Some(format!("device {instance} needs a restart"));
    }
    evidence
        .marker
        .as_ref()
        .filter(|marker| {
            (marker.boot_epoch_secs - evidence.boot_epoch_secs).abs() <= BOOT_TOLERANCE_SECS
        })
        .map(|marker| marker.reason.clone())
}

pub(crate) fn restart_detail(reason: &str) -> String {
    format!(
        "{RESTART_CODE}: Windows must restart to finish the USB/IP driver change ({reason}). \
         USB/IP is not available until then, even if usbip.exe still responds."
    )
}

fn marker_path(directory: &Path) -> PathBuf {
    directory.join(MARKER_NAME)
}

pub(crate) fn read_marker(directory: &Path) -> Option<RestartMarker> {
    serde_json::from_slice(&std::fs::read(marker_path(directory)).ok()?).ok()
}

pub(crate) fn write_marker(directory: &Path, marker: &RestartMarker) -> Result<(), String> {
    std::fs::create_dir_all(directory)
        .and_then(|_| {
            std::fs::write(
                marker_path(directory),
                serde_json::to_vec_pretty(marker).unwrap_or_default(),
            )
        })
        .map_err(|error| format!("{RESTART_CODE}: unable to record the pending restart: {error}"))
}

fn marker_directory() -> PathBuf {
    crate::dualsense::component_root()
}

#[cfg(target_os = "windows")]
pub(crate) fn boot_epoch_secs() -> i64 {
    let uptime = unsafe { windows::Win32::System::SystemInformation::GetTickCount64() } / 1000;
    chrono::Utc::now().timestamp() - uptime as i64
}

#[cfg(target_os = "windows")]
fn services_pending_deletion() -> Vec<String> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    DRIVER_SERVICES
        .iter()
        .filter(|name| {
            hklm.open_subkey_with_flags(
                format!(r"SYSTEM\CurrentControlSet\Services\{name}"),
                KEY_READ,
            )
            .ok()
            .and_then(|key| key.get_value::<u32, _>("DeleteFlag").ok())
            .is_some_and(|flag| flag != 0)
        })
        .map(|name| name.to_string())
        .collect()
}

#[cfg(target_os = "windows")]
fn devnode_states(instances: &[String]) -> Vec<(String, u32, u32)> {
    use windows::Win32::Devices::DeviceAndDriverInstallation::{
        CM_DEVNODE_STATUS_FLAGS, CM_Get_DevNode_Status, CM_LOCATE_DEVNODE_NORMAL,
        CM_Locate_DevNodeW, CM_PROB, CR_SUCCESS,
    };
    use windows::core::PCWSTR;

    instances
        .iter()
        .filter_map(|instance| {
            let encoded: Vec<u16> = instance.encode_utf16().chain(Some(0)).collect();
            let mut devinst = 0u32;
            let located = unsafe {
                CM_Locate_DevNodeW(
                    &mut devinst,
                    PCWSTR(encoded.as_ptr()),
                    CM_LOCATE_DEVNODE_NORMAL,
                )
            };
            if located != CR_SUCCESS {
                return None;
            }
            let mut status = CM_DEVNODE_STATUS_FLAGS(0);
            let mut problem = CM_PROB(0);
            let result = unsafe { CM_Get_DevNode_Status(&mut status, &mut problem, devinst, 0) };
            (result == CR_SUCCESS).then(|| (instance.clone(), status.0, problem.0))
        })
        .collect()
}

#[cfg(target_os = "windows")]
pub(crate) fn gather_evidence() -> RestartEvidence {
    RestartEvidence {
        services_pending_deletion: services_pending_deletion(),
        devnodes: super::device::enumerate_vhci_devnodes()
            .map(|nodes| devnode_states(&nodes))
            .unwrap_or_default(),
        marker: read_marker(&marker_directory()),
        boot_epoch_secs: boot_epoch_secs(),
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn pending_restart() -> Option<String> {
    pending_restart_reason(&gather_evidence())
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn pending_restart() -> Option<String> {
    None
}

/// Called from the elevated maintenance paths once a restart becomes necessary.
#[cfg(target_os = "windows")]
pub(crate) fn record_restart_required(reason: &str) {
    let marker = RestartMarker {
        boot_epoch_secs: boot_epoch_secs(),
        reason: reason.to_string(),
    };
    log::warn!("{}", restart_detail(reason));
    if let Err(error) = write_marker(&marker_directory(), &marker) {
        log::warn!("{error}");
    }
}

/// Records services pended for deletion before a reinstall reactivates them.
#[cfg(target_os = "windows")]
pub(crate) fn record_live_pending_deletion() -> Option<String> {
    let pending = services_pending_deletion();
    if pending.is_empty() {
        return None;
    }
    let reason = format!("driver service {} is pending deletion", pending.join(", "));
    record_restart_required(&reason);
    Some(reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOT: i64 = 1_793_000_000;

    #[test]
    fn pending_deletion_requires_a_restart() {
        let evidence = RestartEvidence {
            services_pending_deletion: vec!["usbip2_ude".into(), "usbip2_filter".into()],
            boot_epoch_secs: BOOT,
            ..Default::default()
        };
        let reason = pending_restart_reason(&evidence).unwrap();
        assert!(reason.contains("usbip2_ude, usbip2_filter is pending deletion"));
        assert!(restart_detail(&reason).starts_with("USBIP-SETUP-010:"));
    }

    #[test]
    fn devnode_restart_flags_require_a_restart() {
        // 0x0180200B is the started VHCI node observed after the repair: no restart flag.
        let started = RestartEvidence {
            devnodes: vec![(r"ROOT\USB\0000".into(), 0x0180_200B, 0)],
            boot_epoch_secs: BOOT,
            ..Default::default()
        };
        assert_eq!(pending_restart_reason(&started), None);
        for (status, problem) in [
            (0x0180_200B | DN_NEED_RESTART, 0),
            (0x0180_0400, CM_PROB_NEED_RESTART),
        ] {
            let evidence = RestartEvidence {
                devnodes: vec![(r"ROOT\USB\0000".into(), status, problem)],
                boot_epoch_secs: BOOT,
                ..Default::default()
            };
            assert!(
                pending_restart_reason(&evidence)
                    .unwrap()
                    .contains(r"ROOT\USB\0000")
            );
        }
    }

    #[test]
    fn a_reactivated_service_stays_unavailable_until_the_recorded_boot_ends() {
        // After the 12:48 reinstall the live markers were gone; only the marker remains.
        let marker = RestartMarker {
            boot_epoch_secs: BOOT,
            reason: "driver service usbip2_ude is pending deletion".into(),
        };
        let same_boot = RestartEvidence {
            marker: Some(marker.clone()),
            boot_epoch_secs: BOOT + 30,
            ..Default::default()
        };
        assert!(pending_restart_reason(&same_boot).is_some());
        let after_restart = RestartEvidence {
            marker: Some(marker),
            boot_epoch_secs: BOOT + 3600,
            ..Default::default()
        };
        assert_eq!(pending_restart_reason(&after_restart), None);
    }

    #[test]
    fn marker_round_trips_and_missing_marker_is_none() {
        let directory = tempfile::tempdir().unwrap();
        assert_eq!(read_marker(directory.path()), None);
        let marker = RestartMarker {
            boot_epoch_secs: BOOT,
            reason: "x".into(),
        };
        write_marker(directory.path(), &marker).unwrap();
        assert_eq!(read_marker(directory.path()), Some(marker));
    }
}
