//! Component test diagnostics: full failure text, persisted failure logs and
//! the session-context guard for tests that depend on the system audio graph.

use std::path::Path;

/// Each diagnostic stream is bounded so a runaway sidecar cannot flood the UI or the IPC response.
const MAX_DIAGNOSTIC_BYTES: usize = 8 * 1024;
/// The headline is shown in toasts; the full text stays in the diagnostics block.
const MAX_SUMMARY_BYTES: usize = 400;
pub(crate) const FAILURE_LOG_NAME: &str = "last-component-test-failure.log";
pub(crate) const DIAGNOSTIC_MARKER: &str = "\n\n--- diagnostics ---\n";

/// Sidecar text that identifies the composite render-endpoint wait failing.
const RENDER_ENDPOINT_TIMEOUT: &str = "did not create an active render endpoint";

fn bounded(text: &str) -> String {
    let text = text.trim();
    if text.len() <= MAX_DIAGNOSTIC_BYTES {
        return text.to_string();
    }
    let mut end = MAX_DIAGNOSTIC_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n[truncated {} bytes]", &text[..end], text.len() - end)
}

/// Builds the user-visible failure: a one-line summary for toasts followed by
/// the full `--result` error, stderr and exit code for the technical details.
pub(crate) fn component_test_failure_text(
    exit_code: Option<i32>,
    stderr: &str,
    result_error: Option<&str>,
    session: Option<&SessionContext>,
) -> String {
    let result_error = result_error.map(str::trim).filter(|text| !text.is_empty());
    let stderr = stderr.trim();
    let summary = result_error
        .or((!stderr.is_empty()).then_some(stderr))
        .and_then(|text| text.lines().find(|line| !line.trim().is_empty()))
        .map(|line| {
            let line = line.trim();
            let mut end = line.len().min(MAX_SUMMARY_BYTES);
            while !line.is_char_boundary(end) {
                end -= 1;
            }
            &line[..end]
        });
    let combined = format!("{} {}", result_error.unwrap_or_default(), stderr);
    // The render-endpoint wait has a known environmental cause; name it.
    let headline = if combined.contains(RENDER_ENDPOINT_TIMEOUT)
        && session.is_some_and(|session| session.remote)
    {
        remote_session_message(session.unwrap())
    } else {
        match summary {
            Some(summary) => format!("DS5-PKG-003: component test failed: {summary}"),
            None => format!(
                "DS5-PKG-003: component test process failed with exit code {}",
                exit_code.unwrap_or(-1)
            ),
        }
    };
    let mut details = vec![format!(
        "exit code: {}",
        exit_code.map_or_else(|| "none".to_string(), |code| code.to_string())
    )];
    if let Some(session) = session {
        details.push(format!("session: {}", session.describe()));
    }
    if let Some(error) = result_error {
        details.push(format!("--result error:\n{}", bounded(error)));
    }
    if !stderr.is_empty() {
        details.push(format!("stderr:\n{}", bounded(stderr)));
    }
    format!("{headline}{DIAGNOSTIC_MARKER}{}", details.join("\n\n"))
}

/// Keeps the last failure on disk: the elevated helper has no persistent log of its own.
pub(crate) fn persist_failure_log(directory: &Path, text: &str) {
    let stamped = format!(
        "{}\n{text}\n",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f %z")
    );
    if let Err(error) = std::fs::write(directory.join(FAILURE_LOG_NAME), stamped) {
        log::warn!("Unable to persist the DualSense component test failure: {error}");
    }
}

/// Windows session facts for the process that launches the sidecar. The
/// sidecar is started from this process, so it inherits the same session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SessionContext {
    pub(crate) session_id: u32,
    pub(crate) console_session_id: u32,
    /// WTSClientProtocolType: 0 console, 1 legacy ICA, 2 RDP.
    pub(crate) protocol_type: u16,
    pub(crate) remote_metric: bool,
    pub(crate) remote: bool,
}

impl SessionContext {
    pub(crate) fn classify(
        session_id: u32,
        console_session_id: u32,
        protocol_type: u16,
        remote_metric: bool,
    ) -> Self {
        // SM_REMOTESESSION covers RDP into any session; the protocol type
        // covers clients that leave the metric clear. Both describe this
        // session itself, not the localized names of the audio endpoints.
        let remote = remote_metric || protocol_type != 0;
        Self {
            session_id,
            console_session_id,
            protocol_type,
            remote_metric,
            remote,
        }
    }

    fn describe(&self) -> String {
        format!(
            "id {} (console {}), protocol {}, remote {}",
            self.session_id,
            self.console_session_id,
            match self.protocol_type {
                0 => "console",
                1 => "ICA",
                2 => "RDP",
                _ => "unknown",
            },
            self.remote
        )
    }
}

fn remote_session_message(session: &SessionContext) -> String {
    format!(
        "DS5-SESSION-001: the DualSense audio test cannot run in a Remote Desktop session \
         (session {}, console session {}). Windows redirects audio there, so the virtual \
         controller's speaker endpoint is not visible. Run the install, update or composite \
         test from the local console session (for example after reconnecting locally or while \
         streaming with Sunshine), then try again.",
        session.session_id, session.console_session_id
    )
}

#[cfg(target_os = "windows")]
pub(crate) fn current_session() -> Result<SessionContext, String> {
    use windows::Win32::System::RemoteDesktop::{
        ProcessIdToSessionId, WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION,
        WTSClientProtocolType, WTSFreeMemory, WTSGetActiveConsoleSessionId,
        WTSQuerySessionInformationW,
    };
    use windows::Win32::System::Threading::GetCurrentProcessId;
    use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_REMOTESESSION};
    use windows::core::PWSTR;

    let mut session_id = 0u32;
    unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session_id) }
        .map_err(|error| format!("DS5-SESSION-002: unable to read the Windows session: {error}"))?;
    let console_session_id = unsafe { WTSGetActiveConsoleSessionId() };
    let remote_metric = unsafe { GetSystemMetrics(SM_REMOTESESSION) } != 0;
    let mut buffer = PWSTR::null();
    let mut bytes = 0u32;
    let protocol_type = unsafe {
        WTSQuerySessionInformationW(
            Some(WTS_CURRENT_SERVER_HANDLE),
            WTS_CURRENT_SESSION,
            WTSClientProtocolType,
            &mut buffer,
            &mut bytes,
        )
    }
    .ok()
    .filter(|_| !buffer.is_null() && bytes as usize >= std::mem::size_of::<u16>())
    .map(|_| unsafe { *(buffer.0 as *const u16) });
    if !buffer.is_null() {
        unsafe { WTSFreeMemory(buffer.0.cast()) };
    }
    Ok(SessionContext::classify(
        session_id,
        console_session_id,
        protocol_type.unwrap_or(0),
        remote_metric,
    ))
}

/// Refuses audio-graph tests in a remote session before any device is created.
pub(crate) fn require_local_audio_session(
    session: Result<SessionContext, String>,
) -> Result<(), String> {
    match session {
        Ok(session) if session.remote => {
            let message = remote_session_message(&session);
            log::error!("{message}");
            Err(message)
        }
        Ok(_) => Ok(()),
        // Unknown context must not block a working console install; the full
        // diagnostics still identify an RDP failure if the test then fails.
        Err(error) => {
            log::warn!("{error}");
            Ok(())
        }
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn ensure_local_audio_session() -> Result<(), String> {
    require_local_audio_session(current_session())
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn ensure_local_audio_session() -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "windows")]
pub(crate) fn current_session_for_diagnostics() -> Option<SessionContext> {
    current_session().ok()
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn current_session_for_diagnostics() -> Option<SessionContext> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // Exact text the 1.4.3 sidecar wrote for the RDP incident (ex.ToString()).
    const RDP_RESULT_ERROR: &str = "System.TimeoutException: The current controller did not create an active render endpoint\r\n   at Sunshine.Ds5Sidecar.DefaultAudioEndpointGuard.WaitForNewRenderEndpoint(IReadOnlySet`1 previous, TimeSpan timeout, CancellationToken cancellationToken)\r\n   at Sunshine.Ds5Sidecar.ProtocolSelfTest.RunAsync(Boolean composite, String resultPath, String audioWriterPath, Boolean genshinCompatibility)";

    fn rdp() -> SessionContext {
        SessionContext::classify(2, 1, 2, true)
    }

    #[test]
    fn classifies_rdp_and_console_sessions_without_endpoint_names() {
        assert!(rdp().remote);
        assert!(SessionContext::classify(3, 1, 2, false).remote);
        assert!(SessionContext::classify(1, 1, 0, true).remote);
        assert!(!SessionContext::classify(1, 1, 0, false).remote);
    }

    #[test]
    fn remote_session_blocks_the_audio_test_with_an_actionable_code() {
        let error = require_local_audio_session(Ok(rdp())).unwrap_err();
        assert!(error.starts_with("DS5-SESSION-001:"), "{error}");
        assert!(error.contains("Remote Desktop"));
        assert!(require_local_audio_session(Ok(SessionContext::classify(1, 1, 0, false))).is_ok());
        assert!(require_local_audio_session(Err("DS5-SESSION-002: x".to_string())).is_ok());
    }

    #[test]
    fn rdp_render_endpoint_failure_keeps_the_full_exception_and_names_the_cause() {
        let text = component_test_failure_text(
            Some(1),
            RDP_RESULT_ERROR,
            Some(RDP_RESULT_ERROR),
            Some(&rdp()),
        );
        let (headline, details) = text.split_once(DIAGNOSTIC_MARKER).unwrap();
        assert!(headline.starts_with("DS5-SESSION-001:"), "{headline}");
        assert!(details.contains("exit code: 1"));
        assert!(details.contains("protocol RDP, remote true"));
        assert!(details.contains("--result error:\nSystem.TimeoutException: The current controller did not create an active render endpoint"));
        assert!(details.contains("ProtocolSelfTest.RunAsync"));
        assert!(details.contains("stderr:\nSystem.TimeoutException"));
    }

    #[test]
    fn console_failures_keep_the_sidecar_summary_and_full_text() {
        let text = component_test_failure_text(
            Some(1),
            "warning\nusbip-win2 attach failed\n   at Stack",
            Some("usbip-win2 attach failed\n   at Stack"),
            Some(&SessionContext::classify(1, 1, 0, false)),
        );
        assert!(text.starts_with("DS5-PKG-003: component test failed: usbip-win2 attach failed"));
        assert!(text.contains("--result error:\nusbip-win2 attach failed\n   at Stack"));
        assert!(text.contains("stderr:\nwarning\nusbip-win2 attach failed"));
    }

    #[test]
    fn falls_back_to_stderr_then_exit_code_and_bounds_output() {
        let text = component_test_failure_text(Some(3), "only stderr", None, None);
        assert!(text.starts_with("DS5-PKG-003: component test failed: only stderr"));
        let text = component_test_failure_text(Some(7), "", None, None);
        assert!(text.starts_with("DS5-PKG-003: component test process failed with exit code 7"));
        let huge = "é".repeat(MAX_DIAGNOSTIC_BYTES);
        let text = component_test_failure_text(Some(1), &huge, None, None);
        assert!(text.contains("[truncated"));
        assert!(text.len() < 3 * MAX_DIAGNOSTIC_BYTES);
    }

    #[test]
    fn persists_the_last_failure_for_the_elevated_helper() {
        let directory = tempfile::tempdir().unwrap();
        persist_failure_log(directory.path(), "DS5-PKG-003: boom");
        let text = std::fs::read_to_string(directory.path().join(FAILURE_LOG_NAME)).unwrap();
        assert!(text.contains("DS5-PKG-003: boom"));
    }
}
