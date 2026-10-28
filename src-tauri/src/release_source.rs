//! Release repository trusted by the Foundation Sunshine updater.
//!
//! Official builds use AlkaidLab/foundation-sunshine together with the
//! alkaidlab.com/.cn metadata and the CNB mirror. A fork build sets
//! `FOUNDATION_RELEASE_REPOSITORY=owner/repo` at compile time (validated by
//! build.rs). The updater then trusts only that repository's GitHub Releases;
//! the official metadata and mirror are disabled because they only describe
//! AlkaidLab releases.

const OFFICIAL_OWNER: &str = "AlkaidLab";
const OFFICIAL_REPOSITORY: &str = "foundation-sunshine";

fn configured() -> Option<(&'static str, &'static str)> {
    option_env!("FOUNDATION_RELEASE_REPOSITORY")
        .filter(|value| !value.trim().is_empty())
        .and_then(|value| value.trim().split_once('/'))
}

/// GitHub owner of the trusted release repository.
pub(crate) fn owner() -> &'static str {
    configured().map_or(OFFICIAL_OWNER, |(owner, _)| owner)
}

/// GitHub name of the trusted release repository.
pub(crate) fn repository() -> &'static str {
    configured().map_or(OFFICIAL_REPOSITORY, |(_, repository)| repository)
}

/// Whether the AlkaidLab-operated metadata endpoints and CNB mirror apply.
pub(crate) fn official_mirrors_enabled() -> bool {
    configured().is_none()
}

/// `https://github.com/<owner>/<repo>` without a trailing slash.
pub(crate) fn github_repository_url() -> String {
    format!("https://github.com/{}/{}", owner(), repository())
}

/// `https://api.github.com/repos/<owner>/<repo>` without a trailing slash.
pub(crate) fn github_api_url() -> String {
    format!("https://api.github.com/repos/{}/{}", owner(), repository())
}

/// URL path prefix of release assets, e.g. `/AlkaidLab/foundation-sunshine/releases/download/`.
pub(crate) fn release_download_path_prefix() -> String {
    format!("/{}/{}/releases/download/", owner(), repository())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mirrors_follow_the_build_time_repository() {
        assert_eq!(
            official_mirrors_enabled(),
            owner() == OFFICIAL_OWNER
                && repository() == OFFICIAL_REPOSITORY
                && configured().is_none()
        );
        assert_eq!(
            release_download_path_prefix(),
            format!("/{}/{}/releases/download/", owner(), repository())
        );
        assert!(github_api_url().ends_with(&format!("/repos/{}/{}", owner(), repository())));
    }
}
