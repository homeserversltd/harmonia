use std::fs;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub const ROOT_PLANE_FORGEJO_CREDENTIAL: &str = "/etc/default/forgejo";
pub const ESTATE_FORGEJO_HOST: &str = "git.home.arpa";
pub const DEFAULT_FORGEJO_USERNAME: &str = "owner";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Credential {
    pub(crate) username: String,
    pub(crate) token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Present { username: String, token: String },
    Absent,
    Err(String),
}

pub(crate) fn resolve_for_url(url: &str) -> Outcome {
    resolve_for_url_at(url, Path::new(ROOT_PLANE_FORGEJO_CREDENTIAL), ESTATE_FORGEJO_HOST)
}

pub(crate) fn resolve_for_url_at(url: &str, path: &Path, estate_host: &str) -> Outcome {
    let Some(host) = url_host(url) else {
        return Outcome::Absent;
    };
    if host != estate_host {
        return Outcome::Absent;
    }
    resolve_path(path)
}

pub(crate) fn resolve_path(path: &Path) -> Outcome {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Outcome::Absent,
        Err(_) => return Outcome::Err("forgejo-credential-unavailable".into()),
    };
    if !metadata.is_file() {
        return Outcome::Err("forgejo-credential-not-regular-file".into());
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Outcome::Err("forgejo-credential-permissive".into());
    }
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(_) => return Outcome::Err("forgejo-credential-unreadable".into()),
    };
    parse(&contents)
}

/// Preserve the legacy token-file grammar: the first nonempty bare line is a
/// token, as is the first nonempty FORGEJO_TOKEN assignment.
pub(crate) fn read_token(path: &Path) -> Result<String, String> {
    let contents = fs::read_to_string(path)
        .map_err(|err| format!("forgejo-token-unavailable {}: {err}", path.display()))?;
    token_from_contents(&contents)
        .ok_or_else(|| format!("forgejo-token-empty {}", path.display()))
}

fn token_from_contents(contents: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let value = line.trim();
        if value.is_empty() {
            return None;
        }
        value
            .strip_prefix("FORGEJO_TOKEN=")
            .map(str::trim)
            .or((!value.contains('=')).then_some(value))
            .filter(|token| !token.is_empty())
            .map(str::to_owned)
    })
}

pub(crate) fn credential_for_url(url: &str) -> Result<Option<Credential>, String> {
    match resolve_for_url(url) {
        Outcome::Present { username, token } => Ok(Some(Credential { username, token })),
        Outcome::Absent => Ok(None),
        Outcome::Err(reason) => Err(reason),
    }
}

pub(crate) fn url_host(url: &str) -> Option<String> {
    let (_, rest) = url.trim().split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?.trim();
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let host = if authority.starts_with('[') {
        authority.split(']').next()?.trim_start_matches('[')
    } else {
        authority.split(':').next().unwrap_or_default()
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

fn parse(contents: &str) -> Outcome {
    let username = contents.lines().find_map(|line| {
        line.trim()
            .strip_prefix("FORGEJO_USERNAME=")
            .map(str::trim)
            .filter(|username| !username.is_empty())
            .map(str::to_owned)
    });
    let Some(token) = token_from_contents(contents) else {
        return Outcome::Err("forgejo-token-empty".into());
    };
    Outcome::Present {
        username: username.unwrap_or_else(|| DEFAULT_FORGEJO_USERNAME.to_owned()),
        token,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::NamedTempFile;

    fn fixture(contents: &str, mode: u32) -> NamedTempFile {
        let file = NamedTempFile::new().unwrap();
        fs::write(file.path(), contents).unwrap();
        let mut permissions = fs::metadata(file.path()).unwrap().permissions();
        permissions.set_mode(mode);
        fs::set_permissions(file.path(), permissions).unwrap();
        file
    }

    #[test]
    fn forgejo_credential_contract_resolver_table_present_absent_permissive_empty_default_username() {
        let present = fixture("FORGEJO_TOKEN=secret
FORGEJO_USERNAME=builder
", 0o600);
        assert_eq!(
            resolve_for_url_at("https://git.home.arpa/api/v1", present.path(), "git.home.arpa"),
            Outcome::Present {
                username: "builder".into(),
                token: "secret".into()
            }
        );
        let absent = present.path().with_extension("absent");
        assert_eq!(
            resolve_for_url_at("https://git.home.arpa/api/v1", &absent, "git.home.arpa"),
            Outcome::Absent
        );
        assert_eq!(
            resolve_for_url_at("https://foreign.example/api/v1", present.path(), "git.home.arpa"),
            Outcome::Absent
        );
        let permissive = fixture("FORGEJO_TOKEN=secret
", 0o644);
        assert_eq!(resolve_path(permissive.path()), Outcome::Err("forgejo-credential-permissive".into()));
        let empty = fixture("FORGEJO_TOKEN=
", 0o600);
        assert_eq!(resolve_path(empty.path()), Outcome::Err("forgejo-token-empty".into()));
        let default_username = fixture("FORGEJO_TOKEN=secret
", 0o600);
        assert_eq!(resolve_path(default_username.path()), Outcome::Present { username: "owner".into(), token: "secret".into() });
        let bare_token = fixture("
  bare-secret  
", 0o600);
        assert_eq!(resolve_path(bare_token.path()), Outcome::Present { username: "owner".into(), token: "bare-secret".into() });
        assert_eq!(read_token(bare_token.path()), Ok("bare-secret".into()));
        println!("trace forgejo-credential resolver credential=present token=redacted");
        println!("trace forgejo-credential resolver credential=absent anonymous");
    }

    #[test]
    fn forgejo_credential_contract_never_accepts_foreign_host() {
        let present = fixture("FORGEJO_TOKEN=secret
", 0o600);
        assert_eq!(resolve_for_url_at("https://git.home.arpa.evil/api/v1", present.path(), "git.home.arpa"), Outcome::Absent);
        assert_eq!(url_host("https://git.home.arpa:443/api/v1").as_deref(), Some("git.home.arpa"));
    }
}
