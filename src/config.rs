//! Runtime configuration, read from the environment.
//!
//! Every setting arrives as an environment variable because that is what the
//! deployment gives us: Ansible renders an `EnvironmentFile` that systemd loads
//! into the unit. There is no config file to keep in sync with the role.

use anyhow::{Context, Result};

/// Prefix for every variable this service reads, so nothing it looks at can
/// collide with something else on the host.
const PREFIX: &str = "SCN_NOTES_";

pub struct Config {
    /// Postgres connection string. The only setting with no default: a relay
    /// that silently fell back to in-memory storage would look healthy right up
    /// until a restart lost every document.
    pub database_url: String,

    /// Address to bind. Must be a wildcard, not the container's own address —
    /// binding a literal `10.1.1.x` loses a cold-boot race with
    /// systemd-networkd and comes up silently loopback-only.
    pub bind: String,

    /// Whether a connection must present a verified DID.
    ///
    /// Defaults to **true**, so the safe posture is the one you get by
    /// forgetting to set it. Turning it off is for local work only, and is a
    /// decision someone has to write down.
    pub require_auth: bool,

    /// What the token verifier needs. Present exactly when `require_auth` is
    /// on, so a gated relay cannot start half configured.
    pub auth: Option<AuthConfig>,

    /// The credential Corliss presents on `/internal/workspaces`. Required when
    /// `require_auth` is on. Without it those endpoints refuse every call.
    pub service_token: Option<String>,

    /// Address the MCP service binds. A listener of its own, so sync and MCP
    /// traffic stay separate in the proxy and in logs.
    pub mcp_bind: String,

    /// Address the public listener binds: the `notes.` host, where members'
    /// clients reach everything. Not started with auth off.
    pub public_bind: String,

    /// The attachment routes and their caps. `None` when attachments are off,
    /// the default, so the schema can ship before any client uses it.
    pub attachments: Option<AttachmentConfig>,
}

pub struct AttachmentConfig {
    /// Per file. `0` refuses every upload; downloads still work.
    pub max_bytes: u64,
    /// The sum of a workspace's attachment sizes.
    pub quota_bytes: u64,
}

/// 50 MiB. Conservative until the backup window is measured.
const DEFAULT_ATTACHMENT_MAX_BYTES: u64 = 50 * 1024 * 1024;
/// 2 GiB. Conservative until the backup window is measured.
const DEFAULT_ATTACHMENT_QUOTA_BYTES: u64 = 2 * 1024 * 1024 * 1024;

pub struct AuthConfig {
    /// The `iss` every token must carry: the issuer's public URL.
    pub oidc_issuer: String,

    /// Where to fetch the issuer's signing keys. Separate from the issuer
    /// because the relay reaches it over the internal network, not the public
    /// name.
    pub oidc_jwks_url: String,

    /// The `aud` a sync token must carry: this relay's public sync URL,
    /// spelled exactly as the issuer spells it.
    pub sync_audience: String,

    /// The `aud` an MCP token must carry: the public MCP URL in canonical
    /// form (lowercase scheme and host, no trailing slash, no default port).
    /// Also the `resource` the relay advertises, the host it accepts MCP
    /// requests for, and the path the MCP service is mounted at.
    pub mcp_audience: String,

    /// The public URL of the `notes.` host, an origin with no path and no
    /// trailing slash, such as `https://notes.example.org`. It is the `aud` a
    /// plugin's token carries there, and with `/mcp` after it, an MCP
    /// client's.
    pub public_url: String,
}

impl AuthConfig {
    /// The `aud` an MCP token carries on the `notes.` host, and where MCP is
    /// mounted there.
    pub fn public_mcp_url(&self) -> String {
        format!("{}/mcp", self.public_url)
    }
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let database_url = var("DATABASE_URL").with_context(|| {
            format!("{PREFIX}DATABASE_URL must be set — there is no in-memory fallback")
        })?;

        let bind = var("BIND").unwrap_or_else(|_| "0.0.0.0:7030".to_string());

        // Anything that isn't an explicit, recognised "off" leaves the gate on.
        let require_auth = match var("REQUIRE_AUTH") {
            Ok(v) => !matches!(v.trim().to_ascii_lowercase().as_str(), "false" | "0" | "no"),
            Err(_) => true,
        };

        let auth = if require_auth {
            Some(AuthConfig {
                oidc_issuer: required_for_auth("OIDC_ISSUER")?,
                oidc_jwks_url: required_for_auth("OIDC_JWKS_URL")?,
                sync_audience: required_for_auth("SYNC_AUDIENCE")?,
                mcp_audience: required_for_auth("MCP_AUDIENCE")?,
                public_url: origin(&required_for_auth("PUBLIC_URL")?)?,
            })
        } else {
            None
        };

        let service_token = if require_auth {
            Some(required_for_auth("SERVICE_TOKEN")?)
        } else {
            var("SERVICE_TOKEN").ok().filter(|v| !v.trim().is_empty())
        };

        Ok(Self {
            database_url,
            bind,
            require_auth,
            auth,
            service_token,
            mcp_bind: var("MCP_BIND").unwrap_or_else(|_| "0.0.0.0:7031".to_string()),
            public_bind: var("PUBLIC_BIND").unwrap_or_else(|_| "0.0.0.0:7032".to_string()),
            attachments: attachments(
                var("ATTACHMENTS_ENABLED").ok().as_deref(),
                var("ATTACHMENT_MAX_BYTES").ok().as_deref(),
                var("ATTACHMENT_WORKSPACE_QUOTA_BYTES").ok().as_deref(),
            )?,
        })
    }
}

/// The attachment settings, from their raw values. Only an explicit "on"
/// enables the routes. A cap that is not a whole number of bytes, a negative
/// one included, refuses startup rather than falling back to a default.
fn attachments(
    enabled: Option<&str>,
    max_bytes: Option<&str>,
    quota_bytes: Option<&str>,
) -> Result<Option<AttachmentConfig>> {
    let enabled = enabled
        .is_some_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes"));
    if !enabled {
        return Ok(None);
    }
    let bytes = |name: &str, value: Option<&str>, default: u64| -> Result<u64> {
        match value.map(str::trim).filter(|v| !v.is_empty()) {
            None => Ok(default),
            Some(v) => v.parse().with_context(|| {
                format!("{PREFIX}{name} must be a whole number of bytes; got {v:?}")
            }),
        }
    };
    Ok(Some(AttachmentConfig {
        max_bytes: bytes(
            "ATTACHMENT_MAX_BYTES",
            max_bytes,
            DEFAULT_ATTACHMENT_MAX_BYTES,
        )?,
        quota_bytes: bytes(
            "ATTACHMENT_WORKSPACE_QUOTA_BYTES",
            quota_bytes,
            DEFAULT_ATTACHMENT_QUOTA_BYTES,
        )?,
    }))
}

/// A setting the gated relay cannot run without. Blank counts as missing: an
/// empty audience or issuer would be compared against tokens as if it meant
/// something.
fn required_for_auth(name: &str) -> Result<String> {
    match var(name) {
        Ok(v) if !v.trim().is_empty() => Ok(v.trim().to_string()),
        _ => anyhow::bail!(
            "{PREFIX}{name} must be set when {PREFIX}REQUIRE_AUTH is on. Set \
             {PREFIX}REQUIRE_AUTH=false to run the unauthenticated relay, and \
             only where it has no route in."
        ),
    }
}

/// `PUBLIC_URL` as given, once it is checked to be an origin alone. Paths
/// are added to it (`/mcp`, `/v1/...`), so a trailing slash or a path would
/// put a doubled slash in an audience, and a token would fail with a bare
/// `401`.
fn origin(url: &str) -> Result<String> {
    let parsed: samod::Url = url
        .parse()
        .with_context(|| format!("{PREFIX}PUBLIC_URL is not a URL: {url:?}"))?;
    anyhow::ensure!(
        parsed.host_str().is_some()
            && parsed.path() == "/"
            && !url.ends_with('/')
            && parsed.query().is_none(),
        "{PREFIX}PUBLIC_URL must be an origin with no path and no trailing slash, \
         such as https://notes.example.org; got {url:?}"
    );
    Ok(url.to_string())
}

fn var(name: &str) -> Result<String, std::env::VarError> {
    std::env::var(format!("{PREFIX}{name}"))
}

#[cfg(test)]
mod tests {
    use super::{attachments, origin};

    #[test]
    fn attachments_are_off_unless_turned_on() {
        for off in [None, Some(""), Some("false"), Some("0"), Some("maybe")] {
            assert!(attachments(off, None, None).unwrap().is_none(), "{off:?}");
        }
        let on = attachments(Some("true"), None, None).unwrap().unwrap();
        assert_eq!(on.max_bytes, 52_428_800);
        assert_eq!(on.quota_bytes, 2_147_483_648);
        let zero = attachments(Some("1"), Some("0"), Some("10"))
            .unwrap()
            .unwrap();
        assert_eq!((zero.max_bytes, zero.quota_bytes), (0, 10));
    }

    #[test]
    fn an_attachment_cap_that_is_not_a_byte_count_refuses_startup() {
        for bad in ["-1", "1.5", "50MiB"] {
            assert!(
                attachments(Some("true"), Some(bad), None).is_err(),
                "{bad:?}"
            );
            assert!(
                attachments(Some("true"), None, Some(bad)).is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn the_public_url_is_an_origin_alone() {
        for good in ["https://notes.example.org", "http://127.0.0.1:7032"] {
            assert_eq!(origin(good).unwrap(), good);
        }
        for bad in [
            "https://notes.example.org/",
            "https://notes.example.org/mcp",
            "https://notes.example.org?x=1",
            "notes.example.org",
            "",
        ] {
            assert!(origin(bad).is_err(), "{bad:?}");
        }
    }
}
