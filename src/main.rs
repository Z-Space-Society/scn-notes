//! An Automerge sync relay for the Shared Computer Network.
//!
//! Speaks the automerge-repo WebSocket protocol via `samod`, and persists to
//! Postgres. A connection is authenticated as a member's DID before the
//! websocket upgrade; see `auth.rs` and [`build_verifier`].

mod actors;
mod auth;
mod authz;
mod config;
mod filter;
mod mcp;
mod reach;
mod storage;
mod unfiled;
mod wire;
mod workspaces;

use std::future::IntoFuture;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    extract::{
        ws::{WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use samod::{AcceptorHandle, Repo, ShareConfig};
use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;

use auth::{AllowAll, CorlissVerifier, DidVerifier, Verified};
use authz::Authz;
use config::Config;
use storage::PostgresStorage;

#[derive(Clone)]
struct AppState {
    acceptor: AcceptorHandle,
    verifier: Arc<dyn DidVerifier>,
    /// The audience a member's token must carry on this listener's sync and
    /// listing routes: the sync URL, or the `notes.` URL. Empty when nothing
    /// is verified.
    audience: Arc<str>,
    /// Who issues sync tokens, for the resource metadata. `None` with no
    /// verifier, where there is no issuer to name.
    oidc_issuer: Option<Arc<str>>,
    authz: Authz,
    /// Whether connections go through the filter. Off only with no verifier,
    /// where there is no DID to decide by.
    enforce: bool,
    /// What Corliss presents on `/internal/workspaces`. `None` refuses every call.
    service_token: Option<Arc<str>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "scn_notes=info,samod=info".into()),
        )
        .init();

    let config = Config::from_env()?;

    // `file-unfiled` is run by hand, with the service stopped; see `unfiled`.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("file-unfiled") {
        let (repo, authz) = open_relay(&config).await?;
        return file_unfiled(&repo, &authz, &args[1..]).await;
    }

    let verifier = build_verifier(&config).await?;
    let (repo, authz) = open_relay(&config).await?;
    authz.start_actor_backfill();

    // The URL is used only to identify this endpoint in samod's own logs; it
    // is not something the relay binds or dials.
    let acceptor = repo
        .make_acceptor(
            format!("ws://{}/sync", config.bind)
                .parse()
                .context("bind address does not form a valid URL")?,
        )
        .map_err(|_| anyhow::anyhow!("repo stopped before it could accept connections"))?;

    let state = AppState {
        acceptor,
        verifier: Arc::clone(&verifier),
        audience: config
            .auth
            .as_ref()
            .map(|auth| auth.sync_audience.as_str())
            .unwrap_or_default()
            .into(),
        oidc_issuer: config
            .auth
            .as_ref()
            .map(|auth| auth.oidc_issuer.as_str().into()),
        authz: authz.clone(),
        enforce: config.require_auth,
        service_token: config.service_token.as_deref().map(Arc::from),
    };
    let app = router(state.clone());

    let listener = tokio::net::TcpListener::bind(&config.bind)
        .await
        .with_context(|| format!("could not bind {}", config.bind))?;

    tracing::info!(
        bind = %config.bind,
        auth = verifier.name(),
        "scn-notes listening"
    );
    let sync = axum::serve(listener, app).with_graceful_shutdown(shutdown());

    // The MCP service acts as the member a token names. With no verifier
    // there is no member, so it is not started.
    let Some(auth) = &config.auth else {
        tracing::warn!(
            "running WITHOUT a membership gate: any peer that can reach this \
             port can sync any document this relay holds. This is only sound \
             while the service has no route through the proxy. The MCP \
             service is not started."
        );
        return sync.await.context("server error");
    };

    let mcp_app = mcp::router(
        authz.clone(),
        Arc::clone(&verifier),
        &auth.mcp_audience,
        &auth.oidc_issuer,
    )?;
    let mcp_listener = tokio::net::TcpListener::bind(&config.mcp_bind)
        .await
        .with_context(|| format!("could not bind {}", config.mcp_bind))?;
    tracing::info!(bind = %config.mcp_bind, audience = %auth.mcp_audience, "MCP service listening");
    let mcp = axum::serve(mcp_listener, mcp_app).with_graceful_shutdown(shutdown());

    let public_app = notes_router(
        AppState {
            audience: auth.public_url.as_str().into(),
            ..state
        },
        mcp::router(
            authz,
            Arc::clone(&verifier),
            &auth.public_mcp_url(),
            &auth.oidc_issuer,
        )?,
    );
    let public_listener = tokio::net::TcpListener::bind(&config.public_bind)
        .await
        .with_context(|| format!("could not bind {}", config.public_bind))?;
    tracing::info!(bind = %config.public_bind, url = %auth.public_url, "notes listening");
    let public = axum::serve(public_listener, public_app).with_graceful_shutdown(shutdown());

    tokio::try_join!(sync.into_future(), mcp.into_future(), public.into_future())
        .context("server error")?;

    Ok(())
}

/// The storage, the repo and the ownership records: what the server and the
/// one-off commands share.
async fn open_relay(config: &Config) -> Result<(Repo, Authz)> {
    // A small pool: this is a relay, not a web app. Connections are held only
    // for the duration of a storage call, and samod serialises per document.
    let pool = PgPoolOptions::new()
        .max_connections(16)
        .connect(&config.database_url)
        .await
        .context("could not connect to Postgres")?;

    let store = PostgresStorage::new(pool.clone());
    store
        .migrate()
        .await
        .context("could not create the storage schema")?;

    // The relay never offers a document unasked, and never asks one peer for
    // a document on behalf of another. A peer gets what it requests and may
    // open, and a change still reaches every peer already syncing that
    // document. Every peer is read-write to samod: who may open what is the
    // filter's decision, made on each frame before samod sees it.
    let repo = Repo::build_tokio()
        .with_storage(store)
        .with_share_policy(ShareConfig::read_write().with_announce(false))
        .load()
        .await;
    let authz = Authz::load(pool, repo.clone())
        .await
        .context("could not load the ownership records")?;

    Ok((repo, authz))
}

/// How long `file-unfiled` waits for the index to walk every workspace.
const WALK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// `file-unfiled <did> [--folder <name>] [--apply | --delete]`: list a
/// member's documents that no workspace reaches. `--apply` links them into a new
/// folder at the root of their private workspace; `--delete` removes them from
/// storage. Stops the repo before returning.
async fn file_unfiled(repo: &Repo, authz: &Authz, args: &[String]) -> Result<()> {
    let result = run_file_unfiled(authz, args).await;
    // Stopped before any delete, so nothing the repo loaded is written back
    // after it.
    repo.stop().await;
    if let Some((did, orphans)) = result? {
        let deleted = authz.delete_orphans(&did, &orphans).await?;
        println!("Deleted {deleted} documents.");
    }
    Ok(())
}

/// Everything but the delete, which waits for the repo to stop. Returns what
/// to delete, if that was asked for.
async fn run_file_unfiled(
    authz: &Authz,
    args: &[String],
) -> Result<Option<(auth::Did, Vec<unfiled::Orphan>)>> {
    const USAGE: &str =
        "usage: scn-notes file-unfiled <did> [--folder <name>] [--apply | --delete]";
    let mut did = None;
    let mut folder = "Recovered".to_string();
    let mut apply = false;
    let mut delete = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--apply" => apply = true,
            "--delete" => delete = true,
            "--folder" => folder = args.next().context(USAGE)?.clone(),
            other if did.is_none() && auth::is_did(other) => {
                did = Some(auth::Did(other.to_string()))
            }
            _ => anyhow::bail!(USAGE),
        }
    }
    let did = did.context(USAGE)?;
    anyhow::ensure!(!(apply && delete), USAGE);

    let started = std::time::Instant::now();
    let orphans = loop {
        if let Some(orphans) = authz.orphans_of(&did).await? {
            break orphans;
        }
        anyhow::ensure!(
            started.elapsed() < WALK_TIMEOUT,
            "the index did not walk every workspace in {WALK_TIMEOUT:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    };

    println!("{} outside every workspace for {}:", orphans.len(), did.0);
    for orphan in &orphans {
        let kind = match orphan.kind {
            unfiled::Kind::Folder => format!("folder, {} inside", orphan.inside),
            unfiled::Kind::Note => "note".to_string(),
            unfiled::Kind::Other => "other, not filed".to_string(),
        };
        let created = orphan
            .created_at
            .map(|at| at.format("%Y-%m-%d").to_string())
            .unwrap_or_else(|| "-".to_string());
        println!(
            "  {created}  {:>7} B  {:<40}  ({kind})  {}",
            orphan.bytes,
            orphan.name.as_deref().unwrap_or("(no name)"),
            orphan.first_line.as_deref().unwrap_or(""),
        );
    }
    if delete {
        return Ok(Some((did, orphans)));
    }
    if !apply {
        println!(
            "Nothing changed. Run again with --apply to put these in {folder:?} in the \
             private workspace, or with --delete to remove them."
        );
        return Ok(None);
    }
    match authz.file_orphans(&did, &folder, &orphans).await {
        Ok(linked) => {
            println!(
                "Put {} in {folder:?} at the root of the private workspace:",
                linked.len()
            );
            for (id, name) in linked {
                println!("  {name}  ({id})");
            }
            Ok(None)
        }
        Err(e) => Err(anyhow::anyhow!("nothing changed: {e}")),
    }
}

fn router(state: AppState) -> Router {
    Router::new()
        // The websocket lives at BOTH the root and /sync, and the root is the one
        // that matters. `automerge-repo`'s WebSocketClientAdapter connects to
        // exactly the URL it is given and appends no path, and the reference
        // sync server serves at the root — so clients are configured with a bare
        // `ws://host:port`. Serving only /sync means a stock client gets a 404
        // instead of an upgrade, which surfaces as "sync silently never works".
        .route("/", get(sync))
        .route("/sync", get(sync))
        .route("/health", get(health))
        .route("/vaults", get(workspaces::list_own_vaults))
        .route("/.well-known/oauth-protected-resource", get(sync_metadata))
        // The shape before v0.7.0, for the Corliss before the rename. Goes when
        // `sync.` retires.
        .route("/internal/vaults", get(workspaces::vaults_for_member))
        .route("/internal/vaults/workspace", put(workspaces::put_vault))
        .route("/internal/vaults/all", get(workspaces::all_vaults))
        .route(
            "/internal/workspaces",
            get(workspaces::workspaces_for_member).put(workspaces::put_workspace),
        )
        .route("/internal/workspaces/all", get(workspaces::all_workspaces))
        .with_state(state)
}

/// The `notes.` listener: everything a member's clients reach, on one host.
///
/// MCP at `/mcp`, versioned by its own protocol. The plugin's API under
/// `/v1/`: a breaking change is a `/v2/` served beside it, never a change to
/// `/v1/`. `/` is left free. `/internal/` is not served here at all, so this
/// listener can be routed whole.
fn notes_router(state: AppState, mcp: Router) -> Router {
    Router::new()
        .route("/v1/sync", get(sync))
        .route("/v1/workspaces", get(workspaces::list_own))
        .route(
            "/v1/documents/{id}/actors",
            post(actors::serve_document_actors),
        )
        .route("/health", get(health))
        .route("/.well-known/oauth-protected-resource", get(sync_metadata))
        .with_state(state)
        .merge(mcp)
}

/// Pick the verifier, or refuse to start.
///
/// Fails closed on purpose. `require_auth` defaults to true, and `Config`
/// refuses to load that way without the issuer settings, so the *only* way to
/// run the ungated relay is to say out loud that you want it.
async fn build_verifier(config: &Config) -> Result<Arc<dyn DidVerifier>> {
    match &config.auth {
        Some(auth) => Ok(Arc::new(
            CorlissVerifier::new(auth.oidc_issuer.clone(), auth.oidc_jwks_url.clone()).await?,
        )),
        None => Ok(Arc::new(AllowAll)),
    }
}

/// Liveness only. It reports that the process is up and which auth mode it is
/// in; it deliberately does not touch Postgres, so a database blip cannot get
/// the relay restarted out from under live connections.
async fn health(State(state): State<AppState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        format!("ok auth={}\n", state.verifier.name()),
    )
}

/// RFC 9728 protected resource metadata for the sync resource: which
/// authorization server issues its tokens. A sync client given only the sync
/// URL finds Corliss from here, so a member pastes one address, not two.
///
/// The token goes in the query string on the websocket, where a browser or
/// phone cannot set a header, and in the header on `/workspaces`.
async fn sync_metadata(State(state): State<AppState>) -> Response {
    match &state.oidc_issuer {
        Some(issuer) => Json(serde_json::json!({
            "resource": &*state.audience,
            "authorization_servers": [&**issuer],
            "bearer_methods_supported": ["header", "query"],
        }))
        .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[derive(Deserialize)]
struct SyncQuery {
    access_token: Option<String>,
}

async fn sync(
    ws: WebSocketUpgrade,
    Query(query): Query<SyncQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Authentication happens *before* the upgrade, so a rejected peer gets an
    // HTTP status it can act on rather than a socket that opens and then dies.
    //
    // The token rides in the URL because a browser or phone WebSocket cannot
    // send an Authorization header. That makes the query string a secret:
    // nothing here logs it, and the proxy in front must not either.
    let verified = match state
        .verifier
        .verify(query.access_token.as_deref(), &state.audience)
        .await
    {
        Ok(verified) => verified,
        Err(e) => {
            // The reason goes to the log and not to the peer.
            tracing::info!(error = %e, "refused a connection");
            return (StatusCode::UNAUTHORIZED, "unauthorized\n").into_response();
        }
    };

    ws.on_upgrade(move |socket| handle_socket(socket, state, verified))
        .into_response()
}

async fn handle_socket(socket: WebSocket, state: AppState, verified: Verified) {
    let did = verified.caller.did.clone();
    if state.enforce {
        let filter = filter::Filter::new(state.authz, verified.caller);
        filter::run(socket, &state.acceptor, filter, verified.expires_at).await;
        return;
    }

    // Ungated: nobody was authenticated, so there is no DID to filter by and
    // samod is handed the socket directly.
    match state.acceptor.accept_axum(socket, None) {
        Ok(_conn) => {
            // samod drives the connection on its own task, so there is nothing
            // to hold here. Dropping the handle does not close the socket.
            tracing::info!(%did, "peer connected");
        }
        Err(_) => {
            tracing::warn!(%did, "repo stopped; dropping connection");
        }
    }
}

/// SIGTERM is what systemd sends on `restart` and `stop`, so handling it is
/// what makes a deploy close sockets cleanly instead of severing them.
async fn shutdown() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    tracing::info!("shutting down");
}

#[cfg(test)]
mod tests {
    use super::*;

    use auth::tests::{Issuer, TokenSpec, SYNC_AUDIENCE};
    use serde_json::{json, Value};
    use sqlx::PgPool;

    const SERVICE_TOKEN: &str = "test-service-token";
    const ALICE: &str = "did:plc:alice";
    const BOB: &str = "did:plc:bob";

    /// A running relay: all three listeners on loopback ports, on the test's
    /// own database, gated by a verifier that trusts the test issuer.
    struct Relay {
        /// Base URL of the sync listener.
        base: String,
        /// The MCP URL, which is also the audience an MCP token must carry.
        mcp: String,
        /// The `notes.` listener's URL: the audience a plugin's token carries
        /// there, and with `/mcp` after it, an MCP client's.
        notes: String,
        authz: Authz,
        repo: Repo,
    }

    /// Start a relay. Calling it twice on one pool is a restart.
    async fn start(pool: &PgPool) -> Relay {
        let issuer = Issuer::start().await;
        let verifier: Arc<dyn DidVerifier> = Arc::new(issuer.verifier().await);
        let (authz, repo) = authz::tests::open(pool).await;
        let acceptor = repo
            .make_acceptor("ws://relay.test/sync".parse().unwrap())
            .unwrap();
        let state = AppState {
            acceptor,
            verifier: Arc::clone(&verifier),
            audience: SYNC_AUDIENCE.into(),
            oidc_issuer: Some(auth::tests::ISSUER.into()),
            authz: authz.clone(),
            enforce: true,
            service_token: Some(SERVICE_TOKEN.into()),
        };
        let app = router(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mcp = format!("http://{}", listener.local_addr().unwrap());
        let app = mcp::router(
            authz.clone(),
            Arc::clone(&verifier),
            &mcp,
            auth::tests::ISSUER,
        )
        .unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let notes = format!("http://{}", listener.local_addr().unwrap());
        let app = notes_router(
            AppState {
                audience: notes.as_str().into(),
                ..state
            },
            mcp::router(
                authz.clone(),
                verifier,
                &format!("{notes}/mcp"),
                auth::tests::ISSUER,
            )
            .unwrap(),
        );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        Relay {
            base,
            mcp,
            notes,
            authz,
            repo,
        }
    }

    async fn relay(pool: &PgPool) -> (String, Authz) {
        let relay = start(pool).await;
        (relay.base, relay.authz)
    }

    /// Ask for a websocket upgrade and report the status of the answer.
    async fn upgrade(url: &str) -> StatusCode {
        reqwest::Client::new()
            .get(url)
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .send()
            .await
            .unwrap()
            .status()
    }

    fn member_token(did: &str) -> String {
        TokenSpec::default().claim("sub", json!(did)).sign()
    }

    /// The member's private workspace, as Corliss's listing makes and finds it.
    async fn private_workspace(base: &str, did: &str) -> (StatusCode, Value) {
        let response = reqwest::Client::new()
            .get(format!("{base}/internal/workspaces?did={did}"))
            .bearer_auth(SERVICE_TOKEN)
            .send()
            .await
            .unwrap();
        let status = response.status();
        let body: Value = response.json().await.unwrap();
        let private = body["workspaces"]
            .as_array()
            .unwrap()
            .iter()
            .find(|workspace| workspace["group_id"].is_null())
            .cloned()
            .unwrap();
        (status, private)
    }

    /// The group's workspace, as Corliss asks for it.
    async fn group_workspace(base: &str, did: &str, group: &str, name: &str) -> reqwest::Response {
        reqwest::Client::new()
            .put(format!("{base}/internal/workspaces"))
            .bearer_auth(SERVICE_TOKEN)
            .json(&json!({ "did": did, "group_id": group, "name": name }))
            .send()
            .await
            .unwrap()
    }

    /// The paths of the workspaces a listing returns.
    async fn workspace_paths(request: reqwest::RequestBuilder) -> Vec<String> {
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = response.json().await.unwrap();
        // The member listing still answers in the shape before v0.7.0.
        body.get("workspaces")
            .unwrap_or(&body["vaults"])
            .as_array()
            .unwrap()
            .iter()
            .map(|workspace| workspace["path"].as_str().unwrap().to_string())
            .collect()
    }

    #[sqlx::test(migrations = false)]
    async fn good_token_upgrades(pool: PgPool) {
        let (base, _) = relay(&pool).await;
        let token = TokenSpec::default().sign();
        for path in ["/", "/sync"] {
            let status = upgrade(&format!("{base}{path}?access_token={token}")).await;
            assert_eq!(status, StatusCode::SWITCHING_PROTOCOLS, "{path}");
        }
    }

    #[sqlx::test(migrations = false)]
    async fn bad_or_missing_token_gets_401_before_upgrade(pool: PgPool) {
        let (base, _) = relay(&pool).await;
        let expired = TokenSpec::default().claim("exp", json!(1)).sign();
        let wrong_audience = TokenSpec::default()
            .claim("aud", json!("https://mcp.corliss.test"))
            .sign();
        for query in [
            String::new(),
            "?access_token=".to_string(),
            "?access_token=garbage".to_string(),
            format!("?access_token={expired}"),
            format!("?access_token={wrong_audience}"),
        ] {
            let status = upgrade(&format!("{base}/{query}")).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{query}");
        }
    }

    #[sqlx::test(migrations = false)]
    async fn a_listing_makes_the_private_workspace_only_its_owner_can_open(pool: PgPool) {
        let (base, authz) = relay(&pool).await;

        let (status, workspace) = private_workspace(&base, ALICE).await;
        assert_eq!(status, StatusCode::OK);
        assert!(workspace["name"].is_null());
        assert_eq!(workspace["path"], "Private");
        assert_eq!(
            workspace["url"],
            format!("automerge:{}", workspace["root_doc_id"].as_str().unwrap())
        );
        assert!(workspace["created_at"].is_string());
        assert!(workspace["last_change_at"].is_null());

        let root = workspace["root_doc_id"].as_str().unwrap().parse().unwrap();
        assert!(authz.opens(&auth::Did(ALICE.into()), &root));
        assert!(!authz.opens(&auth::Did(BOB.into()), &root));

        // The member's own listing finds the same one.
        let own: Value = reqwest::Client::new()
            .get(format!("{base}/vaults"))
            .bearer_auth(member_token(ALICE))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(own["vaults"].as_array().unwrap().len(), 1);
        assert_eq!(own["vaults"][0]["root_doc_id"], workspace["root_doc_id"]);
        // In no group, and still told the Workspaces folder.
        assert_eq!(own["folders"], json!(["Private", "Workspaces"]));

        let response = reqwest::Client::new()
            .get(format!("{base}/internal/workspaces?did=alice"))
            .bearer_auth(SERVICE_TOKEN)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = false)]
    async fn listings_show_only_the_members_own_workspaces(pool: PgPool) {
        let (base, _) = relay(&pool).await;
        let (_, alices) = private_workspace(&base, ALICE).await;
        let (_, bobs) = private_workspace(&base, BOB).await;
        assert_ne!(alices["root_doc_id"], bobs["root_doc_id"]);

        let own: Value = reqwest::Client::new()
            .get(format!("{base}/vaults"))
            .bearer_auth(member_token(ALICE))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let roots: Vec<_> = own["vaults"]
            .as_array()
            .unwrap()
            .iter()
            .map(|workspace| workspace["root_doc_id"].clone())
            .collect();
        assert_eq!(roots, [alices["root_doc_id"].clone()]);
    }

    #[sqlx::test(migrations = false)]
    async fn a_group_workspace_lists_for_whoever_the_token_puts_in_it(pool: PgPool) {
        let (base, _) = relay(&pool).await;
        let client = reqwest::Client::new();

        let response = group_workspace(&base, ALICE, "7", "Garden").await;
        assert_eq!(response.status(), StatusCode::OK);
        let workspace: Value = response.json().await.unwrap();
        assert_eq!(workspace["group_id"], "7");
        assert_eq!(workspace["path"], "Workspaces/Garden");

        // Asked again by another member: the same workspace, and the name sent is
        // the one it carries, which is how a rename in Corliss reaches it.
        let response = group_workspace(&base, BOB, "7", " Garden Club ").await;
        assert_eq!(response.status(), StatusCode::OK);
        let again: Value = response.json().await.unwrap();
        assert_eq!(again["root_doc_id"], workspace["root_doc_id"]);
        assert_eq!(again["path"], "Workspaces/Garden Club");

        let bob_in_7 = TokenSpec::default()
            .claim("sub", json!(BOB))
            .claim("workspaces", json!(["7"]))
            .sign();
        let own = client.get(format!("{base}/vaults")).bearer_auth(&bob_in_7);
        assert_eq!(
            workspace_paths(own).await,
            ["Workspaces/Garden Club", "Private"]
        );

        // Alice made it, and a token naming no group still does not list it.
        let alice = client
            .get(format!("{base}/vaults"))
            .bearer_auth(member_token(ALICE));
        assert_eq!(workspace_paths(alice).await, ["Private"]);

        let for_bob = client
            .get(format!("{base}/internal/workspaces?did={BOB}&groups=7,9"))
            .bearer_auth(SERVICE_TOKEN);
        assert_eq!(
            workspace_paths(for_bob).await,
            ["Workspaces/Garden Club", "Private"]
        );

        for (did, group, name, code) in [
            (BOB, "7", "  ", "invalid_name"),
            (BOB, "a/b", "Seeds", "invalid_group"),
            ("bob", "7", "Seeds", "invalid_did"),
        ] {
            let response = group_workspace(&base, did, group, name).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{code}");
            let answer: Value = response.json().await.unwrap();
            assert_eq!(answer["error"], code);
        }
    }

    #[sqlx::test(migrations = false)]
    async fn the_endpoints_before_v0_7_0_keep_their_shape(pool: PgPool) {
        let (base, _) = relay(&pool).await;
        let client = reqwest::Client::new();
        let service = |request: reqwest::RequestBuilder| request.bearer_auth(SERVICE_TOKEN).send();

        // Corliss before the rename asks for a workspace's vault.
        let response = service(
            client
                .put(format!("{base}/internal/vaults/workspace"))
                .json(&json!({ "did": BOB, "workspace": "7", "name": "Garden" })),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let vault: Value = response.json().await.unwrap();
        assert_eq!(vault["workspace"], "7");
        assert!(vault.get("group_id").is_none(), "{vault}");

        let listing: Value =
            service(client.get(format!("{base}/internal/vaults?did={BOB}&workspaces=7")))
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        assert_eq!(listing["folders"], json!(["Private", "Workspaces"]));
        let entries: Vec<_> = listing["vaults"]
            .as_array()
            .unwrap()
            .iter()
            .map(|vault| (vault["path"].clone(), vault["workspace"].clone()))
            .collect();
        assert_eq!(
            entries,
            [
                (json!("Workspaces/Garden"), json!("7")),
                (json!("Private"), Value::Null)
            ]
        );

        let all: Value = service(client.get(format!("{base}/internal/vaults/all")))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(all["vaults"][0]["owner_did"], BOB);
        assert_eq!(all["vaults"][0]["workspace"], "7");

        // A plugin up to 1.2.x lists its own.
        let bob_in_7 = TokenSpec::default()
            .claim("sub", json!(BOB))
            .claim("workspaces", json!(["7"]))
            .sign();
        let own: Value = client
            .get(format!("{base}/vaults"))
            .bearer_auth(&bob_in_7)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(own["vaults"].as_array().unwrap().len(), 2);
        assert_eq!(own["folders"], json!(["Private", "Workspaces"]));

        let refused = service(
            client
                .put(format!("{base}/internal/vaults/workspace"))
                .json(&json!({ "did": BOB, "workspace": "a/b", "name": "Seeds" })),
        )
        .await
        .unwrap();
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        let answer: Value = refused.json().await.unwrap();
        assert_eq!(answer["error"], "invalid_workspace");

        // The same workspaces in the new shape.
        let listing: Value =
            service(client.get(format!("{base}/internal/workspaces?did={BOB}&groups=7")))
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        assert_eq!(listing["root_folders"], json!(["Private", "Workspaces"]));
        assert_eq!(listing["workspaces"][0]["group_id"], "7");
        assert!(listing["workspaces"][0].get("workspace").is_none());
    }

    #[sqlx::test(migrations = false)]
    async fn the_admin_listing_is_everyones_and_takes_no_parameters(pool: PgPool) {
        let (base, authz) = relay(&pool).await;
        private_workspace(&base, ALICE).await;
        private_workspace(&base, BOB).await;
        group_workspace(&base, BOB, "7", "Garden").await;
        authz::tests::eventually("every workspace is walked", || authz.all_walked()).await;

        let client = reqwest::Client::new();
        let all = |query: &str| {
            client
                .get(format!("{base}/internal/workspaces/all{query}"))
                .bearer_auth(SERVICE_TOKEN)
                .send()
        };
        let body: Value = all("").await.unwrap().json().await.unwrap();
        let listed: Vec<_> = body["workspaces"]
            .as_array()
            .unwrap()
            .iter()
            .map(|workspace| {
                assert!(workspace["bytes"].is_i64(), "{workspace}");
                (
                    workspace["owner_did"].as_str().unwrap(),
                    workspace["path"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            listed,
            [
                (ALICE, "Private"),
                (BOB, "Private"),
                (BOB, "Workspaces/Garden"),
            ]
        );
        assert_eq!(body["unfiled"], json!([]));

        // A query string is not read: it cannot narrow the listing to anyone.
        let narrowed: Value = all(&format!("?did={ALICE}"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(narrowed["workspaces"], body["workspaces"]);

        // The member-facing listings never carry the creator.
        let own: Value = client
            .get(format!("{base}/vaults"))
            .bearer_auth(member_token(ALICE))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(own["vaults"][0].get("owner_did").is_none());
    }

    #[sqlx::test(migrations = false)]
    async fn workspace_endpoints_refuse_the_wrong_credential(pool: PgPool) {
        let (base, _) = relay(&pool).await;
        let client = reqwest::Client::new();
        let member = member_token(ALICE);
        let internal = format!("{base}/internal/workspaces");
        let for_alice = format!("{internal}?did={ALICE}");
        let body = json!({ "did": ALICE, "group_id": "7", "name": "Notes" });
        let group = internal.clone();

        for request in [
            // The member endpoint: no token, the service credential, a token
            // for another audience.
            client.get(format!("{base}/vaults")),
            client
                .get(format!("{base}/vaults"))
                .bearer_auth(SERVICE_TOKEN),
            client.get(format!("{base}/vaults")).bearer_auth(
                TokenSpec::default()
                    .claim("aud", json!("https://mcp.corliss.test"))
                    .sign(),
            ),
            // The internal endpoints: no credential, a wrong one, a member's
            // own token.
            client.get(&for_alice),
            client.get(&for_alice).bearer_auth("wrong"),
            client.get(&for_alice).bearer_auth(&member),
            client.put(&group).json(&body),
            client.put(&group).json(&body).bearer_auth("wrong"),
            client.put(&group).json(&body).bearer_auth(&member),
            client.get(format!("{internal}/all")),
            client.get(format!("{internal}/all")).bearer_auth("wrong"),
            client.get(format!("{internal}/all")).bearer_auth(&member),
        ] {
            let response = request.send().await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[sqlx::test(migrations = false)]
    async fn a_restart_keeps_workspace_records(pool: PgPool) {
        let (base, _) = relay(&pool).await;
        private_workspace(&base, ALICE).await;

        let (base, _) = relay(&pool).await;
        let own = reqwest::Client::new()
            .get(format!("{base}/vaults"))
            .bearer_auth(member_token(ALICE));
        assert_eq!(workspace_paths(own).await, ["Private"]);
    }

    /// Dials the relay's websocket the way a sync client does, token in the
    /// URL.
    struct WsDialer(samod::Url);

    impl samod::Dialer for WsDialer {
        type Error = std::convert::Infallible;

        fn url(&self) -> samod::Url {
            self.0.clone()
        }

        fn connect(
            &self,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<samod::Transport, samod::DialError<Self::Error>>,
                    > + Send,
            >,
        > {
            use futures::{SinkExt, StreamExt};
            use tokio_tungstenite::tungstenite::{Error, Message};

            let url = self.0.clone();
            Box::pin(async move {
                let (socket, _) = tokio_tungstenite::connect_async(url.as_str())
                    .await
                    .map_err(samod::DialError::transient)?;
                let (sink, stream) = socket.split();
                let stream = stream.filter_map(|message| async move {
                    match message {
                        Ok(Message::Binary(frame)) => Some(Ok(frame.to_vec())),
                        Ok(_) => None,
                        Err(e) => Some(Err(e)),
                    }
                });
                let sink = sink.with(|frame: Vec<u8>| async move {
                    Ok::<_, Error>(Message::Binary(frame.into()))
                });
                Ok(samod::Transport::new(Box::pin(stream), Box::pin(sink)))
            })
        }
    }

    fn sync_url(base: &str, token: &str) -> String {
        format!("{}/?access_token={token}", base.replace("http://", "ws://"))
    }

    /// A sync client of its own, connected to the relay as `did`.
    async fn client(base: &str, did: &str) -> Repo {
        let repo = Repo::build_tokio().load().await;
        let url = sync_url(base, &member_token(did)).parse().unwrap();
        repo.dial(samod::BackoffConfig::default(), Arc::new(WsDialer(url)))
            .unwrap()
            .established()
            .await
            .unwrap();
        repo
    }

    /// A document with one key set, so there is something to tell apart from
    /// an empty one.
    fn doc_with(key: &str, value: &str) -> automerge::Automerge {
        use automerge::transaction::Transactable;
        let mut doc = automerge::Automerge::new();
        let mut tx = doc.transaction();
        tx.put(automerge::ROOT, key, value).unwrap();
        tx.commit();
        doc
    }

    async fn value_of(handle: &samod::DocHandle, key: &'static str) -> Option<String> {
        use automerge::ReadDoc;
        handle
            .with_document_async(move |doc| {
                let (value, _) = doc.get(automerge::ROOT, key).ok()??;
                Some(value.as_str()?.to_string())
            })
            .await
            .unwrap()
    }

    #[sqlx::test(migrations = false)]
    async fn a_member_syncs_their_own_documents_and_nobody_elses(pool: PgPool) {
        let (base, authz) = relay(&pool).await;
        let laptop = client(&base, ALICE).await;
        let note = laptop.create(doc_with("title", "plan")).await.unwrap();
        let id = note.document_id().clone();
        authz::tests::eventually("the relay has the note", || authz.creator_of(&id).is_some())
            .await;
        assert!(authz.opens(&auth::Did(ALICE.into()), &id));

        // Her phone gets it from the relay, with the laptop's content.
        let phone = client(&base, ALICE).await;
        let on_phone = phone.find(id.clone()).await.unwrap().expect("found");
        assert_eq!(value_of(&on_phone, "title").await.as_deref(), Some("plan"));

        // Bob is told it is not there, and asking does not make it his.
        let bob = client(&base, BOB).await;
        assert!(bob.find(id.clone()).await.unwrap().is_none());
        assert_eq!(authz.creator_of(&id), Some(auth::Did(ALICE.into())));
    }

    #[sqlx::test(migrations = false)]
    async fn a_workspace_root_reaches_its_owner_only(pool: PgPool) {
        let (base, _) = relay(&pool).await;
        let (_, workspace) = private_workspace(&base, ALICE).await;
        let root: samod::DocumentId = workspace["root_doc_id"].as_str().unwrap().parse().unwrap();

        let alice = client(&base, ALICE).await;
        assert!(alice.find(root.clone()).await.unwrap().is_some());

        let bob = client(&base, BOB).await;
        assert!(bob.find(root).await.unwrap().is_none());
    }

    #[sqlx::test(migrations = false)]
    async fn a_change_reaches_a_peer_already_syncing_the_document(pool: PgPool) {
        let (base, authz) = relay(&pool).await;
        let laptop = client(&base, ALICE).await;
        let note = laptop.create(doc_with("title", "plan")).await.unwrap();
        let id = note.document_id().clone();
        authz::tests::eventually("the relay has the note", || authz.creator_of(&id).is_some())
            .await;

        let phone = client(&base, ALICE).await;
        let on_phone = phone.find(id).await.unwrap().expect("found");

        note.with_document_async(|doc| {
            use automerge::transaction::Transactable;
            let mut tx = doc.transaction();
            tx.put(automerge::ROOT, "status", "done").unwrap();
            tx.commit();
        })
        .await
        .unwrap();

        // The relay announces nothing, so this arrives only because the phone
        // asked for the document.
        for _ in 0..100 {
            if value_of(&on_phone, "status").await.as_deref() == Some("done") {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("the laptop's edit never reached the phone");
    }

    #[sqlx::test(migrations = false)]
    async fn a_connection_is_closed_when_its_token_expires(pool: PgPool) {
        use futures::StreamExt;
        use tokio_tungstenite::tungstenite::Message;

        let (base, _) = relay(&pool).await;
        let exp = jsonwebtoken::get_current_timestamp() + 2;
        let token = TokenSpec::default().claim("exp", json!(exp)).sign();
        let (mut socket, _) = tokio_tungstenite::connect_async(sync_url(&base, &token))
            .await
            .unwrap();

        let opened = std::time::Instant::now();
        let closed = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                match socket.next().await {
                    Some(Ok(Message::Close(frame))) => return frame,
                    Some(Ok(_)) => continue,
                    other => panic!("ended without a close frame: {other:?}"),
                }
            }
        })
        .await
        .expect("still open long after the token expired")
        .expect("a close frame with a reason");

        assert_eq!(u16::from(closed.code), 1008);
        assert_eq!(closed.reason.as_str(), "token expired");
        // Not closed early: it stayed open until `exp`.
        assert!(opened.elapsed() >= std::time::Duration::from_millis(900));
    }

    impl Relay {
        /// A token for the `notes.` host, as the plugin holds one.
        fn notes_token(&self, did: &str, groups: &[&str]) -> String {
            TokenSpec::default()
                .claim("sub", json!(did))
                .claim("aud", json!(self.notes))
                .claim("workspaces", json!(groups))
                .sign()
        }

        /// A token for MCP on the `notes.` host.
        fn notes_mcp_token(&self, did: &str) -> String {
            TokenSpec::default()
                .claim("sub", json!(did))
                .claim("aud", json!(format!("{}/mcp", self.notes)))
                .sign()
        }
    }

    #[sqlx::test(migrations = false)]
    async fn the_notes_host_serves_sync_and_the_listing_on_one_token(pool: PgPool) {
        let relay = start(&pool).await;
        let notes = &relay.notes;
        let token = relay.notes_token(BOB, &["7"]);
        relay
            .authz
            .group_workspace(&auth::Did(ALICE.into()), "7", "Garden")
            .await
            .unwrap();

        assert_eq!(
            upgrade(&format!("{notes}/v1/sync?access_token={token}")).await,
            StatusCode::SWITCHING_PROTOCOLS
        );
        let listing: Value = reqwest::Client::new()
            .get(format!("{notes}/v1/workspaces"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(listing["root_folders"], json!(["Private", "Workspaces"]));
        let entries: Vec<_> = listing["workspaces"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| (w["path"].clone(), w["group_id"].clone()))
            .collect();
        assert_eq!(
            entries,
            [
                (json!("Workspaces/Garden"), json!("7")),
                (json!("Private"), Value::Null)
            ]
        );

        // Tokens for the old hosts, or for MCP, are not for these routes.
        let mcp_here = relay.notes_mcp_token(BOB);
        for wrong in [member_token(BOB), relay.mcp_token(BOB), mcp_here] {
            assert_eq!(
                upgrade(&format!("{notes}/v1/sync?access_token={wrong}")).await,
                StatusCode::UNAUTHORIZED
            );
            let status = reqwest::Client::new()
                .get(format!("{notes}/v1/workspaces"))
                .bearer_auth(&wrong)
                .send()
                .await
                .unwrap()
                .status();
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
    }

    #[sqlx::test(migrations = false)]
    async fn the_notes_host_names_the_member_behind_each_actor(pool: PgPool) {
        let relay = start(&pool).await;
        relay
            .ok(
                ALICE,
                "create_note",
                json!({ "path": "Private/plan.md", "content": "dig beds" }),
            )
            .await;
        let alice = auth::Did(ALICE.into());
        let (_, doc) = mcp::tests::notes_of(&relay.authz, &alice)
            .await
            .into_iter()
            .find(|(path, _)| path == "plan.md")
            .unwrap();
        let hers = relay.authz.mcp_actor(&alice).await.unwrap();
        // Bob's actor is known to the relay, but made nothing in this note.
        let his = relay.authz.mcp_actor(&auth::Did(BOB.into())).await.unwrap();
        let stranger = automerge::ActorId::random();

        let url = format!("{}/v1/documents/{doc}/actors", relay.notes);
        let ask = |token: Option<String>, actors: Vec<String>| {
            let mut request = reqwest::Client::new()
                .post(&url)
                .json(&json!({ "actors": actors }));
            if let Some(token) = token {
                request = request.bearer_auth(token);
            }
            request.send()
        };
        let asked = vec![
            hers.to_hex_string(),
            his.to_hex_string(),
            stranger.to_hex_string(),
        ];

        let response = ask(Some(relay.notes_token(ALICE, &[])), asked.clone())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = response.json().await.unwrap();
        let actors = &body["actors"];
        assert_eq!(actors[hers.to_hex_string()]["did"], ALICE);
        assert_eq!(actors[his.to_hex_string()]["did"], Value::Null);
        assert_eq!(actors[stranger.to_hex_string()]["did"], Value::Null);

        // Bob may not open her Private note, and needs a token at all.
        let status = |r: reqwest::Result<reqwest::Response>| r.unwrap().status();
        assert_eq!(
            status(ask(Some(relay.notes_token(BOB, &[])), asked.clone()).await),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            status(ask(None, asked.clone()).await),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(
                ask(
                    Some(relay.notes_token(ALICE, &[])),
                    vec![stranger.to_hex_string(); actors::MAX_ACTORS + 1]
                )
                .await
            ),
            StatusCode::BAD_REQUEST
        );
    }

    #[sqlx::test(migrations = false)]
    async fn the_notes_host_serves_mcp_at_its_path(pool: PgPool) {
        let relay = start(&pool).await;
        let notes = &relay.notes;
        let mcp = format!("{notes}/mcp");
        let rpc = |token: Option<String>| {
            let mut request = reqwest::Client::new()
                .post(&mcp)
                .header("accept", "application/json, text/event-stream")
                .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} }));
            if let Some(token) = token {
                request = request.bearer_auth(token);
            }
            request.send()
        };

        let response = rpc(Some(relay.notes_mcp_token(ALICE))).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["result"]["tools"].as_array().unwrap().len(), 7);

        // The plugin's token is not an MCP token, and a refusal says where to
        // find the issuer.
        let metadata_url = format!("{notes}/.well-known/oauth-protected-resource/mcp");
        for token in [None, Some(relay.notes_token(ALICE, &[]))] {
            let response = rpc(token).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                response.headers()["www-authenticate"],
                format!("Bearer resource_metadata=\"{metadata_url}\"")
            );
        }

        // Two metadata documents, one per resource.
        let get = |url: String| async move {
            reqwest::get(url)
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        };
        let for_mcp = get(metadata_url.clone()).await;
        assert_eq!(for_mcp["resource"], mcp);
        assert_eq!(
            for_mcp["authorization_servers"],
            json!([auth::tests::ISSUER])
        );
        let for_plugin = get(format!("{notes}/.well-known/oauth-protected-resource")).await;
        assert_eq!(for_plugin["resource"], *notes);
        assert_eq!(
            for_plugin["bearer_methods_supported"],
            json!(["header", "query"])
        );
    }

    #[sqlx::test(migrations = false)]
    async fn the_notes_host_serves_nothing_else(pool: PgPool) {
        let relay = start(&pool).await;
        let notes = &relay.notes;
        let token = relay.notes_token(ALICE, &[]);
        let client = reqwest::Client::new();
        for path in [
            "/",
            "/sync",
            "/vaults",
            "/v1/vaults",
            "/internal/workspaces?did=did:plc:alice",
            "/internal/workspaces/all",
            "/internal/vaults/all",
        ] {
            let status = client
                .get(format!("{notes}{path}"))
                .bearer_auth(SERVICE_TOKEN)
                .send()
                .await
                .unwrap()
                .status();
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        }
        // Not even as a websocket at the root, where the old host has one.
        assert_eq!(
            upgrade(&format!("{notes}/?access_token={token}")).await,
            StatusCode::NOT_FOUND
        );
    }

    #[sqlx::test(migrations = false)]
    async fn a_device_on_the_old_host_and_one_on_notes_see_each_others_edits(pool: PgPool) {
        let relay = start(&pool).await;
        let old_laptop = client(&relay.base, ALICE).await;
        let note = old_laptop.create(doc_with("title", "plan")).await.unwrap();
        let id = note.document_id().clone();
        authz::tests::eventually("the relay has the note", || {
            relay.authz.creator_of(&id).is_some()
        })
        .await;

        let url = format!(
            "{}/v1/sync?access_token={}",
            relay.notes.replace("http://", "ws://"),
            relay.notes_token(ALICE, &[])
        );
        let new_phone = Repo::build_tokio().load().await;
        new_phone
            .dial(
                samod::BackoffConfig::default(),
                Arc::new(WsDialer(url.parse().unwrap())),
            )
            .unwrap()
            .established()
            .await
            .unwrap();
        let on_phone = new_phone.find(id).await.unwrap().expect("found");
        assert_eq!(value_of(&on_phone, "title").await.as_deref(), Some("plan"));

        on_phone
            .with_document_async(|doc| {
                use automerge::transaction::Transactable;
                let mut tx = doc.transaction();
                tx.put(automerge::ROOT, "status", "done").unwrap();
                tx.commit();
            })
            .await
            .unwrap();
        for _ in 0..100 {
            if value_of(&note, "status").await.as_deref() == Some("done") {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("the phone's edit never reached the laptop");
    }

    impl Relay {
        fn mcp_token(&self, did: &str) -> String {
            self.mcp_token_in(did, &[])
        }

        /// An MCP token for a member in these groups.
        fn mcp_token_in(&self, did: &str, groups: &[&str]) -> String {
            TokenSpec::default()
                .claim("sub", json!(did))
                .claim("aud", json!(self.mcp))
                .claim("workspaces", json!(groups))
                .sign()
        }

        /// One JSON-RPC request to the MCP service, as a client sends it.
        async fn rpc(&self, token: Option<&str>, method: &str, params: Value) -> reqwest::Response {
            let mut request = reqwest::Client::new()
                .post(&self.mcp)
                .header("accept", "application/json, text/event-stream")
                .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }));
            if let Some(token) = token {
                request = request.bearer_auth(token);
            }
            request.send().await.unwrap()
        }

        /// Call a tool as a member. Returns whether the tool reported an
        /// error, and the text it answered with.
        async fn call(&self, did: &str, tool: &str, arguments: Value) -> (bool, String) {
            self.call_in(did, &[], tool, arguments).await
        }

        /// [`Relay::call`] for a member in these groups.
        async fn call_in(
            &self,
            did: &str,
            groups: &[&str],
            tool: &str,
            arguments: Value,
        ) -> (bool, String) {
            let response = self
                .rpc(
                    Some(&self.mcp_token_in(did, groups)),
                    "tools/call",
                    json!({ "name": tool, "arguments": arguments }),
                )
                .await;
            assert_eq!(response.status(), StatusCode::OK, "{tool}");
            assert_eq!(
                response.headers()["content-type"],
                "application/json",
                "{tool} answered with a stream"
            );
            let body: Value = response.json().await.unwrap();
            let result = &body["result"];
            assert!(result.is_object(), "{tool}: {body}");
            (
                result["isError"].as_bool().unwrap_or(false),
                result["content"][0]["text"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            )
        }

        /// Call a tool that is expected to work, and return its answer.
        async fn ok(&self, did: &str, tool: &str, arguments: Value) -> String {
            let (is_error, text) = self.call(did, tool, arguments).await;
            assert!(!is_error, "{tool} refused: {text}");
            text
        }

        /// Call a tool that is expected to refuse, and return why.
        async fn refused(&self, did: &str, tool: &str, arguments: Value) -> String {
            let (is_error, text) = self.call(did, tool, arguments).await;
            assert!(is_error, "{tool} should have refused, said: {text}");
            text
        }
    }

    /// The paths a listing or a search returned.
    fn paths(answer: &str) -> Vec<String> {
        let items: Value = serde_json::from_str(answer).unwrap();
        items
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["path"].as_str().unwrap().to_string())
            .collect()
    }

    #[sqlx::test(migrations = false)]
    async fn mcp_sends_an_unauthenticated_client_to_the_issuer(pool: PgPool) {
        let relay = start(&pool).await;
        let metadata_url = format!("{}/.well-known/oauth-protected-resource", relay.mcp);
        let sync_token = member_token(ALICE);

        for token in [None, Some("garbage"), Some(sync_token.as_str())] {
            let response = relay.rpc(token, "tools/list", json!({})).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                response.headers()["www-authenticate"],
                format!("Bearer resource_metadata=\"{metadata_url}\"")
            );
        }

        let metadata: Value = reqwest::get(&metadata_url)
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(metadata["resource"], relay.mcp);
        assert_eq!(
            metadata["authorization_servers"],
            json!([auth::tests::ISSUER])
        );
    }

    #[sqlx::test(migrations = false)]
    async fn mcp_paths_start_with_their_workspace(pool: PgPool) {
        let relay = start(&pool).await;
        // Created under one name and renamed with its group.
        relay
            .authz
            .group_workspace(&auth::Did(ALICE.into()), "7", "Old name")
            .await
            .unwrap();
        relay
            .authz
            .group_workspace(&auth::Did(ALICE.into()), "7", "Notes")
            .await
            .unwrap();
        let in_7 = ["7"];

        let (is_error, text) = relay
            .call_in(
                ALICE,
                &in_7,
                "create_note",
                json!({ "path": "Workspaces/Notes/plan.md", "content": "dig beds" }),
            )
            .await;
        assert!(!is_error, "{text}");
        assert_eq!(text, "Created Workspaces/Notes/plan.md.");

        // Until the index walks the folder, the note is Alice's alone.
        let alice = auth::Caller::in_groups(auth::Did(ALICE.into()), vec!["7".into()]);
        let mut walked = false;
        for _ in 0..200 {
            let workspaces = relay.authz.list_workspaces(&alice).await.unwrap();
            let shared = workspaces
                .iter()
                .find(|workspace| workspace.group_id.is_some())
                .unwrap();
            if shared.note_count == Some(1) {
                walked = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(walked, "the note never joined the workspace");

        // With no path, Bob's workspaces. His Private one is made by this
        // first listing.
        let relay = &relay;
        let list = |arguments: Value| async move {
            let (is_error, text) = relay.call_in(BOB, &in_7, "list_notes", arguments).await;
            assert!(!is_error, "{text}");
            let listed: Value = serde_json::from_str(&text).unwrap();
            listed
                .as_array()
                .unwrap()
                .iter()
                .map(|item| {
                    format!(
                        "{} {}",
                        item["type"].as_str().unwrap(),
                        item["path"].as_str().unwrap()
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            list(json!({})).await,
            ["workspace Private", "workspace Workspaces/Notes"]
        );
        assert_eq!(
            list(json!({ "path": "Workspaces" })).await,
            ["workspace Workspaces/Notes"]
        );
        assert_eq!(
            list(json!({ "path": "workspaces/notes" })).await,
            ["note Workspaces/Notes/plan.md"]
        );
        assert_eq!(
            list(json!({ "recursive": true })).await,
            [
                "workspace Private",
                "workspace Workspaces/Notes",
                "note Workspaces/Notes/plan.md"
            ]
        );

        // Any letter case reaches it.
        let (is_error, text) = relay
            .call_in(
                BOB,
                &in_7,
                "read_note",
                json!({ "path": "workspaces/notes/plan.md" }),
            )
            .await;
        assert!(!is_error, "{text}");
        assert_eq!(text, "dig beds");

        // Private is his own.
        let (is_error, text) = relay
            .call_in(
                BOB,
                &in_7,
                "create_note",
                json!({ "path": "Private/mine.md", "content": "just me" }),
            )
            .await;
        assert!(!is_error, "{text}");
        assert_eq!(text, "Created Private/mine.md.");

        // Search covers every workspace unless given a path.
        let found = |arguments: Value| async move {
            let (is_error, text) = relay.call_in(BOB, &in_7, "search_notes", arguments).await;
            assert!(!is_error, "{text}");
            paths(&text)
        };
        assert_eq!(
            found(json!({ "query": "beds" })).await,
            ["Workspaces/Notes/plan.md"]
        );
        assert_eq!(found(json!({ "query": "just" })).await, ["Private/mine.md"]);
        assert!(found(json!({ "query": "beds", "path": "Private" }))
            .await
            .is_empty());

        // A path has to start with a workspace he has.
        for (path, why) in [
            ("mine.md", "in no workspace"),
            ("Projects/mine.md", "in no workspace"),
            ("Workspaces", "name one"),
            ("Workspaces/Garden/plan.md", "no shared workspace named"),
        ] {
            let (is_error, text) = relay
                .call_in(BOB, &in_7, "read_note", json!({ "path": path }))
                .await;
            assert!(is_error, "{path}: {text}");
            assert!(text.contains(why), "{path}: {text}");
        }

        // Without the group in his token, there is no such workspace.
        let why = relay
            .refused(
                BOB,
                "read_note",
                json!({ "path": "Workspaces/Notes/plan.md" }),
            )
            .await;
        assert!(why.contains("no shared workspace named"), "{why}");
    }

    #[sqlx::test(migrations = false)]
    async fn note_history_lists_changes_by_member_and_reads_old_versions(pool: PgPool) {
        let relay = start(&pool).await;
        relay
            .authz
            .group_workspace(&auth::Did(ALICE.into()), "7", "Garden")
            .await
            .unwrap();
        let in_7 = ["7"];
        let path = "Workspaces/Garden/plan.md";
        let (is_error, text) = relay
            .call_in(
                ALICE,
                &in_7,
                "create_note",
                json!({ "path": path, "content": "dig beds" }),
            )
            .await;
        assert!(!is_error, "{text}");

        // Bob can reach it once the index has walked the folder.
        let mut edited = false;
        for _ in 0..200 {
            let (is_error, _) = relay
                .call_in(
                    BOB,
                    &in_7,
                    "edit_note",
                    json!({ "path": path, "old_text": "dig", "new_text": "rake" }),
                )
                .await;
            if !is_error {
                edited = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(edited, "Bob never reached the shared note");

        let history = |arguments: Value| {
            let relay = &relay;
            async move {
                let (is_error, text) = relay.call_in(ALICE, &in_7, "note_history", arguments).await;
                assert!(!is_error, "{text}");
                text
            }
        };
        let listing: Value = serde_json::from_str(&history(json!({ "path": path })).await).unwrap();
        let groups = listing["groups"].as_array().unwrap();
        assert_eq!(groups[0]["did"], BOB);
        assert_eq!(groups[1]["did"], ALICE);
        assert!(groups[0]["device_time"]["to"].is_string());
        assert_eq!(listing["more"], false);
        let (bobs, alices) = (
            groups[0]["id"].as_str().unwrap(),
            groups[1]["id"].as_str().unwrap(),
        );

        assert_eq!(
            history(json!({ "path": path, "version": alices })).await,
            "dig beds"
        );
        let hunks: Value = serde_json::from_str(
            &history(json!({ "path": path, "version": alices, "compare_to": bobs })).await,
        )
        .unwrap();
        assert_eq!(hunks[0]["removed"], "dig");
        assert_eq!(hunks[0]["added"], "rake");

        // Nothing changed the note.
        let (_, text) = relay
            .call_in(ALICE, &in_7, "read_note", json!({ "path": path }))
            .await;
        assert_eq!(text, "rake beds");

        // Without the group, there is no such note to give a history of.
        relay
            .refused(BOB, "note_history", json!({ "path": path }))
            .await;
    }

    #[sqlx::test(migrations = false)]
    async fn the_sync_listener_names_its_issuer(pool: PgPool) {
        let relay = start(&pool).await;
        let metadata: Value = reqwest::get(format!(
            "{}/.well-known/oauth-protected-resource",
            relay.base
        ))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
        assert_eq!(metadata["resource"], SYNC_AUDIENCE);
        assert_eq!(
            metadata["authorization_servers"],
            json!([auth::tests::ISSUER])
        );
        assert_eq!(
            metadata["bearer_methods_supported"],
            json!(["header", "query"])
        );
    }

    #[sqlx::test(migrations = false)]
    async fn mcp_initializes_and_lists_its_tools(pool: PgPool) {
        let relay = start(&pool).await;
        let token = relay.mcp_token(ALICE);

        let response = relay
            .rpc(
                Some(&token),
                "initialize",
                json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": { "name": "test", "version": "0" },
                }),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        // Stateless: no session to carry into the next request.
        assert!(response.headers().get("mcp-session-id").is_none());
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["result"]["serverInfo"]["name"], "scn-notes");

        let body: Value = relay
            .rpc(Some(&token), "tools/list", json!({}))
            .await
            .json()
            .await
            .unwrap();
        let mut names: Vec<_> = body["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                "append_note",
                "create_note",
                "edit_note",
                "list_notes",
                "note_history",
                "read_note",
                "search_notes"
            ]
        );
    }

    #[sqlx::test(migrations = false)]
    async fn a_member_creates_reads_edits_and_searches_notes(pool: PgPool) {
        let relay = start(&pool).await;
        private_workspace(&relay.base, ALICE).await;

        // No initialize was ever sent: every call stands on its own token.
        assert_eq!(
            paths(
                &relay
                    .ok(ALICE, "list_notes", json!({ "path": "Private" }))
                    .await
            ),
            [""; 0]
        );

        relay
            .ok(
                ALICE,
                "create_note",
                json!({ "path": "Private/Projects/plan.md", "content": "# Plan\nShip the relay 🚀 first.\n" }),
            )
            .await;
        relay
            .ok(
                ALICE,
                "create_note",
                json!({ "path": "Private/inbox.md", "content": "relay relay" }),
            )
            .await;

        assert_eq!(
            paths(
                &relay
                    .ok(ALICE, "list_notes", json!({ "path": "Private" }))
                    .await
            ),
            ["Private/inbox.md", "Private/Projects"]
        );
        assert_eq!(
            paths(
                &relay
                    .ok(
                        ALICE,
                        "list_notes",
                        json!({ "path": "Private", "recursive": true })
                    )
                    .await
            ),
            [
                "Private/inbox.md",
                "Private/Projects",
                "Private/Projects/plan.md"
            ]
        );
        assert_eq!(
            paths(
                &relay
                    .ok(ALICE, "list_notes", json!({ "path": "Private/projects" }))
                    .await
            ),
            ["Private/Projects/plan.md"]
        );

        // The edit lands after an emoji, where text positions are easy to
        // get wrong.
        relay
            .ok(
                ALICE,
                "edit_note",
                json!({ "path": "Private/Projects/plan.md", "old_text": "🚀 first", "new_text": "🚀 before Corliss" }),
            )
            .await;
        relay
            .ok(
                ALICE,
                "append_note",
                json!({ "path": "Private/Projects/plan.md", "text": "Then the plugin." }),
            )
            .await;
        relay
            .ok(
                ALICE,
                "append_note",
                json!({ "path": "Private/inbox.md", "text": "second line" }),
            )
            .await;
        assert_eq!(
            relay
                .ok(
                    ALICE,
                    "read_note",
                    json!({ "path": "Private/Projects/plan.md" })
                )
                .await,
            "# Plan\nShip the relay 🚀 before Corliss.\nThen the plugin."
        );
        assert_eq!(
            relay
                .ok(ALICE, "read_note", json!({ "path": "/Private/inbox.md" }))
                .await,
            "relay relay\nsecond line"
        );

        // Best match first, and a note found by a word in its path.
        let found = relay
            .ok(ALICE, "search_notes", json!({ "query": "RELAY" }))
            .await;
        assert_eq!(
            paths(&found),
            ["Private/inbox.md", "Private/Projects/plan.md"]
        );
        assert!(found.contains("Ship the relay"));
        let found = relay
            .ok(ALICE, "search_notes", json!({ "query": "projects plugin" }))
            .await;
        assert_eq!(paths(&found), ["Private/Projects/plan.md"]);
        let found = relay
            .ok(
                ALICE,
                "search_notes",
                json!({ "query": "nothing-says-this" }),
            )
            .await;
        assert!(paths(&found).is_empty());
    }

    #[sqlx::test(migrations = false)]
    async fn tools_refuse_what_they_should(pool: PgPool) {
        let relay = start(&pool).await;
        private_workspace(&relay.base, ALICE).await;
        relay
            .ok(
                ALICE,
                "create_note",
                json!({ "path": "Private/a.md", "content": "one two one" }),
            )
            .await;

        for (tool, arguments) in [
            // Already there, in any letter case.
            (
                "create_note",
                json!({ "path": "Private/A.md", "content": "" }),
            ),
            (
                "create_note",
                json!({ "path": "Private/notes.txt", "content": "" }),
            ),
            (
                "create_note",
                json!({ "path": "Private/.hidden/a.md", "content": "" }),
            ),
            (
                "create_note",
                json!({ "path": "Private/../a.md", "content": "" }),
            ),
            // A note is not a folder.
            (
                "create_note",
                json!({ "path": "Private/a.md/b.md", "content": "" }),
            ),
            ("read_note", json!({ "path": "Private/missing.md" })),
            ("list_notes", json!({ "path": "Private/missing" })),
            (
                "edit_note",
                json!({ "path": "Private/a.md", "old_text": "three", "new_text": "3" }),
            ),
            // Two matches and no replace_all.
            (
                "edit_note",
                json!({ "path": "Private/a.md", "old_text": "one", "new_text": "1" }),
            ),
            (
                "edit_note",
                json!({ "path": "Private/a.md", "old_text": "", "new_text": "x" }),
            ),
            (
                "append_note",
                json!({ "path": "Private/missing.md", "text": "x" }),
            ),
            ("read_note", json!({ "path": "Other/a.md" })),
            ("search_notes", json!({ "query": "  " })),
        ] {
            relay.refused(ALICE, tool, arguments).await;
        }
        // None of that changed the note.
        assert_eq!(
            relay
                .ok(ALICE, "read_note", json!({ "path": "Private/a.md" }))
                .await,
            "one two one"
        );

        relay
            .ok(
                ALICE,
                "edit_note",
                json!({ "path": "Private/a.md", "old_text": "one", "new_text": "1", "replace_all": true }),
            )
            .await;
        assert_eq!(
            relay
                .ok(ALICE, "read_note", json!({ "path": "Private/a.md" }))
                .await,
            "1 two 1"
        );

        // A group's workspace does not change what no workspace named means: it
        // is still her private workspace.
        group_workspace(&relay.base, ALICE, "7", "Garden").await;
        let in_7 = ["7"];
        let (is_error, text) = relay
            .call_in(ALICE, &in_7, "read_note", json!({ "path": "Private/a.md" }))
            .await;
        assert!(!is_error, "{text}");
        assert_eq!(text, "1 two 1");
        let (is_error, _) = relay
            .call_in(
                ALICE,
                &in_7,
                "read_note",
                json!({ "path": "Workspaces/Garden/a.md" }),
            )
            .await;
        assert!(is_error);
    }

    #[sqlx::test(migrations = false)]
    async fn tools_never_reach_another_members_notes(pool: PgPool) {
        let relay = start(&pool).await;
        private_workspace(&relay.base, ALICE).await;
        let (_, bobs) = private_workspace(&relay.base, BOB).await;
        relay
            .ok(
                ALICE,
                "create_note",
                json!({ "path": "Private/secret.md", "content": "alice only" }),
            )
            .await;

        // Same workspace name, his own workspace: hers is not in it.
        assert!(paths(
            &relay
                .ok(
                    BOB,
                    "list_notes",
                    json!({ "path": "Private", "recursive": true })
                )
                .await
        )
        .is_empty());
        relay
            .refused(BOB, "read_note", json!({ "path": "Private/secret.md" }))
            .await;
        relay
            .refused(BOB, "note_history", json!({ "path": "Private/secret.md" }))
            .await;
        assert!(paths(
            &relay
                .ok(BOB, "search_notes", json!({ "query": "alice" }))
                .await
        )
        .is_empty());

        // Bob writes a link to her note into his own root folder.
        let alice = auth::Did(ALICE.into());
        let notes = mcp::tests::notes_of(&relay.authz, &alice).await;
        let secret = notes
            .into_iter()
            .find(|(path, _)| path == "secret.md")
            .unwrap()
            .1;
        let bobs_root: samod::DocumentId = bobs["root_doc_id"].as_str().unwrap().parse().unwrap();
        let entry = reach::Entry {
            name: "stolen.md".to_string(),
            kind: "md".to_string(),
            url: samod::AutomergeUrl::from(&secret).to_string(),
        };
        relay
            .repo
            .find(bobs_root)
            .await
            .unwrap()
            .unwrap()
            .with_document_async(move |doc| reach::add_entry(doc, &entry))
            .await
            .unwrap()
            .unwrap();

        assert!(paths(
            &relay
                .ok(BOB, "list_notes", json!({ "path": "Private" }))
                .await
        )
        .is_empty());
        relay
            .refused(BOB, "read_note", json!({ "path": "Private/stolen.md" }))
            .await;
        relay
            .refused(BOB, "note_history", json!({ "path": "Private/stolen.md" }))
            .await;
        relay
            .refused(
                BOB,
                "append_note",
                json!({ "path": "Private/stolen.md", "text": "mine now" }),
            )
            .await;
        assert!(paths(
            &relay
                .ok(BOB, "search_notes", json!({ "query": "alice" }))
                .await
        )
        .is_empty());
        assert_eq!(
            relay
                .ok(ALICE, "read_note", json!({ "path": "Private/secret.md" }))
                .await,
            "alice only"
        );
    }

    #[sqlx::test(migrations = false)]
    async fn an_mcp_edit_reaches_a_sync_client_and_a_sync_edit_reaches_mcp(pool: PgPool) {
        use automerge::{transaction::Transactable, ReadDoc};

        let relay = start(&pool).await;
        let (_, workspace) = private_workspace(&relay.base, ALICE).await;
        let root: samod::DocumentId = workspace["root_doc_id"].as_str().unwrap().parse().unwrap();

        // Her device is connected and syncing the workspace's root before
        // anything is written.
        let device = client(&relay.base, ALICE).await;
        let folder = device
            .find(root)
            .await
            .unwrap()
            .expect("the workspace root");

        relay
            .ok(
                ALICE,
                "create_note",
                json!({ "path": "Private/today.md", "content": "from Claude" }),
            )
            .await;

        // The new entry arrives in the folder she already has...
        let mut entries = Vec::new();
        for _ in 0..100 {
            entries = folder
                .with_document_async(|doc| reach::read_entries(doc))
                .await
                .unwrap();
            if !entries.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(entries.len(), 1, "the entry never reached the device");
        assert_eq!(
            (entries[0].name.as_str(), entries[0].kind.as_str()),
            ("today.md", "md")
        );

        // ...and the note it points at can be fetched, as the plugin would.
        let note_id = entries[0].doc_id().unwrap();
        let note = device.find(note_id).await.unwrap().expect("the note");
        let text = note
            .with_document_async(|doc| reach::read_string(doc, &automerge::ROOT, "content"))
            .await
            .unwrap();
        assert_eq!(text.as_deref(), Some("from Claude"));

        // She types on the device. MCP reads it with no laptop in between.
        note.with_document_async(|doc| {
            let (_, content) = doc.get(automerge::ROOT, "content").unwrap().unwrap();
            let end = doc.length(&content);
            let mut tx = doc.transaction();
            tx.splice_text(&content, end, 0, ", and from the phone")
                .unwrap();
            tx.commit();
        })
        .await
        .unwrap();

        for _ in 0..100 {
            let text = relay
                .ok(ALICE, "read_note", json!({ "path": "Private/today.md" }))
                .await;
            if text == "from Claude, and from the phone" {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("the device's edit never reached MCP");
    }
}
