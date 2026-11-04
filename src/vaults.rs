//! The vault endpoints.
//!
//! `GET /vaults` is for a member, who presents the same token as for sync and
//! sees their own vaults and their workspaces'. The `/internal/vaults`
//! endpoints are for Corliss, which lists and creates vaults on a member's
//! behalf, and lists every vault for its admins, presenting a shared service
//! credential. The `/internal/` prefix exists so the proxy can leave it
//! unrouted: it is reachable on the internal network only.
//!
//! Vaults are created here and nowhere else. No sync client makes one.

use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use subtle::ConstantTimeEq;

use crate::auth::{is_did, is_workspace_id, Did};
use crate::authz::{CreateVaultError, Vault};
use crate::AppState;

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then_some(token.trim())
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, "unauthorized\n").into_response()
}

fn error(status: StatusCode, code: &str) -> Response {
    (status, Json(json!({ "error": code }))).into_response()
}

fn internal_error(e: anyhow::Error) -> Response {
    tracing::error!(error = %e, "vault request failed");
    error(StatusCode::INTERNAL_SERVER_ERROR, "internal")
}

/// Is this call from Corliss? With no credential configured, nothing is.
fn is_service(state: &AppState, headers: &HeaderMap) -> bool {
    match (&state.service_token, bearer(headers)) {
        (Some(expected), Some(presented)) => presented.as_bytes().ct_eq(expected.as_bytes()).into(),
        _ => false,
    }
}

async fn list(state: &AppState, vaults: anyhow::Result<Vec<Vault>>) -> Response {
    let mut vaults = match vaults {
        Ok(vaults) => vaults,
        Err(e) => return internal_error(e),
    };
    match state.authz.add_sizes(&mut vaults).await {
        Ok(()) => Json(json!({ "vaults": vaults })).into_response(),
        Err(e) => internal_error(e),
    }
}

/// `GET /vaults`: the caller's own vaults and their workspaces'.
pub async fn list_own(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let verified = match state
        .verifier
        .verify(bearer(&headers), &state.sync_audience)
        .await
    {
        Ok(verified) => verified,
        Err(e) => {
            tracing::info!(error = %e, "refused a vault listing");
            return unauthorized();
        }
    };
    let vaults = state.authz.list_vaults(&verified.caller).await;
    list(&state, vaults).await
}

#[derive(Deserialize)]
pub struct ForMember {
    did: String,
    /// Comma-separated workspace IDs whose vaults to include.
    #[serde(default)]
    workspaces: String,
}

/// `GET /internal/vaults?did=&workspaces=`: a member's vaults and those of the
/// workspaces Corliss names, which it does from its own roster.
pub async fn list_for_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ForMember>,
) -> Response {
    if !is_service(&state, &headers) {
        return unauthorized();
    }
    if !is_did(&query.did) {
        return error(StatusCode::BAD_REQUEST, "invalid_did");
    }
    let workspaces: Vec<String> = query
        .workspaces
        .split(',')
        .filter(|w| !w.is_empty())
        .map(str::to_string)
        .collect();
    if !workspaces.iter().all(|w| is_workspace_id(w)) {
        return error(StatusCode::BAD_REQUEST, "invalid_workspace");
    }
    let vaults = state.authz.vaults_where(&Did(query.did), &workspaces).await;
    list(&state, vaults).await
}

/// `GET /internal/vaults/all`: every vault with the DID that made it, and per
/// creator the documents no vault reaches. For Corliss's admin view.
///
/// Takes no query parameters at all, so no request can choose whose vaults it
/// gets: it is everyone's or a `401`. Who may see the answer is Corliss's
/// question, asked by the admin gate on the one page that calls this.
pub async fn list_all(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !is_service(&state, &headers) {
        return unauthorized();
    }
    let mut held = match state.authz.all_vaults().await {
        Ok(held) => held,
        Err(e) => return internal_error(e),
    };
    // Collected first: a lazy `map` held across the await is not `Send`.
    let vaults: Vec<&mut Vault> = held.iter_mut().map(|h| &mut h.vault).collect();
    if let Err(e) = state.authz.add_sizes(vaults).await {
        return internal_error(e);
    }
    match state.authz.unfiled().await {
        Ok(unfiled) => Json(json!({ "vaults": held, "unfiled": unfiled })).into_response(),
        Err(e) => internal_error(e),
    }
}

#[derive(Deserialize)]
pub struct NewVault {
    did: String,
    name: String,
    /// The workspace to hold the vault. Left out, the member holds it.
    workspace: Option<String>,
}

/// `POST /internal/vaults`: create a vault for a member or one of their
/// workspaces, for Corliss.
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<NewVault>,
) -> Response {
    if !is_service(&state, &headers) {
        return unauthorized();
    }
    if !is_did(&body.did) {
        return error(StatusCode::BAD_REQUEST, "invalid_did");
    }
    let did = Did(body.did);
    let created = match body.workspace.as_deref() {
        Some(workspace) if !is_workspace_id(workspace) => {
            return error(StatusCode::BAD_REQUEST, "invalid_workspace");
        }
        Some(workspace) => {
            state
                .authz
                .create_workspace_vault(&did, workspace, &body.name)
                .await
        }
        None => state.authz.create_vault(&did, &body.name).await,
    };
    match created {
        Ok(vault) => (StatusCode::CREATED, Json(vault)).into_response(),
        Err(CreateVaultError::InvalidName) => error(StatusCode::BAD_REQUEST, "invalid_name"),
        Err(CreateVaultError::NameTaken) => error(StatusCode::CONFLICT, "name_taken"),
        Err(CreateVaultError::WorkspaceHasVault) => {
            error(StatusCode::CONFLICT, "workspace_has_vault")
        }
        Err(CreateVaultError::Internal(e)) => internal_error(e),
    }
}

#[derive(Deserialize)]
pub struct Rename {
    workspace: String,
    name: String,
}

/// `PATCH /internal/vaults`: rename a workspace's vault, for Corliss, when the
/// workspace is renamed.
pub async fn rename(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Rename>,
) -> Response {
    if !is_service(&state, &headers) {
        return unauthorized();
    }
    if !is_workspace_id(&body.workspace) {
        return error(StatusCode::BAD_REQUEST, "invalid_workspace");
    }
    match state
        .authz
        .rename_workspace_vault(&body.workspace, &body.name)
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error(StatusCode::NOT_FOUND, "no_vault"),
        Err(CreateVaultError::InvalidName) => error(StatusCode::BAD_REQUEST, "invalid_name"),
        Err(CreateVaultError::Internal(e)) => internal_error(e),
        // A workspace's vault name is its own; nothing can take it.
        Err(other) => internal_error(anyhow::anyhow!("rename failed: {other:?}")),
    }
}
