//! The vault endpoints.
//!
//! `GET /vaults` is for a member, who presents the same token as for sync and
//! sees their own vault and their workspaces'. The `/internal/vaults`
//! endpoints are for Corliss, which lists vaults on a member's behalf, asks
//! for a workspace's vault by name, and lists every vault for its admins,
//! presenting a shared service credential. The `/internal/` prefix exists so the proxy can leave it
//! unrouted: it is reachable on the internal network only.
//!
//! Vaults are made by the relay and nowhere else: a member's private vault the
//! first time any listing asks for it, a workspace's the first time Corliss
//! asks for it. No sync client makes one.

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
pub struct WorkspaceVault {
    /// The member asking, who makes the vault if the workspace has none yet.
    did: String,
    workspace: String,
    /// The workspace's name in Corliss, which its vault carries.
    name: String,
}

/// `PUT /internal/vaults/workspace`: the workspace's vault, for Corliss. Made
/// now if the workspace has none, and given the name Corliss sends either way,
/// so the same call serves a workspace's page, its creation and its rename.
/// The relay sees workspace IDs only, which is why Corliss is the one to ask.
pub async fn workspace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<WorkspaceVault>,
) -> Response {
    if !is_service(&state, &headers) {
        return unauthorized();
    }
    if !is_did(&body.did) {
        return error(StatusCode::BAD_REQUEST, "invalid_did");
    }
    if !is_workspace_id(&body.workspace) {
        return error(StatusCode::BAD_REQUEST, "invalid_workspace");
    }
    match state
        .authz
        .workspace_vault(&Did(body.did), &body.workspace, &body.name)
        .await
    {
        Ok(vault) => Json(vault).into_response(),
        Err(CreateVaultError::InvalidName) => error(StatusCode::BAD_REQUEST, "invalid_name"),
        Err(CreateVaultError::Internal(e)) => internal_error(e),
    }
}
