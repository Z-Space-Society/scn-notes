//! The workspace endpoints.
//!
//! A workspace is a member's Private workspace or a group's shared one: a
//! tree of folder and note documents under a root, and the unit of access.
//!
//! Two shapes are served while plugins up to 1.2.x and the Corliss before the
//! rename are still about:
//!
//! - **Before v0.7.0**, under `/vaults` and `/internal/vaults`: the listing is
//!   `{"vaults", "folders"}` and each entry names its group as `workspace`.
//!   These answer exactly as they did, and go when `sync.` retires.
//! - **From v0.7.0**, under `/internal/workspaces` here and `/v1/workspaces`
//!   on the `notes.` host: the listing is `{"workspaces", "root_folders"}` and
//!   each entry names its group as `group_id`.
//!
//! `GET /vaults` is for a member, who presents the same token as for sync. The
//! `/internal/` endpoints are for Corliss, which lists workspaces on a
//! member's behalf, asks for a group's workspace by name, and lists every
//! workspace for its admins, presenting a shared service credential. The
//! `/internal/` prefix exists so the proxy can leave it unrouted: it is
//! reachable on the internal network only.
//!
//! Workspaces are made by the relay and nowhere else: a member's Private
//! workspace the first time any listing asks for it, a group's the first time
//! Corliss asks for it. No sync client makes one.

use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use subtle::ConstantTimeEq;

use crate::auth::{is_did, is_group_id, Did};
use crate::authz::{CreateWorkspaceError, HeldWorkspace, Workspace, PRIVATE, WORKSPACES};
use crate::AppState;

/// Which shape an endpoint answers in.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// Before v0.7.0: `vaults`, `folders`, `workspace`.
    Vaults,
    /// From v0.7.0: `workspaces`, `root_folders`, `group_id`.
    Workspaces,
}

impl Shape {
    fn bad_group(self) -> &'static str {
        match self {
            Shape::Vaults => "invalid_workspace",
            Shape::Workspaces => "invalid_group",
        }
    }
}

/// One workspace in the shape asked for.
fn entry(shape: Shape, workspace: &Workspace) -> Value {
    let mut value = serde_json::to_value(workspace).unwrap_or_default();
    if shape == Shape::Vaults {
        if let Value::Object(fields) = &mut value {
            let group = fields.remove("group_id").unwrap_or(Value::Null);
            fields.insert("workspace".into(), group);
        }
    }
    value
}

/// An admin listing entry: a workspace with the DID that made it.
fn held_entry(shape: Shape, held: &HeldWorkspace) -> Value {
    let mut value = entry(shape, &held.workspace);
    if let Value::Object(fields) = &mut value {
        fields.insert("owner_did".into(), json!(held.owner_did));
    }
    value
}

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
    tracing::error!(error = %e, "workspace request failed");
    error(StatusCode::INTERNAL_SERVER_ERROR, "internal")
}

/// Is this call from Corliss? With no credential configured, nothing is.
fn is_service(state: &AppState, headers: &HeaderMap) -> bool {
    match (&state.service_token, bearer(headers)) {
        (Some(expected), Some(presented)) => presented.as_bytes().ct_eq(expected.as_bytes()).into(),
        _ => false,
    }
}

/// A listing, with the root folders a member's workspaces sit under. Both are
/// named even when the member has no workspace in one, so a client can show
/// the folder before anything is in it rather than spell the word itself.
async fn list(
    state: &AppState,
    shape: Shape,
    workspaces: anyhow::Result<Vec<Workspace>>,
) -> Response {
    let mut workspaces = match workspaces {
        Ok(workspaces) => workspaces,
        Err(e) => return internal_error(e),
    };
    if let Err(e) = state.authz.add_sizes(&mut workspaces).await {
        return internal_error(e);
    }
    let entries: Vec<Value> = workspaces.iter().map(|w| entry(shape, w)).collect();
    let roots = [PRIVATE, WORKSPACES];
    let body = match shape {
        Shape::Vaults => json!({ "vaults": entries, "folders": roots }),
        Shape::Workspaces => json!({ "workspaces": entries, "root_folders": roots }),
    };
    Json(body).into_response()
}

/// `GET /vaults`: the caller's own workspace and their groups', in the shape
/// plugins up to 1.2.x read.
pub async fn list_own_vaults(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let verified = match state
        .verifier
        .verify(bearer(&headers), &state.sync_audience)
        .await
    {
        Ok(verified) => verified,
        Err(e) => {
            tracing::info!(error = %e, "refused a workspace listing");
            return unauthorized();
        }
    };
    let workspaces = state.authz.list_workspaces(&verified.caller).await;
    list(&state, Shape::Vaults, workspaces).await
}

/// The query Corliss lists a member's workspaces with. The groups are named
/// `workspaces` before v0.7.0 and `groups` after.
#[derive(Deserialize)]
pub struct ForMember {
    did: String,
    /// Comma-separated group IDs whose workspaces to include.
    #[serde(default, alias = "workspaces")]
    groups: String,
}

async fn for_member(
    state: AppState,
    shape: Shape,
    headers: HeaderMap,
    query: ForMember,
) -> Response {
    if !is_service(&state, &headers) {
        return unauthorized();
    }
    if !is_did(&query.did) {
        return error(StatusCode::BAD_REQUEST, "invalid_did");
    }
    let groups: Vec<String> = query
        .groups
        .split(',')
        .filter(|g| !g.is_empty())
        .map(str::to_string)
        .collect();
    if !groups.iter().all(|g| is_group_id(g)) {
        return error(StatusCode::BAD_REQUEST, shape.bad_group());
    }
    let workspaces = state.authz.workspaces_where(&Did(query.did), &groups).await;
    list(&state, shape, workspaces).await
}

/// `GET /internal/vaults?did=&workspaces=`, the shape before v0.7.0.
pub async fn vaults_for_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ForMember>,
) -> Response {
    for_member(state, Shape::Vaults, headers, query).await
}

/// `GET /internal/workspaces?did=&groups=`: a member's Private workspace and
/// those of the groups Corliss names, which it does from its own roster.
pub async fn workspaces_for_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ForMember>,
) -> Response {
    for_member(state, Shape::Workspaces, headers, query).await
}

async fn all(state: AppState, shape: Shape, headers: HeaderMap) -> Response {
    if !is_service(&state, &headers) {
        return unauthorized();
    }
    let mut held = match state.authz.all_workspaces().await {
        Ok(held) => held,
        Err(e) => return internal_error(e),
    };
    // Collected first: a lazy `map` held across the await is not `Send`.
    let workspaces: Vec<&mut Workspace> = held.iter_mut().map(|h| &mut h.workspace).collect();
    if let Err(e) = state.authz.add_sizes(workspaces).await {
        return internal_error(e);
    }
    let unfiled = match state.authz.unfiled().await {
        Ok(unfiled) => unfiled,
        Err(e) => return internal_error(e),
    };
    let entries: Vec<Value> = held.iter().map(|h| held_entry(shape, h)).collect();
    let key = match shape {
        Shape::Vaults => "vaults",
        Shape::Workspaces => "workspaces",
    };
    Json(json!({ key: entries, "unfiled": unfiled })).into_response()
}

/// `GET /internal/vaults/all`, the shape before v0.7.0.
pub async fn all_vaults(State(state): State<AppState>, headers: HeaderMap) -> Response {
    all(state, Shape::Vaults, headers).await
}

/// `GET /internal/workspaces/all`: every workspace with the DID that made it,
/// and per creator the documents no workspace reaches. For Corliss's admin
/// view.
///
/// Takes no query parameters at all, so no request can choose whose
/// workspaces it gets: it is everyone's or a `401`. Who may see the answer is
/// Corliss's question, asked by the admin gate on the one page that calls
/// this.
pub async fn all_workspaces(State(state): State<AppState>, headers: HeaderMap) -> Response {
    all(state, Shape::Workspaces, headers).await
}

/// The body Corliss asks for a group's workspace with. The group is named
/// `workspace` before v0.7.0 and `group_id` after.
#[derive(Deserialize)]
pub struct GroupWorkspace {
    /// The member asking, who makes the workspace if the group has none yet.
    did: String,
    #[serde(alias = "workspace")]
    group_id: String,
    /// The group's name in Corliss, which its workspace carries.
    name: String,
}

async fn group(
    state: AppState,
    shape: Shape,
    headers: HeaderMap,
    body: GroupWorkspace,
) -> Response {
    if !is_service(&state, &headers) {
        return unauthorized();
    }
    if !is_did(&body.did) {
        return error(StatusCode::BAD_REQUEST, "invalid_did");
    }
    if !is_group_id(&body.group_id) {
        return error(StatusCode::BAD_REQUEST, shape.bad_group());
    }
    match state
        .authz
        .group_workspace(&Did(body.did), &body.group_id, &body.name)
        .await
    {
        Ok(workspace) => Json(entry(shape, &workspace)).into_response(),
        Err(CreateWorkspaceError::InvalidName) => error(StatusCode::BAD_REQUEST, "invalid_name"),
        Err(CreateWorkspaceError::Internal(e)) => internal_error(e),
    }
}

/// `PUT /internal/vaults/workspace`, the shape before v0.7.0.
pub async fn put_vault(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<GroupWorkspace>,
) -> Response {
    group(state, Shape::Vaults, headers, body).await
}

/// `PUT /internal/workspaces`: the group's workspace, for Corliss. Made now if
/// the group has none, and given the name Corliss sends either way, so the
/// same call serves a group's page, its creation and its rename. The relay
/// sees group IDs only, which is why Corliss is the one to ask.
pub async fn put_workspace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<GroupWorkspace>,
) -> Response {
    group(state, Shape::Workspaces, headers, body).await
}
