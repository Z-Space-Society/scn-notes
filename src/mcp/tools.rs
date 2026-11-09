//! The MCP tools.
//!
//! Every tool acts as the member whose token made the request. The auth
//! middleware has already verified that token and left the member's DID in
//! the request's extensions; a tool reads the DID from there and never sees
//! the token.

use axum::http::request::Parts;
use rmcp::{
    handler::server::{router::tool::ToolRouter, tool::Extension, wrapper::Parameters},
    model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig},
    schemars, tool, tool_handler, tool_router, ErrorData, ServerHandler,
};
use serde::Deserialize;
use serde_json::json;

use super::history::History;
use super::notes::{NoteError, Notes};
use super::search;
use crate::auth::Caller;
use crate::authz::Authz;

const DEFAULT_SEARCH_LIMIT: usize = 20;
const MAX_SEARCH_LIMIT: usize = 50;
const DEFAULT_HISTORY_LIMIT: usize = 20;
const MAX_HISTORY_LIMIT: usize = 100;

#[derive(Clone)]
pub struct NotesServer {
    authz: Authz,
    tool_router: ToolRouter<Self>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ListNotes {
    /// What to list. Leave out for your workspaces: "Private", yours alone,
    /// and "Workspaces/<name>" for each shared one. "Workspaces" lists the
    /// shared ones; a workspace or a folder in one, such as
    /// "Private/Projects", lists what is in it.
    path: Option<String>,
    /// Also list everything inside the folders found. Defaults to false.
    recursive: Option<bool>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ReadNote {
    /// Path of the note, starting with its workspace: "Private/plan.md" for
    /// your own, "Workspaces/<name>/plan.md" for a shared one.
    path: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct SearchNotes {
    /// Words to look for. A note matches when it contains all of them, in its
    /// text or its path, in any letter case.
    query: String,
    /// Where to look: a workspace or a folder in one, such as "Private" or
    /// "Workspaces/Garden/Plans". Leave out to search every workspace you have.
    path: Option<String>,
    /// The most notes to return. Defaults to 20, at most 50.
    limit: Option<usize>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct CreateNote {
    /// Path for the new note, starting with its workspace and ending in ".md":
    /// "Private/Projects/plan.md", or "Workspaces/<name>/plan.md" to share it
    /// with that workspace. Folders on the way that do not exist are created.
    path: String,
    /// The note's markdown.
    content: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct EditNote {
    /// Path of the note, starting with its workspace: "Private/plan.md" for
    /// your own, "Workspaces/<name>/plan.md" for a shared one.
    path: String,
    /// The exact text to replace. It must appear in the note, and only once
    /// unless replace_all is set, so include enough around it to be unique.
    old_text: String,
    /// The text to put in its place. Empty removes old_text.
    new_text: String,
    /// Replace every place old_text appears. Defaults to false.
    replace_all: Option<bool>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct AppendNote {
    /// Path of the note, starting with its workspace: "Private/plan.md" for
    /// your own, "Workspaces/<name>/plan.md" for a shared one.
    path: String,
    /// The text to add. It starts on a new line.
    text: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct NoteHistory {
    /// Path of the note, starting with its workspace: "Private/plan.md" for
    /// your own, "Workspaces/<name>/plan.md" for a shared one.
    path: String,
    /// A change's id from this tool's listing. Alone, returns the note's text
    /// as that change left it; to restore it, create a new note from that
    /// text. With compare_to, the start of a diff.
    version: Option<String>,
    /// A second change id: returns what changed from version to this one.
    compare_to: Option<String>,
    /// The most groups of changes to list. Defaults to 20, at most 100.
    limit: Option<usize>,
}

fn said(text: impl Into<String>) -> Result<CallToolResult, ErrorData> {
    Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
}

fn listed(value: serde_json::Value) -> Result<CallToolResult, ErrorData> {
    said(serde_json::to_string_pretty(&value).unwrap_or_default())
}

/// A refusal goes back as a tool result the model can read and act on. A
/// fault of ours is logged and reported as an error without detail.
fn failed(e: NoteError) -> Result<CallToolResult, ErrorData> {
    match e {
        NoteError::Refused(why) => Ok(CallToolResult::error(vec![ContentBlock::text(why)])),
        NoteError::Internal(e) => {
            tracing::error!(error = %e, "a tool failed");
            Err(ErrorData::internal_error(
                "the relay could not do that",
                None,
            ))
        }
    }
}

/// The member the request was authenticated as.
fn caller(parts: &Parts) -> Result<Caller, ErrorData> {
    parts
        .extensions
        .get::<Caller>()
        .cloned()
        // Unreachable behind the middleware. Refused rather than assumed.
        .ok_or_else(|| ErrorData::invalid_request("not authenticated", None))
}

#[tool_router]
impl NotesServer {
    pub fn new(authz: Authz) -> Self {
        Self {
            authz,
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "List your workspaces, or the notes and folders in one. With no path, lists your workspaces: Private, which is yours alone, and Workspaces/<name> for each one you share with others. Every path these tools take and return starts with its workspace.",
        annotations(title = "List notes", read_only_hint = true)
    )]
    async fn list_notes(
        &self,
        Parameters(args): Parameters<ListNotes>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, ErrorData> {
        let caller = caller(&parts)?;
        let notes = Notes {
            authz: &self.authz,
            caller: &caller,
        };
        let found = notes.list_anywhere(
            args.path.as_deref().unwrap_or_default(),
            args.recursive.unwrap_or(false),
        );
        match found.await {
            Ok(found) => listed(json!(found
                .iter()
                .map(|item| json!({ "path": item.path, "type": item.kind.as_str() }))
                .collect::<Vec<_>>())),
            Err(e) => failed(e),
        }
    }

    #[tool(
        description = "Read a note's markdown.",
        annotations(title = "Read note", read_only_hint = true)
    )]
    async fn read_note(
        &self,
        Parameters(args): Parameters<ReadNote>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, ErrorData> {
        let caller = caller(&parts)?;
        let notes = Notes {
            authz: &self.authz,
            caller: &caller,
        };
        let text = async {
            let at = notes.locate(&args.path).await?;
            notes.read(&at.root, &at.rest).await
        };
        match text.await {
            Ok(text) => said(text),
            Err(e) => failed(e),
        }
    }

    #[tool(
        description = "A note's history. With no version: its changes, newest first, grouped \
                       by session, each with the member's DID (or \"unknown\"), the device's \
                       time, and characters added and removed. With version: the note's text \
                       as that change left it, removed text included. With version and \
                       compare_to: the text removed and added between them. Times are as each \
                       device's clock reported them. This never changes the note.",
        annotations(title = "Note history", read_only_hint = true)
    )]
    async fn note_history(
        &self,
        Parameters(args): Parameters<NoteHistory>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, ErrorData> {
        let caller = caller(&parts)?;
        let notes = Notes {
            authz: &self.authz,
            caller: &caller,
        };
        let limit = args
            .limit
            .unwrap_or(DEFAULT_HISTORY_LIMIT)
            .clamp(1, MAX_HISTORY_LIMIT);
        let path = args.path.clone();
        let history = async {
            let at = notes.locate(&args.path).await?;
            notes
                .history(&at.root, &at.rest, args.version, args.compare_to, limit)
                .await
        };
        let time = |t: Option<chrono::DateTime<chrono::Utc>>| t.map(|t| t.to_rfc3339());
        match history.await {
            Ok(History::Changes { groups, more }) => listed(json!({
                "path": path,
                "times": "as each device's clock reported them",
                "groups": groups.iter().map(|group| json!({
                    "id": group.id.to_string(),
                    "did": self
                        .authz
                        .actor_owner(&group.actor)
                        .map_or_else(|| "unknown".to_string(), |did| did.0),
                    "device_time": { "from": time(group.from), "to": time(group.to) },
                    "added": group.added,
                    "removed": group.removed,
                    "changes": group.changes,
                })).collect::<Vec<_>>(),
                "more": more,
            })),
            Ok(History::Text(text)) => said(text),
            Ok(History::Diff(hunks)) => listed(json!(hunks
                .iter()
                .map(|hunk| json!({
                    "line": hunk.line,
                    "removed": hunk.removed,
                    "added": hunk.added,
                }))
                .collect::<Vec<_>>())),
            Err(e) => failed(e),
        }
    }

    #[tool(
        description = "Search the text of your notes, in every workspace or in one workspace or \
                       folder. Returns the matching notes' paths with the lines that matched.",
        annotations(title = "Search notes", read_only_hint = true)
    )]
    async fn search_notes(
        &self,
        Parameters(args): Parameters<SearchNotes>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, ErrorData> {
        let caller = caller(&parts)?;
        let notes = Notes {
            authz: &self.authz,
            caller: &caller,
        };
        let limit = args
            .limit
            .unwrap_or(DEFAULT_SEARCH_LIMIT)
            .clamp(1, MAX_SEARCH_LIMIT);
        let hits = async {
            let scopes = notes
                .scopes(args.path.as_deref().unwrap_or_default())
                .await?;
            search::search(&notes, &scopes, &args.query, limit).await
        };
        match hits.await {
            Ok(hits) => listed(json!(hits
                .iter()
                .map(|hit| json!({
                    "path": hit.path,
                    "matches": hit.count,
                    "lines": hit.lines,
                }))
                .collect::<Vec<_>>())),
            Err(e) => failed(e),
        }
    }

    #[tool(
        description = "Create a new note. Fails if something already exists at the path.",
        annotations(
            title = "Create note",
            read_only_hint = false,
            destructive_hint = false
        )
    )]
    async fn create_note(
        &self,
        Parameters(args): Parameters<CreateNote>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, ErrorData> {
        let caller = caller(&parts)?;
        let notes = Notes {
            authz: &self.authz,
            caller: &caller,
        };
        let created = async {
            let at = notes.locate(&args.path).await?;
            let path = notes.create(&at.root, &at.rest, &args.content).await?;
            Ok(at.full(&path))
        };
        match created.await {
            Ok(path) => said(format!("Created {path}.")),
            Err(e) => failed(e),
        }
    }

    #[tool(
        description = "Change part of a note by replacing one piece of its text with another. \
                       Read the note first so old_text matches it exactly.",
        annotations(title = "Edit note", read_only_hint = false, destructive_hint = true)
    )]
    async fn edit_note(
        &self,
        Parameters(args): Parameters<EditNote>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, ErrorData> {
        let caller = caller(&parts)?;
        let notes = Notes {
            authz: &self.authz,
            caller: &caller,
        };
        let path = args.path.clone();
        let edited = async {
            let at = notes.locate(&args.path).await?;
            notes
                .edit(
                    &at.root,
                    &at.rest,
                    args.old_text,
                    args.new_text,
                    args.replace_all.unwrap_or(false),
                )
                .await
        };
        match edited.await {
            Ok(1) => said(format!("Edited {path}.")),
            Ok(n) => said(format!("Edited {path} in {n} places.")),
            Err(e) => failed(e),
        }
    }

    #[tool(
        description = "Add text to the end of a note.",
        annotations(
            title = "Append to note",
            read_only_hint = false,
            destructive_hint = false
        )
    )]
    async fn append_note(
        &self,
        Parameters(args): Parameters<AppendNote>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, ErrorData> {
        let caller = caller(&parts)?;
        let notes = Notes {
            authz: &self.authz,
            caller: &caller,
        };
        let path = args.path.clone();
        let appended = async {
            let at = notes.locate(&args.path).await?;
            notes.append(&at.root, &at.rest, args.text).await
        };
        match appended.await {
            Ok(()) => said(format!("Appended to {path}.")),
            Err(e) => failed(e),
        }
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for NotesServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("scn-notes", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "Your Obsidian notes on the Shared Computer Network. Notes are markdown files \
                 addressed by a path that starts with their workspace: Private/... for yours \
                 alone, Workspaces/<name>/... for one you share. Changes made here appear in \
                 Obsidian on your devices, and changes made there appear here.",
            )
    }
}
