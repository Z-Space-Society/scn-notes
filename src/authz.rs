//! Who may open which document.
//!
//! Every check goes through [`Authz::may_open`]: the sync filter in both
//! directions and every MCP tool.
//!
//! A vault is held by one member or by one workspace. A member's own vault
//! opens to them alone. A workspace's vault opens to whoever's token says they
//! are in that workspace. Corliss decides that when it issues the token, so the
//! relay holds no roster.
//!
//! Two records back it, in two tables beside `storage`:
//!
//! - `vaults`: one row per vault, naming its creator, the workspace that holds
//!   it if any, and its root folder document.
//! - `doc_creators`: the DID of whoever first sent each document, and the
//!   workspaces their token named when they sent it.
//!
//! `doc_creators` is loaded into memory at startup and written through, and
//! the set of documents reachable from each vault's root is derived from it and
//! held in memory too (`reach.rs`). So `may_open` never touches the database,
//! which matters because it runs on every frame.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use samod::{DocumentId, Repo};
use serde::Serialize;
use sqlx::{PgPool, Row};

use crate::actors::Actors;
use crate::auth::{Caller, Did};
use crate::reach;

#[derive(Clone)]
pub struct Authz(pub(crate) Arc<Inner>);

pub(crate) struct Inner {
    pub(crate) pool: PgPool,
    pub(crate) repo: Repo,
    pub(crate) creators: RwLock<HashMap<DocumentId, Caller>>,
    pub(crate) reach: RwLock<reach::Index>,
    pub(crate) actors: RwLock<Actors>,
}

/// Who a vault belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Holder {
    Member(Did),
    Workspace(String),
}

impl Holder {
    fn of(owner: Did, workspace: Option<String>) -> Self {
        match workspace {
            Some(workspace) => Holder::Workspace(workspace),
            None => Holder::Member(owner),
        }
    }

    /// May this caller open the vault?
    pub fn opens_to(&self, caller: &Caller) -> bool {
        match self {
            Holder::Member(owner) => *owner == caller.did,
            Holder::Workspace(workspace) => caller.is_in(workspace),
        }
    }

    /// The admission rule: may a document by this creator join the vault?
    ///
    /// For a member's vault, only if they made it. For a workspace's, only if
    /// its creator was in the workspace when they sent it, so a note outlives
    /// its author's membership. Either way, a member cannot pull someone
    /// else's document in by writing its URL into a folder.
    pub fn admits(&self, creator: &Caller) -> bool {
        self.opens_to(creator)
    }
}

impl std::fmt::Display for Holder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Holder::Member(did) => write!(f, "{did}"),
            Holder::Workspace(workspace) => write!(f, "workspace {workspace}"),
        }
    }
}

/// A member's private vault's path: the group alone, since a member has one.
pub const PRIVATE: &str = "Private";
/// The group workspaces' vaults are listed under.
pub const WORKSPACES: &str = "Workspaces";

/// A vault's path: `Private` for a member's one private vault, which has no
/// name, and the name under its group for a workspace's, `Workspaces/Garden
/// Club`.
///
/// The one place these words are spelled. Every listing carries the result as
/// `path`, so MCP, the Obsidian plugin's folders and Corliss's pages all show
/// what this says rather than each building it.
pub fn path_of(name: Option<&str>, workspace: Option<&str>) -> String {
    match workspace {
        Some(_) => format!("{WORKSPACES}/{}", name.unwrap_or_default()),
        None => PRIVATE.to_string(),
    }
}

/// A vault as the endpoints return it.
#[derive(Clone, Debug, Serialize)]
pub struct Vault {
    pub root_doc_id: String,
    pub url: String,
    /// The workspace's name for its vault. Null for a member's private vault,
    /// which has none of its own.
    pub name: Option<String>,
    /// The workspace that holds the vault, or null for a member's own.
    pub workspace: Option<String>,
    /// The name with its group, from [`path_of`]: how MCP names the vault and
    /// where the Obsidian plugin puts it.
    pub path: String,
    pub created_at: DateTime<Utc>,
    pub last_change_at: Option<DateTime<Utc>>,
    /// Null until the relay has walked the vault since it started.
    pub note_count: Option<usize>,
    /// Bytes the vault's documents take in storage: Automerge history, not
    /// the size of the notes as files. Filled by [`Authz::add_sizes`] only,
    /// so the MCP tools, which list vaults on every call, never pay for it.
    pub bytes: Option<i64>,
}

/// A vault with the DID that made it, for the admin listing only.
///
/// A wrapper rather than a field on [`Vault`], so the member-facing listings
/// never start telling a workspace's members which of them made its vault.
#[derive(Clone, Debug, Serialize)]
pub struct HeldVault {
    pub owner_did: String,
    #[serde(flatten)]
    pub vault: Vault,
}

/// One creator's documents that no vault reaches.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Unfiled {
    pub did: String,
    pub docs: usize,
    pub bytes: i64,
}

/// A `vaults` row as a [`Vault`], with what the index knows filled in.
fn vault_from(row: &sqlx::postgres::PgRow, reach: &reach::Index) -> Result<Vault> {
    let root: String = row.try_get("root_doc_id")?;
    let id = DocumentId::from_str(&root).ok();
    // Memory is ahead of the table by up to a minute.
    let in_memory = id.as_ref().and_then(|id| reach.last_change(id));
    let workspace: Option<String> = row.try_get("workspace_id")?;
    // A private row written before v0.5.0 may still carry its old name until
    // the startup statements clear it; it is never shown.
    let name: Option<String> = match workspace {
        Some(_) => row.try_get("name")?,
        None => None,
    };
    Ok(Vault {
        url: format!("automerge:{root}"),
        note_count: id.as_ref().and_then(|id| reach.note_count(id)),
        root_doc_id: root,
        path: path_of(name.as_deref(), workspace.as_deref()),
        name,
        workspace,
        created_at: row.try_get("created_at")?,
        last_change_at: in_memory.or(row.try_get("last_change_at")?),
        bytes: None,
    })
}

#[derive(Debug)]
pub enum CreateVaultError {
    /// A workspace's vault name that is empty or too long once trimmed.
    InvalidName,
    Internal(anyhow::Error),
}

impl<E: Into<anyhow::Error>> From<E> for CreateVaultError {
    fn from(e: E) -> Self {
        CreateVaultError::Internal(e.into())
    }
}

/// The longest vault name, in characters, after trimming.
const MAX_VAULT_NAME: usize = 100;

impl Authz {
    /// Create the tables if needed, load the records, and start indexing.
    ///
    /// The reachability index fills in behind this call, one vault at a time.
    /// That is safe to serve through: until a vault is indexed its documents
    /// are still open to their creator, who is its owner, and to nobody else.
    pub async fn load(pool: PgPool, repo: Repo) -> Result<Self> {
        migrate(&pool)
            .await
            .context("could not create the ownership schema")?;

        let mut creators = HashMap::new();
        for row in sqlx::query("SELECT doc_id, creator_did, workspaces FROM doc_creators")
            .fetch_all(&pool)
            .await?
        {
            let doc_id: String = row.try_get("doc_id")?;
            match DocumentId::from_str(&doc_id) {
                Ok(id) => {
                    creators.insert(
                        id,
                        Caller::in_workspaces(
                            Did(row.try_get("creator_did")?),
                            row.try_get("workspaces")?,
                        ),
                    );
                }
                Err(_) => tracing::warn!(%doc_id, "skipping an unparseable document ID"),
            }
        }

        let actors = Self::load_actors(&pool).await?;

        let authz = Self(Arc::new(Inner {
            pool,
            repo,
            creators: RwLock::new(creators),
            reach: RwLock::new(reach::Index::default()),
            actors: RwLock::new(actors),
        }));

        for row in
            sqlx::query("SELECT root_doc_id, owner_did, workspace_id, last_change_at FROM vaults")
                .fetch_all(&authz.0.pool)
                .await?
        {
            let root: String = row.try_get("root_doc_id")?;
            match DocumentId::from_str(&root) {
                Ok(id) => authz.start_vault(
                    id,
                    Holder::of(Did(row.try_get("owner_did")?), row.try_get("workspace_id")?),
                    row.try_get("last_change_at")?,
                ),
                Err(_) => tracing::warn!(%root, "skipping a vault with an unparseable root"),
            }
        }
        authz.start_last_change_flush();

        Ok(authz)
    }

    /// May this caller open this document?
    ///
    /// Yes when the document is reachable from a vault that opens to them, or
    /// when they created it and no vault reaches it. The second case is a note
    /// not yet linked into a folder, one part way through a move, or one whose
    /// entry was deleted.
    pub fn may_open(&self, caller: &Caller, doc: &DocumentId) -> bool {
        if let Some(holder) = self.0.reach.read().unwrap().holder_of(doc) {
            return holder.opens_to(caller);
        }
        self.creator_of(doc).as_ref() == Some(&caller.did)
    }

    pub(crate) fn creator_of(&self, doc: &DocumentId) -> Option<Did> {
        self.creator(doc).map(|creator| creator.did)
    }

    /// Who first sent a document, as their token described them then.
    pub(crate) fn creator(&self, doc: &DocumentId) -> Option<Caller> {
        self.0.creators.read().unwrap().get(doc).cloned()
    }

    /// Who holds the vault a document is in, if the index has it in one.
    pub(crate) fn holder_of(&self, doc: &DocumentId) -> Option<Holder> {
        self.0.reach.read().unwrap().holder_of(doc).cloned()
    }

    /// Record who first sent a document, and return who that turned out to be.
    ///
    /// The first writer wins and the row is never changed, so two peers racing
    /// on one ID cannot both become its creator. Their workspaces are kept as
    /// the token named them then, which is what lets a workspace's vault keep
    /// a note after its author leaves. Only a document's first frame reaches
    /// the database; after that the answer comes from memory.
    pub async fn record_creator(&self, doc: &DocumentId, caller: &Caller) -> Result<Did> {
        if let Some(creator) = self.creator_of(doc) {
            return Ok(creator);
        }

        let doc_id = doc.to_string();
        sqlx::query(
            "INSERT INTO doc_creators (doc_id, creator_did, workspaces) VALUES ($1, $2, $3)
             ON CONFLICT (doc_id) DO NOTHING",
        )
        .bind(&doc_id)
        .bind(&caller.did.0)
        .bind(&caller.workspaces)
        .execute(&self.0.pool)
        .await?;
        let row = sqlx::query("SELECT creator_did, workspaces FROM doc_creators WHERE doc_id = $1")
            .bind(&doc_id)
            .fetch_one(&self.0.pool)
            .await?;
        let creator =
            Caller::in_workspaces(Did(row.try_get("creator_did")?), row.try_get("workspaces")?);
        let did = creator.did.clone();

        self.0
            .creators
            .write()
            .unwrap()
            .insert(doc.clone(), creator);
        // A folder may already link to this document, waiting to learn whose
        // it is.
        self.0.reach.read().unwrap().wake_pending(doc);
        Ok(did)
    }

    /// The vaults open to a caller, oldest first: their own, then their
    /// workspaces', interleaved by age.
    pub async fn list_vaults(&self, caller: &Caller) -> Result<Vec<Vault>> {
        self.vaults_where(&caller.did, &caller.workspaces).await
    }

    /// The vaults a member holds plus those of the named workspaces. Corliss
    /// names the workspaces itself; a sync or MCP caller's come from their
    /// token, through [`Authz::list_vaults`].
    ///
    /// The member's private vault is made here when they have none yet, so
    /// whoever asks first, the Obsidian plugin, MCP or Corliss, finds it.
    pub async fn vaults_where(&self, owner: &Did, workspaces: &[String]) -> Result<Vec<Vault>> {
        let mut vaults = self.listed(owner, workspaces).await?;
        if !vaults.iter().any(|vault| vault.workspace.is_none()) {
            self.private_vault(owner)
                .await
                .map_err(|e| anyhow::anyhow!("making the private vault failed: {e:?}"))?;
            vaults = self.listed(owner, workspaces).await?;
        }
        Ok(vaults)
    }

    async fn listed(&self, owner: &Did, workspaces: &[String]) -> Result<Vec<Vault>> {
        let rows = sqlx::query(
            "SELECT root_doc_id, name, workspace_id, created_at, last_change_at FROM vaults
             WHERE (owner_did = $1 AND workspace_id IS NULL) OR workspace_id = ANY($2)
             ORDER BY created_at, root_doc_id",
        )
        .bind(&owner.0)
        .bind(workspaces)
        .fetch_all(&self.0.pool)
        .await?;

        let reach = self.0.reach.read().unwrap();
        rows.iter().map(|row| vault_from(row, &reach)).collect()
    }

    /// Every vault on the relay, with the DID that made it, for Corliss's
    /// admin view. Takes no argument on purpose: there is nothing for a
    /// request to choose.
    pub async fn all_vaults(&self) -> Result<Vec<HeldVault>> {
        let rows = sqlx::query(
            "SELECT root_doc_id, owner_did, name, workspace_id, created_at, last_change_at
             FROM vaults ORDER BY created_at, root_doc_id",
        )
        .fetch_all(&self.0.pool)
        .await?;

        let reach = self.0.reach.read().unwrap();
        rows.iter()
            .map(|row| {
                Ok(HeldVault {
                    owner_did: row.try_get("owner_did")?,
                    vault: vault_from(row, &reach)?,
                })
            })
            .collect()
    }

    /// Per creator, the documents they sent that no vault reaches, and the
    /// bytes those take. `None` until every vault has been walked, because an
    /// unwalked vault's documents would be counted here.
    ///
    /// These are notes linked from no folder: deleted entries, a move cut off
    /// part way, a first frame whose folder never arrived, and entries of a
    /// type the relay does not index.
    pub async fn unfiled(&self) -> Result<Option<Vec<Unfiled>>> {
        let by_creator = {
            let reach = self.0.reach.read().unwrap();
            if !reach.all_walked() {
                return Ok(None);
            }
            let creators = self.0.creators.read().unwrap();
            let mut by_creator: HashMap<String, Vec<String>> = HashMap::new();
            for (doc, creator) in creators.iter() {
                if reach.vault_of(doc).is_none() {
                    by_creator
                        .entry(creator.did.0.clone())
                        .or_default()
                        .push(doc.to_string());
                }
            }
            by_creator
        };

        let mut unfiled = Vec::with_capacity(by_creator.len());
        for (did, docs) in by_creator {
            unfiled.push(Unfiled {
                bytes: self.bytes_of(&docs).await?,
                docs: docs.len(),
                did,
            });
        }
        unfiled.sort_by(|a, b| a.did.cmp(&b.did));
        Ok(Some(unfiled))
    }

    /// Fill in `bytes` for vaults that have been walked.
    pub async fn add_sizes(&self, vaults: impl IntoIterator<Item = &mut Vault>) -> Result<()> {
        for vault in vaults {
            let docs = DocumentId::from_str(&vault.root_doc_id)
                .ok()
                .and_then(|root| self.0.reach.read().unwrap().docs_of(&root));
            let Some(docs) = docs else { continue };
            let docs: Vec<String> = docs.iter().map(ToString::to_string).collect();
            vault.bytes = Some(self.bytes_of(&docs).await?);
        }
        Ok(())
    }

    /// The bytes these documents take in storage.
    pub(crate) async fn bytes_of(&self, docs: &[String]) -> Result<i64> {
        // A document's rows are the keys from `<id>/` up to `<id>0`, `0`
        // being the character after `/`. The `~>=~` and `~<~` operators
        // are the ones `text_pattern_ops` serves, so this is one index
        // range per document; a `LIKE` on a joined value would scan.
        Ok(sqlx::query_scalar(
            "SELECT COALESCE(SUM(octet_length(s.value)), 0)::BIGINT
             FROM unnest($1::TEXT[]) AS d(id)
             JOIN storage s ON s.key ~>=~ (d.id || '/') AND s.key ~<~ (d.id || '0')",
        )
        .bind(docs)
        .fetch_one(&self.0.pool)
        .await?)
    }

    /// The member's private vault, made now if they have none. A member has
    /// one.
    ///
    /// Membership is not checked. The caller is Corliss acting for a signed-in
    /// member, or the member's own token, and a vault whose owner cannot get a
    /// token is unreachable anyway.
    pub async fn private_vault(&self, owner: &Did) -> Result<Vault, CreateVaultError> {
        self.find_or_create(owner, None).await
    }

    /// The workspace's vault, made now by `creator` if it has none, and
    /// carrying `name`, the workspace's name in Corliss, either way. A
    /// workspace has one vault.
    ///
    /// Membership of the workspace is not checked either: Corliss holds the
    /// roster and asks only for a member of it. Only the listing's name
    /// changes on a rename. The root folder's own `title` is left alone: no
    /// client reads it, and rewriting it would be an edit every member syncs.
    pub async fn workspace_vault(
        &self,
        creator: &Did,
        workspace: &str,
        name: &str,
    ) -> Result<Vault, CreateVaultError> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > MAX_VAULT_NAME {
            return Err(CreateVaultError::InvalidName);
        }
        sqlx::query(
            "UPDATE vaults SET name = $1 WHERE workspace_id = $2 AND name IS DISTINCT FROM $1",
        )
        .bind(name)
        .bind(workspace)
        .execute(&self.0.pool)
        .await?;
        self.find_or_create(creator, Some((workspace, name))).await
    }

    /// The vault's row as a [`Vault`], if there is one.
    async fn find(&self, owner: &Did, workspace: Option<&str>) -> Result<Option<Vault>> {
        let row = match workspace {
            Some(workspace) => {
                sqlx::query(
                    "SELECT root_doc_id, name, workspace_id, created_at, last_change_at
                     FROM vaults WHERE workspace_id = $1",
                )
                .bind(workspace)
                .fetch_optional(&self.0.pool)
                .await?
            }
            None => {
                sqlx::query(
                    "SELECT root_doc_id, name, workspace_id, created_at, last_change_at
                     FROM vaults WHERE owner_did = $1 AND workspace_id IS NULL",
                )
                .bind(&owner.0)
                .fetch_optional(&self.0.pool)
                .await?
            }
        };
        let reach = self.0.reach.read().unwrap();
        row.map(|row| vault_from(&row, &reach)).transpose()
    }

    /// Find the vault, or make it: an empty root folder document and its row.
    async fn find_or_create(
        &self,
        owner: &Did,
        workspace: Option<(&str, &str)>,
    ) -> Result<Vault, CreateVaultError> {
        let id = workspace.map(|(id, _)| id);
        // Asked first so the ordinary case leaves no document behind. The
        // unique indexes below are what make it true under a race.
        if let Some(vault) = self.find(owner, id).await? {
            return Ok(vault);
        }

        let title = workspace.map_or(PRIVATE, |(_, name)| name);
        let handle = self
            .0
            .repo
            .create(reach::new_folder(title)?)
            .await
            .map_err(|_| anyhow::anyhow!("repo stopped"))?;
        let root = handle.document_id().clone();
        // The root is the vault's own from the start, whatever this row says,
        // so the creator recorded here only matters if the insert below fails.
        let creator =
            Caller::in_workspaces(owner.clone(), id.map(str::to_string).into_iter().collect());
        self.record_creator(&root, &creator).await?;

        let inserted = sqlx::query(
            "INSERT INTO vaults (root_doc_id, owner_did, workspace_id, name)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(root.to_string())
        .bind(&owner.0)
        .bind(id)
        .bind(workspace.map(|(_, name)| name))
        .execute(&self.0.pool)
        .await;
        match inserted {
            Ok(_) => self.start_vault(
                root,
                Holder::of(owner.clone(), id.map(str::to_string)),
                None,
            ),
            // Lost a race to another request making the same vault. The root
            // document stays behind, open only to its creator and linked from
            // nowhere, and the winner's vault is the answer.
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {}
            Err(e) => return Err(e.into()),
        }
        self.find(owner, id)
            .await?
            .ok_or_else(|| CreateVaultError::Internal(anyhow::anyhow!("the vault's row is gone")))
    }
}

/// Same approach as `PostgresStorage::migrate`: idempotent statements at
/// startup, no migration framework.
async fn migrate(pool: &PgPool) -> Result<(), sqlx::Error> {
    for statement in [
        "CREATE TABLE IF NOT EXISTS vaults (
             root_doc_id    TEXT PRIMARY KEY,
             owner_did      TEXT NOT NULL,
             name           TEXT NOT NULL,
             created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
             last_change_at TIMESTAMPTZ
         )",
        // Null for a member's own vault.
        "ALTER TABLE vaults ADD COLUMN IF NOT EXISTS workspace_id TEXT",
        // Up to v0.3.0 this index covered every row, and up to v0.4.4 the one
        // after it allowed a member many private vaults, one per name.
        "DROP INDEX IF EXISTS vaults_owner_name",
        "DROP INDEX IF EXISTS vaults_member_name",
        // From v0.5.0 a member's private vault has no name: its path is
        // `Private`. A workspace's vault keeps the workspace's name.
        "ALTER TABLE vaults ALTER COLUMN name DROP NOT NULL",
        "UPDATE vaults SET name = NULL WHERE workspace_id IS NULL AND name IS NOT NULL",
        // One private vault per member. Fails, and so stops startup, if a
        // member has two: merging them is not something to do silently. Also
        // serves the lookup by owner.
        "CREATE UNIQUE INDEX IF NOT EXISTS vaults_member
             ON vaults (owner_did) WHERE workspace_id IS NULL",
        // One vault per workspace. Also serves the lookup by workspace.
        "CREATE UNIQUE INDEX IF NOT EXISTS vaults_workspace
             ON vaults (workspace_id) WHERE workspace_id IS NOT NULL",
        "CREATE TABLE IF NOT EXISTS doc_creators (
             doc_id      TEXT PRIMARY KEY,
             creator_did TEXT NOT NULL,
             created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
         )",
        // The creator's workspaces when they sent the document. Empty for
        // every row written before v0.4.0, which is right: no workspace vault
        // existed then.
        "ALTER TABLE doc_creators
             ADD COLUMN IF NOT EXISTS workspaces TEXT[] NOT NULL DEFAULT '{}'",
        // Who each Automerge actor belongs to; see `actors.rs`.
        "CREATE TABLE IF NOT EXISTS actor_members (
             actor_id      TEXT PRIMARY KEY,
             did           TEXT NOT NULL,
             source        TEXT NOT NULL,
             first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
         )",
        // One MCP actor per member.
        "CREATE UNIQUE INDEX IF NOT EXISTS actor_members_mcp
             ON actor_members (did) WHERE source = 'mcp'",
        // One-off jobs that have run, such as the actor backfill.
        "CREATE TABLE IF NOT EXISTS relay_jobs (
             name    TEXT PRIMARY KEY,
             done_at TIMESTAMPTZ NOT NULL DEFAULT now()
         )",
    ] {
        sqlx::query(statement).execute(pool).await?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::time::Duration;

    use automerge::{transaction::Transactable, Automerge, ReadDoc, ROOT};
    use samod::{AutomergeUrl, DocHandle};

    use crate::reach::{add_entry, new_folder, Entry};
    use crate::storage::PostgresStorage;

    pub fn did(name: &str) -> Did {
        Did(format!("did:plc:{name}"))
    }

    /// A relay's worth of state on the test's own database: a repo that
    /// persists to it and the ownership records beside it. Calling it twice on
    /// one pool is a restart.
    pub async fn open(pool: &PgPool) -> (Authz, Repo) {
        let store = PostgresStorage::new(pool.clone());
        store.migrate().await.unwrap();
        let repo = Repo::build_tokio()
            .with_storage(store)
            .with_share_policy(samod::ShareConfig::read_write().with_announce(false))
            .load()
            .await;
        let authz = Authz::load(pool.clone(), repo.clone()).await.unwrap();
        (authz, repo)
    }

    /// Wait for something the index does in the background.
    pub async fn eventually(what: &str, check: impl Fn() -> bool) {
        for _ in 0..200 {
            if check() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("timed out waiting for: {what}");
    }

    impl Authz {
        pub fn vault_of(&self, doc: &DocumentId) -> Option<DocumentId> {
            self.0.reach.read().unwrap().vault_of(doc).cloned()
        }

        pub fn all_walked(&self) -> bool {
            self.0.reach.read().unwrap().all_walked()
        }

        /// [`Authz::may_open`] for a member in no workspace.
        pub fn opens(&self, did: &Did, doc: &DocumentId) -> bool {
            self.may_open(&did.clone().into(), doc)
        }

        /// [`Authz::record_creator`] for a member in no workspace.
        pub async fn record(&self, doc: &DocumentId, did: &Did) -> Result<Did> {
            self.record_creator(doc, &did.clone().into()).await
        }

        /// [`Authz::list_vaults`] for a member in no workspace.
        pub async fn vaults_of(&self, did: &Did) -> Result<Vec<Vault>> {
            self.list_vaults(&did.clone().into()).await
        }
    }

    /// A document as a sync client would have sent it: stored, with `creator`
    /// recorded as its first sender.
    pub async fn sent(authz: &Authz, repo: &Repo, creator: &Did, doc: Automerge) -> DocHandle {
        let handle = repo.create(doc).await.unwrap();
        authz.record(handle.document_id(), creator).await.unwrap();
        handle
    }

    pub async fn link(folder: &DocHandle, name: &str, kind: &str, target: &DocumentId) {
        let entry = Entry {
            name: name.to_string(),
            kind: kind.to_string(),
            url: AutomergeUrl::from(target).to_string(),
        };
        folder
            .with_document_async(move |doc| add_entry(doc, &entry))
            .await
            .unwrap()
            .unwrap();
    }

    pub async fn unlink(folder: &DocHandle, index: usize) {
        folder
            .with_document_async(move |doc| {
                let (_, docs) = doc.get(ROOT, "docs").unwrap().unwrap();
                let mut tx = doc.transaction();
                tx.delete(&docs, index).unwrap();
                tx.commit();
            })
            .await
            .unwrap();
    }

    /// The member's private vault: its root and a handle on it.
    pub async fn vault(authz: &Authz, repo: &Repo, owner: &Did) -> (DocumentId, DocHandle) {
        let vault = authz.private_vault(owner).await.unwrap();
        let root = DocumentId::from_str(&vault.root_doc_id).unwrap();
        let handle = repo.find(root.clone()).await.unwrap().unwrap();
        (root, handle)
    }

    #[sqlx::test(migrations = false)]
    async fn a_vault_root_is_open_to_its_owner_only(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let (root, _) = vault(&authz, &repo, &did("alice")).await;

        assert!(authz.opens(&did("alice"), &root));
        assert!(!authz.opens(&did("bob"), &root));
        assert_eq!(authz.vault_of(&root), Some(root));
    }

    #[sqlx::test(migrations = false)]
    async fn an_unlinked_document_is_open_to_its_creator_only(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let note = sent(&authz, &repo, &did("alice"), Automerge::new()).await;
        let note = note.document_id();

        assert!(authz.opens(&did("alice"), note));
        assert!(!authz.opens(&did("bob"), note));
        assert_eq!(authz.vault_of(note), None);
    }

    #[sqlx::test(migrations = false)]
    async fn a_document_nobody_is_recorded_for_is_open_to_nobody(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let stray = repo.create(Automerge::new()).await.unwrap();
        assert!(!authz.opens(&did("alice"), stray.document_id()));
    }

    #[sqlx::test(migrations = false)]
    async fn the_first_sender_stays_the_creator(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let note = sent(&authz, &repo, &did("alice"), Automerge::new()).await;

        let creator = authz.record(note.document_id(), &did("bob")).await.unwrap();
        assert_eq!(creator, did("alice"));
        assert!(!authz.opens(&did("bob"), note.document_id()));
    }

    #[sqlx::test(migrations = false)]
    async fn linked_notes_and_nested_folders_join_the_vault(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let alice = did("alice");
        let (root, root_doc) = vault(&authz, &repo, &alice).await;

        let folder = sent(&authz, &repo, &alice, new_folder("Projects").unwrap()).await;
        let note = sent(&authz, &repo, &alice, Automerge::new()).await;
        link(&folder, "plan.md", "md", note.document_id()).await;
        link(&root_doc, "Projects", "folder", folder.document_id()).await;

        let note = note.document_id().clone();
        eventually("the nested note is in the vault", || {
            authz.vault_of(&note) == Some(root.clone())
        })
        .await;
        assert_eq!(authz.vault_of(folder.document_id()), Some(root));
        assert!(authz.opens(&alice, &note));
        assert!(!authz.opens(&did("bob"), &note));
    }

    #[sqlx::test(migrations = false)]
    async fn a_link_to_someone_elses_document_is_ignored(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let (alice, bob) = (did("alice"), did("bob"));
        let (root, root_doc) = vault(&authz, &repo, &alice).await;

        let theirs = sent(&authz, &repo, &bob, Automerge::new()).await;
        let mine = sent(&authz, &repo, &alice, Automerge::new()).await;
        link(&root_doc, "stolen.md", "md", theirs.document_id()).await;
        link(&root_doc, "mine.md", "md", mine.document_id()).await;

        // The second link shows the walk that saw the first has finished.
        let mine = mine.document_id().clone();
        eventually("alice's own note is in the vault", || {
            authz.vault_of(&mine) == Some(root.clone())
        })
        .await;
        assert_eq!(authz.vault_of(theirs.document_id()), None);
        assert!(!authz.opens(&alice, theirs.document_id()));
        assert!(authz.opens(&bob, theirs.document_id()));
    }

    #[sqlx::test(migrations = false)]
    async fn a_link_that_arrives_before_the_note_waits_for_its_creator(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let alice = did("alice");
        let (root, root_doc) = vault(&authz, &repo, &alice).await;

        // Stored, but nobody is recorded as having sent it yet.
        let note = repo.create(Automerge::new()).await.unwrap();
        let note_id = note.document_id().clone();
        link(&root_doc, "early.md", "md", &note_id).await;

        let marker = sent(&authz, &repo, &alice, Automerge::new()).await;
        link(&root_doc, "marker.md", "md", marker.document_id()).await;
        let marker = marker.document_id().clone();
        eventually("the walk has seen both links", || {
            authz.vault_of(&marker) == Some(root.clone())
        })
        .await;
        assert_eq!(authz.vault_of(&note_id), None);
        assert!(!authz.opens(&alice, &note_id));

        authz.record(&note_id, &alice).await.unwrap();
        eventually("the waiting link is admitted", || {
            authz.vault_of(&note_id) == Some(root.clone())
        })
        .await;
    }

    #[sqlx::test(migrations = false)]
    async fn a_note_survives_a_move_and_outlives_its_last_entry(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let alice = did("alice");
        let (root, root_doc) = vault(&authz, &repo, &alice).await;

        let folder = sent(&authz, &repo, &alice, new_folder("Archive").unwrap()).await;
        let note = sent(&authz, &repo, &alice, Automerge::new()).await;
        let note_id = note.document_id().clone();
        link(&root_doc, "Archive", "folder", folder.document_id()).await;
        link(&root_doc, "a.md", "md", &note_id).await;
        eventually("the note is in the vault", || {
            authz.vault_of(&note_id) == Some(root.clone())
        })
        .await;

        // A move adds the new entry before removing the old one.
        link(&folder, "a.md", "md", &note_id).await;
        unlink(&root_doc, 1).await;
        tokio::time::sleep(Duration::from_millis(2500)).await;
        assert_eq!(authz.vault_of(&note_id), Some(root));

        // Deleted: out of the vault, still its creator's.
        unlink(&folder, 0).await;
        eventually("the note has left the vault", || {
            authz.vault_of(&note_id).is_none()
        })
        .await;
        assert!(authz.opens(&alice, &note_id));
        assert!(!authz.opens(&did("bob"), &note_id));
    }

    #[sqlx::test(migrations = false)]
    async fn entries_of_other_types_are_left_alone(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let alice = did("alice");
        let (root, root_doc) = vault(&authz, &repo, &alice).await;

        let canvas = sent(&authz, &repo, &alice, Automerge::new()).await;
        let note = sent(&authz, &repo, &alice, Automerge::new()).await;
        link(&root_doc, "board.canvas", "canvas", canvas.document_id()).await;
        link(&root_doc, "a.md", "md", note.document_id()).await;

        let note = note.document_id().clone();
        eventually("the note is in the vault", || {
            authz.vault_of(&note) == Some(root.clone())
        })
        .await;
        assert_eq!(authz.vault_of(canvas.document_id()), None);
    }

    #[sqlx::test(migrations = false)]
    async fn a_change_in_the_vault_sets_its_last_change(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let alice = did("alice");
        let (_, root_doc) = vault(&authz, &repo, &alice).await;
        assert!(authz.vaults_of(&alice).await.unwrap()[0]
            .last_change_at
            .is_none());

        let note = sent(&authz, &repo, &alice, Automerge::new()).await;
        link(&root_doc, "a.md", "md", note.document_id()).await;

        for _ in 0..100 {
            if authz.vaults_of(&alice).await.unwrap()[0]
                .last_change_at
                .is_some()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("last change was never set");
    }

    #[sqlx::test(migrations = false)]
    async fn a_walked_vault_has_a_note_count_and_a_size(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let alice = did("alice");
        let (root, root_doc) = vault(&authz, &repo, &alice).await;

        let mut notes = Vec::new();
        for name in ["a.md", "b.md"] {
            let note = sent(&authz, &repo, &alice, Automerge::new()).await;
            link(&root_doc, name, "md", note.document_id()).await;
            notes.push(note.document_id().clone());
        }
        // Alice's own, but linked from nowhere: in no vault's total.
        sent(&authz, &repo, &alice, Automerge::new()).await;
        eventually("both notes are in the vault", || {
            notes
                .iter()
                .all(|note| authz.vault_of(note) == Some(root.clone()))
        })
        .await;

        let mut vaults = authz.vaults_of(&alice).await.unwrap();
        assert_eq!(vaults[0].note_count, Some(2));
        assert_eq!(vaults[0].bytes, None, "only add_sizes fills it");

        let mut expected = 0;
        for doc in [&root].into_iter().chain(&notes) {
            let doc_bytes: i64 = sqlx::query_scalar(
                "SELECT COALESCE(SUM(octet_length(value)), 0)::BIGINT
                 FROM storage WHERE key LIKE $1 || '/%'",
            )
            .bind(doc.to_string())
            .fetch_one(&pool)
            .await
            .unwrap();
            assert!(doc_bytes > 0, "{doc} has nothing in storage");
            expected += doc_bytes;
        }
        authz.add_sizes(&mut vaults).await.unwrap();
        assert_eq!(vaults[0].bytes, Some(expected));
    }

    #[sqlx::test(migrations = false)]
    async fn documents_no_vault_reaches_are_counted_per_creator(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let (alice, bob) = (did("alice"), did("bob"));
        let (root, root_doc) = vault(&authz, &repo, &alice).await;

        let filed = sent(&authz, &repo, &alice, Automerge::new()).await;
        link(&root_doc, "a.md", "md", filed.document_id()).await;
        let stray = sent(&authz, &repo, &alice, Automerge::new()).await;
        let bobs = sent(&authz, &repo, &bob, Automerge::new()).await;
        let filed = filed.document_id().clone();
        eventually("the filed note is in the vault", || {
            authz.vault_of(&filed) == Some(root.clone())
        })
        .await;

        let mut expected = Vec::new();
        for (owner, doc) in [(&alice, stray.document_id()), (&bob, bobs.document_id())] {
            let bytes: i64 = sqlx::query_scalar(
                "SELECT COALESCE(SUM(octet_length(value)), 0)::BIGINT
                 FROM storage WHERE key LIKE $1 || '/%'",
            )
            .bind(doc.to_string())
            .fetch_one(&pool)
            .await
            .unwrap();
            expected.push(Unfiled {
                did: owner.0.clone(),
                docs: 1,
                bytes,
            });
        }
        assert_eq!(authz.unfiled().await.unwrap(), Some(expected));

        let all = authz.all_vaults().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].owner_did, alice.0);
        assert_eq!(all[0].vault.note_count, Some(1));
    }

    #[sqlx::test(migrations = false)]
    async fn unfiled_is_unknown_until_every_vault_is_walked(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let (root, _) = vault(&authz, &repo, &did("alice")).await;
        // Let the first walk finish so it cannot land after the line below.
        eventually("the vault is walked", || authz.all_walked()).await;
        assert!(authz.unfiled().await.unwrap().is_some());
        // Stand in for the moment after startup when a vault is registered
        // and its walk has not finished.
        authz.0.reach.write().unwrap().forget_walk(&root);
        assert_eq!(authz.unfiled().await.unwrap(), None);
    }

    #[sqlx::test(migrations = false)]
    async fn a_member_has_one_private_vault_with_no_name_made_when_first_listed(pool: PgPool) {
        let (authz, _repo) = open(&pool).await;
        let alice = did("alice");

        let listed = authz.vaults_of(&alice).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, None);
        assert_eq!(listed[0].workspace, None);
        assert_eq!(listed[0].path, "Private");

        // Asked again, every way, it is the same vault.
        assert_eq!(
            authz.vaults_of(&alice).await.unwrap()[0].root_doc_id,
            listed[0].root_doc_id
        );
        assert_eq!(
            authz.private_vault(&alice).await.unwrap().root_doc_id,
            listed[0].root_doc_id
        );
        let bobs = authz.private_vault(&did("bob")).await.unwrap();
        assert_ne!(bobs.root_doc_id, listed[0].root_doc_id);
    }

    #[sqlx::test(migrations = false)]
    async fn a_named_private_vault_from_before_v0_5_0_keeps_its_root_and_loses_its_name(
        pool: PgPool,
    ) {
        let (authz, _repo) = open(&pool).await;
        let alice = did("alice");
        let before = authz.private_vault(&alice).await.unwrap();
        // As v0.4 left it: the private vault carries the name it was made with.
        sqlx::query("UPDATE vaults SET name = 'SCN Notes' WHERE workspace_id IS NULL")
            .execute(&pool)
            .await
            .unwrap();
        drop(authz);

        let (authz, _repo) = open(&pool).await;
        let after = authz.vaults_of(&alice).await.unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].root_doc_id, before.root_doc_id);
        assert_eq!(after[0].path, "Private");
        assert_eq!(after[0].name, None);
        let stored: Option<String> =
            sqlx::query_scalar("SELECT name FROM vaults WHERE workspace_id IS NULL")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stored, None);
    }

    /// A member whose token names these workspaces.
    pub fn member_of(name: &str, workspaces: &[&str]) -> Caller {
        Caller::in_workspaces(
            did(name),
            workspaces.iter().map(|w| w.to_string()).collect(),
        )
    }

    /// A document as a sync client in some workspaces would have sent it.
    pub async fn sent_by(authz: &Authz, repo: &Repo, creator: &Caller) -> DocumentId {
        let handle = repo.create(Automerge::new()).await.unwrap();
        authz
            .record_creator(handle.document_id(), creator)
            .await
            .unwrap();
        handle.document_id().clone()
    }

    pub async fn workspace_vault(
        authz: &Authz,
        repo: &Repo,
        workspace: &str,
    ) -> (DocumentId, DocHandle) {
        let vault = authz
            .workspace_vault(&did("alice"), workspace, "Garden")
            .await
            .unwrap();
        assert_eq!(vault.workspace.as_deref(), Some(workspace));
        let root = DocumentId::from_str(&vault.root_doc_id).unwrap();
        let handle = repo.find(root.clone()).await.unwrap().unwrap();
        (root, handle)
    }

    #[sqlx::test(migrations = false)]
    async fn a_workspace_vault_opens_to_whoever_the_token_puts_in_it(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let (root, _) = workspace_vault(&authz, &repo, "7").await;

        assert!(authz.may_open(&member_of("bob", &["7"]), &root));
        assert!(authz.may_open(&member_of("carol", &["3", "7"]), &root));
        // Alice made it, but a token without the workspace does not open it.
        assert!(!authz.may_open(&member_of("alice", &[]), &root));
        assert!(!authz.may_open(&member_of("dave", &["8"]), &root));
    }

    #[sqlx::test(migrations = false)]
    async fn members_notes_join_a_workspace_vault_and_stay_after_they_leave(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let (root, root_doc) = workspace_vault(&authz, &repo, "7").await;

        let bobs = sent_by(&authz, &repo, &member_of("bob", &["7"])).await;
        let carols = sent_by(&authz, &repo, &member_of("carol", &["7"])).await;
        link(&root_doc, "bob.md", "md", &bobs).await;
        link(&root_doc, "carol.md", "md", &carols).await;
        eventually("both notes are in the vault", || {
            [&bobs, &carols]
                .iter()
                .all(|note| authz.vault_of(note) == Some(root.clone()))
        })
        .await;

        // Each member opens the other's note.
        assert!(authz.may_open(&member_of("carol", &["7"]), &bobs));
        assert!(authz.may_open(&member_of("bob", &["7"]), &carols));

        // Bob's next token leaves the workspace out. He loses the vault, his
        // own note included, and the note stays for everyone still in it.
        assert!(!authz.may_open(&member_of("bob", &[]), &bobs));
        assert!(!authz.may_open(&member_of("bob", &[]), &root));
        assert!(authz.may_open(&member_of("carol", &["7"]), &bobs));
        assert_eq!(authz.vault_of(&bobs), Some(root));
    }

    #[sqlx::test(migrations = false)]
    async fn a_workspace_vault_ignores_documents_from_outside_the_workspace(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let (root, root_doc) = workspace_vault(&authz, &repo, "7").await;

        // Dave was never in it. Bob's private note predates his joining.
        let daves = sent_by(&authz, &repo, &member_of("dave", &["8"])).await;
        let bobs_private = sent_by(&authz, &repo, &member_of("bob", &[])).await;
        let bobs_shared = sent_by(&authz, &repo, &member_of("bob", &["7"])).await;
        link(&root_doc, "dave.md", "md", &daves).await;
        link(&root_doc, "private.md", "md", &bobs_private).await;
        link(&root_doc, "shared.md", "md", &bobs_shared).await;

        eventually("the admitted note is in the vault", || {
            authz.vault_of(&bobs_shared) == Some(root.clone())
        })
        .await;
        assert_eq!(authz.vault_of(&daves), None);
        assert_eq!(authz.vault_of(&bobs_private), None);
        assert!(!authz.may_open(&member_of("carol", &["7"]), &daves));
        assert!(!authz.may_open(&member_of("carol", &["7"]), &bobs_private));
    }

    #[sqlx::test(migrations = false)]
    async fn a_workspace_has_one_vault_apart_from_its_members_own(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let (root, _) = workspace_vault(&authz, &repo, "7").await;

        // Asked for again, by anyone, it is the same vault under the name
        // Corliss sends: that is how a rename reaches it.
        let again = authz
            .workspace_vault(&did("bob"), "7", " Garden Club ")
            .await
            .unwrap();
        assert_eq!(again.root_doc_id, root.to_string());
        assert_eq!(again.path, "Workspaces/Garden Club");

        for bad in ["", "   ", &"x".repeat(101)] {
            let result = authz.workspace_vault(&did("bob"), "7", bad).await;
            assert!(matches!(result, Err(CreateVaultError::InvalidName)));
        }

        let listed: Vec<_> = authz
            .list_vaults(&member_of("alice", &["7"]))
            .await
            .unwrap()
            .into_iter()
            .map(|vault| (vault.path, vault.workspace))
            .collect();
        assert_eq!(
            listed,
            [
                ("Workspaces/Garden Club".to_string(), Some("7".to_string())),
                ("Private".to_string(), None),
            ]
        );
    }

    #[sqlx::test(migrations = false)]
    async fn a_restart_keeps_workspace_vaults_and_creators(pool: PgPool) {
        let note = {
            let (authz, repo) = open(&pool).await;
            let (root, root_doc) = workspace_vault(&authz, &repo, "7").await;
            let note = sent_by(&authz, &repo, &member_of("bob", &["7"])).await;
            link(&root_doc, "bob.md", "md", &note).await;
            eventually("the note is in the vault", || {
                authz.vault_of(&note) == Some(root.clone())
            })
            .await;
            repo.stop().await;
            note
        };

        let (authz, _repo) = open(&pool).await;
        eventually("the index is rebuilt from storage", || {
            authz.vault_of(&note).is_some()
        })
        .await;
        assert!(authz.may_open(&member_of("carol", &["7"]), &note));
        assert!(!authz.may_open(&member_of("carol", &[]), &note));
    }

    #[sqlx::test(migrations = false)]
    async fn a_restart_loses_nothing(pool: PgPool) {
        let alice = did("alice");
        let (root, note_id) = {
            let (authz, repo) = open(&pool).await;
            let (root, root_doc) = vault(&authz, &repo, &alice).await;
            let note = sent(&authz, &repo, &alice, Automerge::new()).await;
            let note_id = note.document_id().clone();
            link(&root_doc, "a.md", "md", &note_id).await;
            eventually("the note is in the vault", || {
                authz.vault_of(&note_id) == Some(root.clone())
            })
            .await;
            repo.stop().await;
            (root, note_id)
        };

        let (authz, _repo) = open(&pool).await;
        let vaults = authz.vaults_of(&alice).await.unwrap();
        assert_eq!(vaults.len(), 1);
        assert_eq!(vaults[0].root_doc_id, root.to_string());
        assert!(authz.opens(&alice, &root));
        assert!(!authz.opens(&did("bob"), &note_id));
        eventually("the index is rebuilt from storage", || {
            authz.vault_of(&note_id) == Some(root.clone())
        })
        .await;
    }
}
