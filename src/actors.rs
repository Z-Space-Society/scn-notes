//! Who made each change.
//!
//! An Automerge change names its author only by an actor ID: 16 random bytes
//! the client picks. The JS client picks a new one each time it opens a note,
//! so one actor is one note on one device for one session, and nothing in it
//! says whose it is. The relay is the one place that can say: it knows which
//! member is on each connection, and a new change first reaches the relay on
//! its author's.
//!
//! `actor_members` records that, one row per actor, the first member seen
//! keeping it. The `source` column says how each row was learned:
//!
//! - `sync`: the actor's first new change arrived on that member's connection.
//! - `mcp`: the actor the relay writes under for that member's MCP edits.
//! - `creator`, `private`: the one-off backfill of history stored before the
//!   map existed, from a document's creator and from private workspaces.
//!
//! The table is loaded into memory at startup and written through, like
//! `doc_creators`, so a frame whose actors are already known costs no query.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use automerge::sync::{Message, MessageVersion};
use automerge::{ActorId, Automerge, Change, ChangeHash, ReadDoc};
use samod::DocumentId;
use sqlx::Row;

use crate::auth::{Caller, Did};
use crate::authz::{Authz, Holder};

pub(crate) const SYNC: &str = "sync";
pub(crate) const MCP: &str = "mcp";
pub(crate) const CREATOR: &str = "creator";
pub(crate) const PRIVATE: &str = "private";

/// The `relay_jobs` row that marks the backfill done.
const BACKFILL: &str = "actor-backfill";

/// How often the backfill looks again for the index to finish its first walk.
const WALK_POLL: Duration = Duration::from_secs(1);

/// Rows per insert when the backfill writes its findings.
const BATCH: usize = 1000;

/// The actor maps held in memory.
#[derive(Default)]
pub(crate) struct Actors {
    owners: HashMap<ActorId, Did>,
    /// Each member's MCP actor.
    mcp: HashMap<Did, ActorId>,
}

/// What to do with a frame, given who made the changes in it.
#[derive(Debug, PartialEq)]
pub enum Verdict {
    Pass,
    /// A change the relay does not hold, under an actor another member owns.
    Forged,
    /// Its sync message does not decode.
    Unreadable,
}

/// What the backfill mapped, by source, and how many actors it left alone
/// because two members had a claim on them.
#[derive(Debug, Default, PartialEq)]
pub struct Backfilled {
    pub creator: usize,
    pub private: usize,
    pub conflicts: usize,
}

/// The changes a sync message carries, as hash and actor.
///
/// A V1 message carries changes one by one. A V2 message carries a whole saved
/// document: everything the sender holds, not just what the relay lacks.
pub(crate) fn changes_in(message: &[u8]) -> Result<Vec<(ChangeHash, ActorId)>> {
    let message = Message::decode(message).map_err(|e| anyhow!("{e}"))?;
    match message.version {
        MessageVersion::V1 => message
            .changes
            .iter()
            .map(|bytes| {
                let change = Change::from_bytes(bytes.to_vec()).map_err(|e| anyhow!("{e}"))?;
                Ok((change.hash(), change.actor_id().clone()))
            })
            .collect(),
        MessageVersion::V2 => {
            let mut doc = Automerge::new();
            for chunk in message.changes.iter() {
                doc.load_incremental(chunk)?;
            }
            Ok(doc
                .get_changes(&[])
                .iter()
                .map(|change| (change.hash(), change.actor_id().clone()))
                .collect())
        }
    }
}

impl Authz {
    /// The member an actor belongs to, if the relay knows.
    pub fn actor_owner(&self, actor: &ActorId) -> Option<Did> {
        self.0.actors.read().unwrap().owners.get(actor).cloned()
    }

    /// Read the actor maps from the table.
    pub(crate) async fn load_actors(pool: &sqlx::PgPool) -> Result<Actors> {
        let mut actors = Actors::default();
        for row in sqlx::query("SELECT actor_id, did, source FROM actor_members")
            .fetch_all(pool)
            .await?
        {
            let raw: String = row.try_get("actor_id")?;
            let Ok(actor) = ActorId::from_str(&raw) else {
                tracing::warn!(actor = %raw, "skipping an unparseable actor ID");
                continue;
            };
            let did = Did(row.try_get("did")?);
            if row.try_get::<String, _>("source")? == MCP {
                actors.mcp.insert(did.clone(), actor.clone());
            }
            actors.owners.insert(actor, did);
        }
        Ok(actors)
    }

    /// Record who made the changes in a `sync` or `request` frame's message,
    /// and say whether the frame may go on.
    ///
    /// Only changes the relay does not hold yet count. A client re-sends what
    /// it already got, and a V2 message carries every change in the document,
    /// so a held change says nothing about who is sending it now.
    pub async fn record_actors(
        &self,
        doc: &DocumentId,
        caller: &Caller,
        message: &[u8],
    ) -> Result<Verdict> {
        let Ok(changes) = changes_in(message) else {
            return Ok(Verdict::Unreadable);
        };

        // The caller's own known actors need nothing more. That is nearly
        // every frame, and it never reaches the database.
        let unsettled: Vec<(ChangeHash, ActorId)> = {
            let actors = self.0.actors.read().unwrap();
            changes
                .into_iter()
                .filter(|(_, actor)| actors.owners.get(actor) != Some(&caller.did))
                .collect()
        };
        if unsettled.is_empty() {
            return Ok(Verdict::Pass);
        }

        let held = self
            .held(doc, unsettled.iter().map(|(hash, _)| *hash).collect())
            .await?;
        let mut new = HashSet::new();
        for (hash, actor) in &unsettled {
            if held.contains(hash) {
                continue;
            }
            match self.actor_owner(actor) {
                None => {
                    new.insert(actor.clone());
                }
                Some(owner) if owner == caller.did => {}
                Some(_) => return Ok(Verdict::Forged),
            }
        }
        for actor in new {
            // Two members racing on one new actor: the first insert wins and
            // the other is refused as if it had come second.
            if self.map_actor(&actor, &caller.did, SYNC).await? != caller.did {
                return Ok(Verdict::Forged);
            }
        }
        Ok(Verdict::Pass)
    }

    /// The actor the relay writes under for this member's MCP edits, made the
    /// first time they edit.
    pub async fn mcp_actor(&self, did: &Did) -> Result<ActorId> {
        if let Some(actor) = self.0.actors.read().unwrap().mcp.get(did) {
            return Ok(actor.clone());
        }
        sqlx::query(
            "INSERT INTO actor_members (actor_id, did, source) VALUES ($1, $2, $3)
             ON CONFLICT DO NOTHING",
        )
        .bind(ActorId::random().to_hex_string())
        .bind(&did.0)
        .bind(MCP)
        .execute(&self.0.pool)
        .await?;
        let raw: String =
            sqlx::query_scalar("SELECT actor_id FROM actor_members WHERE did = $1 AND source = $2")
                .bind(&did.0)
                .bind(MCP)
                .fetch_one(&self.0.pool)
                .await?;
        let actor = ActorId::from_str(&raw).map_err(|e| anyhow!("{e}"))?;

        let mut actors = self.0.actors.write().unwrap();
        actors.mcp.insert(did.clone(), actor.clone());
        actors.owners.insert(actor.clone(), did.clone());
        Ok(actor)
    }

    /// Give an actor to a member unless someone already has it, and return
    /// whoever has it now.
    async fn map_actor(&self, actor: &ActorId, did: &Did, source: &str) -> Result<Did> {
        let hex = actor.to_hex_string();
        sqlx::query(
            "INSERT INTO actor_members (actor_id, did, source) VALUES ($1, $2, $3)
             ON CONFLICT (actor_id) DO NOTHING",
        )
        .bind(&hex)
        .bind(&did.0)
        .bind(source)
        .execute(&self.0.pool)
        .await?;
        let owner = Did(
            sqlx::query_scalar("SELECT did FROM actor_members WHERE actor_id = $1")
                .bind(&hex)
                .fetch_one(&self.0.pool)
                .await?,
        );
        self.0
            .actors
            .write()
            .unwrap()
            .owners
            .insert(actor.clone(), owner.clone());
        Ok(owner)
    }

    /// Which of these changes the relay already holds for the document.
    ///
    /// A document with nothing in storage holds nothing, and is not looked
    /// for any further: asking samod for it would send a request to the very
    /// peer that is sending it.
    async fn held(&self, doc: &DocumentId, hashes: Vec<ChangeHash>) -> Result<HashSet<ChangeHash>> {
        if !self.stored(doc).await? {
            return Ok(HashSet::new());
        }
        let Some(handle) = self.open(doc).await else {
            return Ok(HashSet::new());
        };
        handle
            .with_document_async(move |doc| {
                hashes
                    .into_iter()
                    .filter(|hash| doc.get_change_by_hash(hash).is_some())
                    .collect()
            })
            .await
            .map_err(|_| anyhow!("repo stopped"))
    }

    /// Does storage hold anything for this document? The same index range
    /// as [`Authz::bytes_of`].
    async fn stored(&self, doc: &DocumentId) -> Result<bool> {
        Ok(sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM storage
                            WHERE key ~>=~ ($1 || '/') AND key ~<~ ($1 || '0'))",
        )
        .bind(doc.to_string())
        .fetch_one(&self.0.pool)
        .await?)
    }

    /// A document as storage holds it, read without samod, so the backfill
    /// does not leave every document loaded in the repo.
    async fn stored_doc(&self, doc: &DocumentId) -> Result<Option<Automerge>> {
        let chunks: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT value FROM storage WHERE key ~>=~ ($1 || '/') AND key ~<~ ($1 || '0')",
        )
        .bind(doc.to_string())
        .fetch_all(&self.0.pool)
        .await?;
        if chunks.is_empty() {
            return Ok(None);
        }
        let mut loaded = Automerge::new();
        for chunk in &chunks {
            loaded.load_incremental(chunk)?;
        }
        Ok(Some(loaded))
    }

    /// Run the backfill in the background, once the index has walked every
    /// workspace. Started by the service, not by the `file-unfiled` command.
    pub fn start_actor_backfill(&self) {
        let authz = self.clone();
        tokio::spawn(async move {
            while !authz.0.reach.read().unwrap().all_walked() {
                tokio::time::sleep(WALK_POLL).await;
            }
            if let Err(e) = authz.backfill_actors().await {
                tracing::error!(error = %e, "actor-backfill failed; it runs again at the next start");
            }
        });
    }

    /// Map the actors in history stored before the map existed. Runs once:
    /// `None` when it already has.
    ///
    /// Two rules, the first taking precedence, and neither ever replacing a
    /// mapping already made:
    ///
    /// 1. **Creator.** A document's first change (no dependencies) was made by
    ///    whoever sent it first, its `doc_creators` member.
    /// 2. **Private.** Every other actor in a private workspace's document is its
    ///    owner's, since nobody else can open it. A note moved in from a
    ///    group can carry another member's old edits; this rule would give
    ///    those to the owner, which the README states.
    ///
    /// An actor one rule would give to two members is left unmapped.
    pub(crate) async fn backfill_actors(&self) -> Result<Option<Backfilled>> {
        let done: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM relay_jobs WHERE name = $1)")
                .bind(BACKFILL)
                .fetch_one(&self.0.pool)
                .await?;
        if done {
            return Ok(None);
        }

        let docs: Vec<(DocumentId, Did)> = self
            .0
            .creators
            .read()
            .unwrap()
            .iter()
            .map(|(doc, creator)| (doc.clone(), creator.did.clone()))
            .collect();

        let mut by_creator = Claims::default();
        let mut by_owner = Claims::default();
        for (doc, creator) in docs {
            let loaded = match self.stored_doc(&doc).await {
                Ok(Some(loaded)) => loaded,
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!(%doc, error = %e, "actor-backfill skipping a document that will not load");
                    continue;
                }
            };
            let owner = match self.holder_of(&doc) {
                Some(Holder::Member(owner)) => Some(owner),
                _ => None,
            };
            for change in loaded.get_changes(&[]) {
                if change.deps().is_empty() {
                    by_creator.claim(change.actor_id(), &creator);
                } else if let Some(owner) = &owner {
                    by_owner.claim(change.actor_id(), owner);
                }
            }
        }

        let conflicts = by_creator.conflicts + by_owner.conflicts;
        let creator_rows = by_creator.settled();
        let claimed: HashSet<&ActorId> = creator_rows.iter().map(|(actor, _)| actor).collect();
        let owner_rows: Vec<(ActorId, Did)> = by_owner
            .settled()
            .into_iter()
            .filter(|(actor, _)| !claimed.contains(actor))
            .collect();

        let result = Backfilled {
            creator: self.map_actors(&creator_rows, CREATOR).await?,
            private: self.map_actors(&owner_rows, PRIVATE).await?,
            conflicts,
        };
        sqlx::query("INSERT INTO relay_jobs (name) VALUES ($1) ON CONFLICT DO NOTHING")
            .bind(BACKFILL)
            .execute(&self.0.pool)
            .await?;
        tracing::info!(
            creator = result.creator,
            private = result.private,
            conflicts = result.conflicts,
            "actor-backfill done"
        );
        Ok(Some(result))
    }

    /// Insert mappings that no row has yet, and return how many went in.
    async fn map_actors(&self, rows: &[(ActorId, Did)], source: &str) -> Result<usize> {
        let mut inserted = 0;
        for batch in rows.chunks(BATCH) {
            let actors: Vec<String> = batch.iter().map(|(a, _)| a.to_hex_string()).collect();
            let dids: Vec<String> = batch.iter().map(|(_, d)| d.0.clone()).collect();
            let written = sqlx::query(
                "INSERT INTO actor_members (actor_id, did, source)
                 SELECT a, d, $3 FROM unnest($1::TEXT[], $2::TEXT[]) AS t(a, d)
                 ON CONFLICT (actor_id) DO NOTHING
                 RETURNING actor_id, did",
            )
            .bind(&actors)
            .bind(&dids)
            .bind(source)
            .fetch_all(&self.0.pool)
            .await?;
            let mut map = self.0.actors.write().unwrap();
            for row in &written {
                let raw: String = row.try_get("actor_id")?;
                if let Ok(actor) = ActorId::from_str(&raw) {
                    map.owners.insert(actor, Did(row.try_get("did")?));
                }
            }
            inserted += written.len();
        }
        Ok(inserted)
    }
}

/// Run `write` on the document as `actor`, and put its own actor back after.
pub(crate) fn as_actor<R>(
    doc: &mut Automerge,
    actor: ActorId,
    write: impl FnOnce(&mut Automerge) -> R,
) -> R {
    let own = doc.get_actor().clone();
    doc.set_actor(actor);
    let result = write(doc);
    doc.set_actor(own);
    result
}

/// One backfill rule's findings: who each actor belongs to, or `None` where
/// the rule found two members.
#[derive(Default)]
struct Claims {
    actors: HashMap<ActorId, Option<Did>>,
    conflicts: usize,
}

impl Claims {
    fn claim(&mut self, actor: &ActorId, did: &Did) {
        match self.actors.get_mut(actor) {
            None => {
                self.actors.insert(actor.clone(), Some(did.clone()));
            }
            Some(Some(existing)) if existing != did => {
                tracing::warn!(%actor, "actor-backfill found two members for one actor; leaving it unmapped");
                self.actors.insert(actor.clone(), None);
                self.conflicts += 1;
            }
            Some(_) => {}
        }
    }

    fn settled(self) -> Vec<(ActorId, Did)> {
        self.actors
            .into_iter()
            .filter_map(|(actor, did)| did.map(|did| (actor, did)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use automerge::sync::ChunkList;
    use automerge::transaction::Transactable;
    use automerge::ROOT;
    use samod::{DocHandle, Repo};
    use sqlx::PgPool;

    use crate::authz::tests::{did, eventually, group_workspace, link, member_of, open, workspace};
    use crate::filter::{Filter, Inbound};
    use crate::mcp::notes::Notes;
    use crate::wire::tests::frame_with;

    /// A V1 sync message carrying these changes.
    fn carrying(changes: &[Change]) -> Vec<u8> {
        Message {
            heads: vec![],
            need: vec![],
            have: vec![],
            changes: changes
                .iter()
                .map(|change| change.raw_bytes().to_vec())
                .collect::<Vec<_>>()
                .into(),
            flags: None,
            version: MessageVersion::V1,
        }
        .encode()
    }

    /// A V2 sync message carrying the whole document.
    fn whole(doc: &Automerge) -> Vec<u8> {
        Message {
            heads: vec![],
            need: vec![],
            have: vec![],
            changes: ChunkList::from(doc.save()),
            flags: None,
            version: MessageVersion::V2,
        }
        .encode()
    }

    /// One change to the document, made as its current actor.
    fn edit(doc: &mut Automerge, key: &str) -> Change {
        let before = doc.get_heads();
        let mut tx = doc.transaction();
        tx.put(ROOT, key, 1).unwrap();
        tx.commit();
        doc.get_changes(&before).pop().unwrap()
    }

    /// A client's copy of what the relay holds, writing as `actor`.
    async fn client_copy(handle: &DocHandle, actor: &ActorId) -> Automerge {
        let saved = handle.with_document(|doc| doc.save());
        Automerge::load(&saved).unwrap().with_actor(actor.clone())
    }

    /// What the relay does with a change once the filter lets it through.
    async fn apply(handle: &DocHandle, change: Change) {
        handle
            .with_document_async(move |doc| doc.apply_changes([change]).unwrap())
            .await
            .unwrap();
    }

    /// Wait for storage to hold the document, as it does once samod has
    /// written it.
    async fn until_stored(authz: &Authz, doc: &DocumentId, changes: usize) {
        for _ in 0..200 {
            if let Ok(Some(stored)) = authz.stored_doc(doc).await {
                if stored.get_changes(&[]).len() >= changes {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("timed out waiting for {doc} to be stored");
    }

    async fn rows(pool: &PgPool) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM actor_members")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// A note in group 7's workspace, made by Alice, that Alice and Bob may
    /// both open and the relay has stored.
    async fn shared_note(authz: &Authz, repo: &Repo) -> DocHandle {
        let (root, root_doc) = group_workspace(authz, repo, "7").await;
        let mut first = Automerge::new();
        edit(&mut first, "title");
        let handle = repo.create(first).await.unwrap();
        authz
            .record_creator(handle.document_id(), &member_of("alice", &["7"]))
            .await
            .unwrap();
        link(&root_doc, "plan.md", "md", handle.document_id()).await;
        eventually("the note is in the group's workspace", || {
            authz.workspace_of(handle.document_id()) == Some(root.clone())
        })
        .await;
        until_stored(authz, handle.document_id(), 1).await;
        handle
    }

    #[sqlx::test(migrations = false)]
    async fn a_new_change_maps_its_actor_to_the_member_who_sent_it(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let note = shared_note(&authz, &repo).await;
        let doc = note.document_id().clone();
        let alice = Filter::new(authz.clone(), member_of("alice", &["7"]));
        let laptop = ActorId::random();
        let mut copy = client_copy(&note, &laptop).await;

        let change = edit(&mut copy, "a");
        let sent = frame_with("sync", Some(&doc), &carrying(&[change]));
        assert_eq!(alice.inbound(&sent).await, Inbound::Pass);
        assert_eq!(authz.actor_owner(&laptop), Some(did("alice")));
        let before = rows(&pool).await;

        // More from the same actor costs nothing more.
        let change = edit(&mut copy, "b");
        let sent = frame_with("sync", Some(&doc), &carrying(&[change]));
        assert_eq!(alice.inbound(&sent).await, Inbound::Pass);
        assert_eq!(rows(&pool).await, before);

        // And it survives a restart.
        repo.stop().await;
        let (authz, _repo) = open(&pool).await;
        assert_eq!(authz.actor_owner(&laptop), Some(did("alice")));
    }

    #[sqlx::test(migrations = false)]
    async fn a_new_change_under_another_members_actor_is_dropped(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let note = shared_note(&authz, &repo).await;
        let doc = note.document_id().clone();
        let alice = Filter::new(authz.clone(), member_of("alice", &["7"]));
        let bob = Filter::new(authz.clone(), member_of("bob", &["7"]));
        let laptop = ActorId::random();

        let mut hers = client_copy(&note, &laptop).await;
        let change = edit(&mut hers, "a");
        let sent = frame_with("sync", Some(&doc), &carrying(&[change]));
        assert_eq!(alice.inbound(&sent).await, Inbound::Pass);

        let mut forged = client_copy(&note, &laptop).await;
        let change = edit(&mut forged, "b");
        let sent = frame_with("sync", Some(&doc), &carrying(&[change]));
        assert_eq!(bob.inbound(&sent).await, Inbound::Drop);
        assert_eq!(authz.actor_owner(&laptop), Some(did("alice")));
    }

    #[sqlx::test(migrations = false)]
    async fn a_change_the_relay_holds_passes_whoever_resends_it(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let note = shared_note(&authz, &repo).await;
        let doc = note.document_id().clone();
        let alice = Filter::new(authz.clone(), member_of("alice", &["7"]));
        let bob = Filter::new(authz.clone(), member_of("bob", &["7"]));
        let laptop = ActorId::random();

        let mut hers = client_copy(&note, &laptop).await;
        let change = edit(&mut hers, "a");
        let sent = frame_with("sync", Some(&doc), &carrying(std::slice::from_ref(&change)));
        assert_eq!(alice.inbound(&sent).await, Inbound::Pass);
        apply(&note, change.clone()).await;
        until_stored(&authz, &doc, 2).await;

        let resent = frame_with("sync", Some(&doc), &carrying(&[change]));
        assert_eq!(bob.inbound(&resent).await, Inbound::Pass);
        assert_eq!(authz.actor_owner(&laptop), Some(did("alice")));
    }

    #[sqlx::test(migrations = false)]
    async fn a_whole_document_maps_only_the_changes_the_relay_lacks(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let note = shared_note(&authz, &repo).await;
        let doc = note.document_id().clone();
        let first_actor = note.with_document(|doc| doc.get_changes(&[])[0].actor_id().clone());
        let bob = Filter::new(authz.clone(), member_of("bob", &["7"]));
        let phone = ActorId::random();

        // Bob's copy holds the note's history, which the relay has, plus his
        // own new change, sent the way a large catch-up is: as a V2 message
        // with the whole document.
        let mut his = client_copy(&note, &phone).await;
        edit(&mut his, "b");
        let sent = frame_with("sync", Some(&doc), &whole(&his));
        assert_eq!(bob.inbound(&sent).await, Inbound::Pass);

        assert_eq!(authz.actor_owner(&phone), Some(did("bob")));
        assert_eq!(authz.actor_owner(&first_actor), None);
    }

    #[sqlx::test(migrations = false)]
    async fn a_frame_whose_message_does_not_decode_is_dropped(pool: PgPool) {
        let (authz, _repo) = open(&pool).await;
        let alice = Filter::new(authz.clone(), member_of("alice", &[]));
        let doc = crate::wire::tests::doc_id(9);
        let sent = frame_with("sync", Some(&doc), &[1, 2, 3]);
        assert_eq!(alice.inbound(&sent).await, Inbound::Drop);
    }

    #[sqlx::test(migrations = false)]
    async fn mcp_edits_are_written_as_the_member_who_made_them(pool: PgPool) {
        let (authz, _repo) = open(&pool).await;
        let caller = Caller::from(did("alice"));
        let notes = Notes {
            authz: &authz,
            caller: &caller,
        };
        let root = notes.locate("Private").await.unwrap().root;
        notes.create(&root, "Plans/a.md", "one").await.unwrap();
        notes
            .edit(&root, "Plans/a.md", "one".into(), "two".into(), false)
            .await
            .unwrap();
        notes
            .append(&root, "Plans/a.md", "three".into())
            .await
            .unwrap();

        let (_, id) = crate::mcp::tests::notes_of(&authz, &did("alice"))
            .await
            .into_iter()
            .find(|(path, _)| path == "Plans/a.md")
            .unwrap();
        let handle = authz.open(&id).await.unwrap();
        let actors: HashSet<ActorId> = handle.with_document(|doc| {
            doc.get_changes(&[])
                .iter()
                .map(|change| change.actor_id().clone())
                .collect()
        });
        assert_eq!(actors.len(), 1);
        for actor in &actors {
            assert_eq!(authz.actor_owner(actor), Some(did("alice")));
        }

        let bobs = authz.mcp_actor(&did("bob")).await.unwrap();
        assert!(!actors.contains(&bobs));
        assert_eq!(authz.actor_owner(&bobs), Some(did("bob")));
    }

    #[sqlx::test(migrations = false)]
    async fn the_backfill_maps_creators_and_private_workspaces_once(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let (root, root_doc) = workspace(&authz, &repo, &did("alice")).await;
        let (made, later, mapped) = (ActorId::random(), ActorId::random(), ActorId::random());

        // A note Alice made, edited in two later sessions, one of which the
        // relay already saw live as Carol's.
        let mut first = Automerge::new().with_actor(made.clone());
        edit(&mut first, "title");
        let handle = repo.create(first).await.unwrap();
        authz
            .record_creator(handle.document_id(), &did("alice").into())
            .await
            .unwrap();
        for actor in [&later, &mapped] {
            let mut session = client_copy(&handle, actor).await;
            // A key of its own: putting a value a key already has is no change.
            apply(&handle, edit(&mut session, &actor.to_hex_string())).await;
        }
        authz.map_actor(&mapped, &did("carol"), SYNC).await.unwrap();
        link(&root_doc, "a.md", "md", handle.document_id()).await;
        eventually("the note is in the workspace", || {
            authz.workspace_of(handle.document_id()) == Some(root.clone())
        })
        .await;
        until_stored(&authz, handle.document_id(), 3).await;

        let done = authz.backfill_actors().await.unwrap().unwrap();
        assert_eq!(authz.actor_owner(&made), Some(did("alice")));
        assert_eq!(authz.actor_owner(&later), Some(did("alice")));
        assert_eq!(authz.actor_owner(&mapped), Some(did("carol")));
        assert_eq!(done.conflicts, 0);

        assert_eq!(authz.backfill_actors().await.unwrap(), None);
    }
}
