//! `scn-notes file-unfiled`: a member's documents that no workspace reaches,
//! listed, and on request linked back into their private workspace.
//!
//! A document drops out of every workspace when its last entry goes: a note or
//! folder deleted in Obsidian, or a move cut off part way. It stays on the
//! relay, open only to its creator. This command shows what those are and can
//! put them in a new folder, where the member sees them on every device.
//!
//! It is run by hand with the service stopped, so nothing else is writing the
//! workspace's root folder while it does.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use anyhow::Result;
use automerge::{Automerge, ObjType, ReadDoc, ROOT};
use chrono::{DateTime, Utc};
use samod::{AutomergeUrl, DocumentId};
use sqlx::Row;
use unicode_normalization::UnicodeNormalization;

use crate::auth::{Caller, Did};
use crate::authz::Authz;
use crate::reach::{self, Entry, FOLDER, NOTE};

/// What kind of document an orphan is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Folder,
    Note,
    /// Neither: another file type, or a document with no recognisable shape.
    /// Listed, never linked.
    Other,
}

/// One of a member's documents no workspace reaches, at the top: not linked from
/// another of their orphaned folders.
#[derive(Clone, Debug)]
pub struct Orphan {
    pub id: DocumentId,
    pub kind: Kind,
    /// A note's own name, a folder's title.
    pub name: Option<String>,
    /// A note's first line that has text on it.
    pub first_line: Option<String>,
    /// For a folder, how many of the member's orphans it holds, at any depth.
    pub inside: usize,
    /// This document and every one of the member's orphans it holds.
    pub docs: Vec<DocumentId>,
    /// Bytes in storage, a folder's with everything it holds.
    pub bytes: i64,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug)]
pub enum FileError {
    /// The workspace's root already has an entry with the folder's name.
    FolderTaken,
    Internal(anyhow::Error),
}

impl<E: Into<anyhow::Error>> From<E> for FileError {
    fn from(e: E) -> Self {
        FileError::Internal(e.into())
    }
}

impl std::fmt::Display for FileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileError::FolderTaken => {
                write!(f, "the workspace already has an entry with that name")
            }
            FileError::Internal(e) => write!(f, "{e:#}"),
        }
    }
}

/// What a document says about itself.
struct Shape {
    kind: Kind,
    name: Option<String>,
    first_line: Option<String>,
    children: Vec<DocumentId>,
}

fn shape_of(doc: &Automerge) -> Shape {
    let patchwork = match doc.get(ROOT, "@patchwork") {
        Ok(Some((automerge::Value::Object(ObjType::Map), id))) => {
            reach::read_string(doc, &id, "type")
        }
        _ => None,
    };
    match patchwork.as_deref() {
        Some(FOLDER) => Shape {
            kind: Kind::Folder,
            name: reach::read_string(doc, &ROOT, "title"),
            first_line: None,
            children: reach::read_entries(doc)
                .iter()
                .filter_map(Entry::doc_id)
                .collect(),
        },
        Some("file") if reach::read_string(doc, &ROOT, "extension").as_deref() == Some(NOTE) => {
            Shape {
                kind: Kind::Note,
                name: reach::read_string(doc, &ROOT, "name"),
                first_line: reach::read_string(doc, &ROOT, "content").and_then(|text| {
                    text.lines()
                        .map(str::trim)
                        .find(|line| !line.is_empty())
                        .map(|line| line.chars().take(80).collect())
                }),
                children: Vec::new(),
            }
        }
        _ => Shape {
            kind: Kind::Other,
            name: reach::read_string(doc, &ROOT, "name"),
            first_line: None,
            children: Vec::new(),
        },
    }
}

/// How two names are compared, as everywhere else: NFC and case folded.
fn key(name: &str) -> String {
    name.nfc().collect::<String>().to_lowercase()
}

/// A name a folder entry can carry (D5): one segment, not hidden.
fn usable(name: &str) -> String {
    let name = name.replace('/', "-");
    let name = name.trim().trim_start_matches('.').trim();
    match name {
        "" | "." | ".." => String::new(),
        name => name.nfc().collect(),
    }
}

/// The name a colliding entry gets: the plugin's `conflictName`, so devices
/// see a name they could have made themselves.
fn conflict_name(name: &str, kind: &str, url: &str) -> String {
    let id: String = url
        .trim_start_matches("automerge:")
        .chars()
        .take(6)
        .collect();
    let dot = if kind == FOLDER {
        None
    } else {
        name.rfind('.')
    };
    match dot {
        Some(dot) if dot > 0 => format!("{} (conflict {id}){}", &name[..dot], &name[dot..]),
        _ => format!("{name} (conflict {id})"),
    }
}

/// The entry an orphan is linked under, before collisions. None for one that
/// is not linked.
fn entry_name(orphan: &Orphan) -> Option<(String, &'static str)> {
    let short: String = orphan.id.to_string().chars().take(6).collect();
    let name = orphan.name.as_deref().map(usable).unwrap_or_default();
    match orphan.kind {
        Kind::Folder if name.is_empty() => Some((format!("Untitled {short}"), FOLDER)),
        Kind::Folder => Some((name, FOLDER)),
        Kind::Note if name.is_empty() => Some((format!("Untitled {short}.md"), NOTE)),
        Kind::Note if key(&name).ends_with(".md") => Some((name, NOTE)),
        Kind::Note => Some((format!("{name}.md"), NOTE)),
        Kind::Other => None,
    }
}

impl Authz {
    /// The member's documents no workspace reaches, top-level only, oldest first.
    /// `None` until every workspace has been walked.
    pub async fn orphans_of(&self, did: &Did) -> Result<Option<Vec<Orphan>>> {
        let ids: Vec<DocumentId> = {
            let reach = self.0.reach.read().unwrap();
            if !reach.all_walked() {
                return Ok(None);
            }
            let creators = self.0.creators.read().unwrap();
            creators
                .iter()
                .filter(|(doc, creator)| creator.did == *did && reach.workspace_of(doc).is_none())
                .map(|(doc, _)| doc.clone())
                .collect()
        };
        let set: HashSet<&DocumentId> = ids.iter().collect();

        let mut shapes: HashMap<DocumentId, Shape> = HashMap::new();
        for id in &ids {
            let shape = match self.open(id).await {
                Some(handle) => handle.with_document(|doc| shape_of(doc)),
                None => Shape {
                    kind: Kind::Other,
                    name: None,
                    first_line: None,
                    children: Vec::new(),
                },
            };
            shapes.insert(id.clone(), shape);
        }

        // Linked from another orphaned folder: it comes back with that one.
        let held: HashSet<&DocumentId> = shapes
            .iter()
            .flat_map(|(parent, shape)| shape.children.iter().filter(move |c| *c != parent))
            .filter(|child| set.contains(child))
            .collect();

        let created: HashMap<String, DateTime<Utc>> =
            sqlx::query("SELECT doc_id, created_at FROM doc_creators WHERE doc_id = ANY($1)")
                .bind(ids.iter().map(ToString::to_string).collect::<Vec<_>>())
                .fetch_all(&self.0.pool)
                .await?
                .iter()
                .map(|row| Ok((row.try_get("doc_id")?, row.try_get("created_at")?)))
                .collect::<Result<_, sqlx::Error>>()?;

        let mut orphans = Vec::new();
        for id in ids.iter().filter(|id| !held.contains(id)) {
            // Everything of the member's this one holds, at any depth.
            let mut subtree = vec![id.clone()];
            let mut seen: HashSet<DocumentId> = HashSet::from([id.clone()]);
            let mut i = 0;
            while i < subtree.len() {
                for child in &shapes[&subtree[i]].children {
                    if set.contains(child) && seen.insert(child.clone()) {
                        subtree.push(child.clone());
                    }
                }
                i += 1;
            }
            let shape = &shapes[id];
            let docs: Vec<String> = subtree.iter().map(ToString::to_string).collect();
            orphans.push(Orphan {
                id: id.clone(),
                kind: shape.kind,
                name: shape.name.clone(),
                first_line: shape.first_line.clone(),
                inside: subtree.len() - 1,
                docs: subtree.clone(),
                bytes: self.bytes_of(&docs).await?,
                created_at: created.get(&id.to_string()).copied(),
            });
        }
        orphans.sort_by(|a, b| {
            (a.created_at, a.id.to_string()).cmp(&(b.created_at, b.id.to_string()))
        });
        Ok(Some(orphans))
    }

    /// Put these orphans in a new folder at the root of the member's private
    /// workspace. Returns each linked document with the name it was given.
    /// Orphans of no linkable kind are left where they are.
    pub async fn file_orphans(
        &self,
        did: &Did,
        folder: &str,
        orphans: &[Orphan],
    ) -> Result<Vec<(DocumentId, String)>, FileError> {
        let folder = usable(folder);
        if folder.is_empty() {
            return Err(FileError::FolderTaken);
        }
        let workspace = self
            .private_workspace(did)
            .await
            .map_err(|e| anyhow::anyhow!("finding the private workspace failed: {e:?}"))?;
        let root = DocumentId::from_str(&workspace.root_doc_id)
            .map_err(|e| anyhow::anyhow!("unparseable workspace root: {e:?}"))?;
        let root = self
            .open(&root)
            .await
            .ok_or_else(|| anyhow::anyhow!("the workspace's root folder did not load"))?;
        let taken = root.with_document(|doc| {
            reach::read_entries(doc)
                .iter()
                .any(|entry| key(&entry.name) == key(&folder))
        });
        if taken {
            return Err(FileError::FolderTaken);
        }

        // The folder is built whole, then linked: the root changes once.
        let mut doc = reach::new_folder(&folder)?;
        let mut used: HashSet<String> = HashSet::new();
        let mut linked = Vec::new();
        for orphan in orphans {
            let Some((name, kind)) = entry_name(orphan) else {
                continue;
            };
            let url = AutomergeUrl::from(&orphan.id).to_string();
            let name = if used.contains(&key(&name)) {
                conflict_name(&name, kind, &url)
            } else {
                name
            };
            used.insert(key(&name));
            reach::add_entry(
                &mut doc,
                &Entry {
                    name: name.clone(),
                    kind: kind.to_string(),
                    url,
                },
            )?;
            linked.push((orphan.id.clone(), name));
        }

        let handle = self
            .0
            .repo
            .create(doc)
            .await
            .map_err(|_| anyhow::anyhow!("repo stopped"))?;
        let caller: Caller = did.clone().into();
        self.record_creator(handle.document_id(), &caller).await?;
        let entry = Entry {
            name: folder,
            kind: FOLDER.to_string(),
            url: AutomergeUrl::from(handle.document_id()).to_string(),
        };
        root.with_document_async(move |doc| reach::add_entry(doc, &entry))
            .await
            .map_err(|_| anyhow::anyhow!("repo stopped"))??;
        Ok(linked)
    }

    /// Delete these orphans and everything they hold: their stored history
    /// and their creator rows. Returns how many documents went.
    ///
    /// Each one is checked again first: still the member's, and still in no
    /// workspace. One that fails either check stops the whole delete, and nothing
    /// is removed. The caller stops the repo before this, so nothing it has
    /// loaded is written back afterwards.
    pub async fn delete_orphans(&self, did: &Did, orphans: &[Orphan]) -> Result<usize> {
        let docs: Vec<&DocumentId> = orphans.iter().flat_map(|o| o.docs.iter()).collect();
        {
            let reach = self.0.reach.read().unwrap();
            let creators = self.0.creators.read().unwrap();
            for doc in &docs {
                anyhow::ensure!(
                    creators.get(*doc).map(|c| &c.did) == Some(did),
                    "{doc} is not the member's; nothing deleted"
                );
                anyhow::ensure!(
                    reach.workspace_of(doc).is_none(),
                    "{doc} is in a workspace; nothing deleted"
                );
            }
        }
        let ids: Vec<String> = docs.iter().map(ToString::to_string).collect();
        let mut tx = self.0.pool.begin().await?;
        // The same per-document key range `bytes_of` sums.
        sqlx::query(
            "DELETE FROM storage s USING unnest($1::TEXT[]) AS d(id)
             WHERE s.key ~>=~ (d.id || '/') AND s.key ~<~ (d.id || '0')",
        )
        .bind(&ids)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM doc_creators WHERE doc_id = ANY($1)")
            .bind(&ids)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;

        let mut creators = self.0.creators.write().unwrap();
        for doc in &docs {
            creators.remove(*doc);
        }
        Ok(docs.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use sqlx::PgPool;

    use crate::authz::tests::{did, eventually, link, open, sent, unlink, workspace};
    use crate::mcp::notes::new_note;
    use crate::reach::new_folder;

    async fn walked(authz: &Authz) {
        eventually("every workspace is walked", || authz.all_walked()).await;
    }

    async fn orphans(authz: &Authz, who: &Did) -> Vec<Orphan> {
        for _ in 0..200 {
            if let Some(found) = authz.orphans_of(who).await.unwrap() {
                return found;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("never walked");
    }

    fn names(found: &[Orphan]) -> Vec<String> {
        let mut names: Vec<_> = found.iter().filter_map(|o| o.name.clone()).collect();
        names.sort();
        names
    }

    #[sqlx::test(migrations = false)]
    async fn a_deleted_note_is_listed_and_filed_back_into_the_workspace(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let alice = did("alice");
        let (root, root_doc) = workspace(&authz, &repo, &alice).await;
        let note = sent(
            &authz,
            &repo,
            &alice,
            new_note("plan.md", "\n# The plan\nmore").unwrap(),
        )
        .await;
        let id = note.document_id().clone();
        link(&root_doc, "plan.md", "md", &id).await;
        eventually("the note is in the workspace", || {
            authz.workspace_of(&id).is_some()
        })
        .await;
        unlink(&root_doc, 0).await;
        eventually("the note has left the workspace", || {
            authz.workspace_of(&id).is_none()
        })
        .await;
        walked(&authz).await;

        let found = orphans(&authz, &alice).await;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, Kind::Note);
        assert_eq!(found[0].name.as_deref(), Some("plan.md"));
        assert_eq!(found[0].first_line.as_deref(), Some("# The plan"));

        let linked = authz
            .file_orphans(&alice, "Recovered", &found)
            .await
            .unwrap();
        assert_eq!(linked, vec![(id.clone(), "plan.md".to_string())]);
        eventually("the note is back in the workspace", || {
            authz.workspace_of(&id) == Some(root.clone())
        })
        .await;
        assert!(orphans(&authz, &alice).await.is_empty());
    }

    #[sqlx::test(migrations = false)]
    async fn a_deleted_folder_comes_back_whole(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let alice = did("alice");
        let (root, root_doc) = workspace(&authz, &repo, &alice).await;
        let folder = sent(&authz, &repo, &alice, new_folder("Art Projects").unwrap()).await;
        let note = sent(&authz, &repo, &alice, new_note("kiln.md", "glaze").unwrap()).await;
        let note_id = note.document_id().clone();
        link(&folder, "kiln.md", "md", &note_id).await;
        link(&root_doc, "Art Projects", "folder", folder.document_id()).await;
        eventually("the note is in the workspace", || {
            authz.workspace_of(&note_id).is_some()
        })
        .await;
        unlink(&root_doc, 0).await;
        eventually("the note has left the workspace", || {
            authz.workspace_of(&note_id).is_none()
        })
        .await;
        walked(&authz).await;

        let found = orphans(&authz, &alice).await;
        assert_eq!(names(&found), vec!["Art Projects"]);
        assert_eq!(found[0].kind, Kind::Folder);
        assert_eq!(found[0].inside, 1);

        authz
            .file_orphans(&alice, "Recovered", &found)
            .await
            .unwrap();
        eventually("the folder's note is back in the workspace", || {
            authz.workspace_of(&note_id) == Some(root.clone())
        })
        .await;
    }

    #[sqlx::test(migrations = false)]
    async fn nothing_is_listed_before_every_workspace_is_walked(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let alice = did("alice");
        let (root, _) = workspace(&authz, &repo, &alice).await;
        sent(&authz, &repo, &alice, new_note("loose.md", "").unwrap()).await;
        walked(&authz).await;
        authz.0.reach.write().unwrap().forget_walk(&root);
        assert!(authz.orphans_of(&alice).await.unwrap().is_none());
    }

    #[sqlx::test(migrations = false)]
    async fn only_the_members_own_orphans_are_listed(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let (alice, bob) = (did("alice"), did("bob"));
        let (_, root_doc) = workspace(&authz, &repo, &alice).await;
        let filed = sent(&authz, &repo, &alice, new_note("kept.md", "").unwrap()).await;
        let filed_id = filed.document_id().clone();
        link(&root_doc, "kept.md", "md", &filed_id).await;
        sent(&authz, &repo, &bob, new_note("bobs.md", "").unwrap()).await;
        sent(&authz, &repo, &alice, new_note("loose.md", "").unwrap()).await;
        eventually("the kept note is in the workspace", || {
            authz.workspace_of(&filed_id).is_some()
        })
        .await;
        walked(&authz).await;

        assert_eq!(names(&orphans(&authz, &alice).await), vec!["loose.md"]);
    }

    #[sqlx::test(migrations = false)]
    async fn two_orphans_with_one_name_get_the_plugins_conflict_name(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let alice = did("alice");
        workspace(&authz, &repo, &alice).await;
        sent(&authz, &repo, &alice, new_note("a.md", "one").unwrap()).await;
        sent(&authz, &repo, &alice, new_note("A.md", "two").unwrap()).await;
        walked(&authz).await;

        let found = orphans(&authz, &alice).await;
        let linked = authz
            .file_orphans(&alice, "Recovered", &found)
            .await
            .unwrap();
        let mut given: Vec<String> = linked.iter().map(|(_, name)| name.clone()).collect();
        given.sort();
        // Whichever came first keeps its name; the other gets the conflict one.
        let (kept, renamed) = if given.contains(&"a.md".to_string()) {
            ("a.md", "A")
        } else {
            ("A.md", "a")
        };
        let (other, _) = linked.iter().find(|(_, name)| name != kept).unwrap();
        let short: String = other.to_string().chars().take(6).collect();
        let mut expected = vec![kept.to_string(), format!("{renamed} (conflict {short}).md")];
        expected.sort();
        assert_eq!(given, expected);
    }

    #[sqlx::test(migrations = false)]
    async fn nothing_is_written_when_the_folder_name_is_taken(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let alice = did("alice");
        let (_, root_doc) = workspace(&authz, &repo, &alice).await;
        sent(&authz, &repo, &alice, new_note("loose.md", "").unwrap()).await;
        let existing = sent(&authz, &repo, &alice, new_folder("Recovered").unwrap()).await;
        let existing = existing.document_id().clone();
        link(&root_doc, "recovered", "folder", &existing).await;
        eventually("the existing folder is in the workspace", || {
            authz.workspace_of(&existing).is_some()
        })
        .await;
        walked(&authz).await;
        let found = orphans(&authz, &alice).await;

        assert!(matches!(
            authz.file_orphans(&alice, "Recovered", &found).await,
            Err(FileError::FolderTaken)
        ));
        walked(&authz).await;
        assert_eq!(names(&orphans(&authz, &alice).await), vec!["loose.md"]);
    }

    #[sqlx::test(migrations = false)]
    async fn filing_makes_the_private_workspace_if_there_is_none_yet(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let alice = did("alice");
        let loose = sent(&authz, &repo, &alice, new_note("loose.md", "").unwrap()).await;
        let loose = loose.document_id().clone();
        walked(&authz).await;
        let found = orphans(&authz, &alice).await;
        authz
            .file_orphans(&alice, "Recovered", &found)
            .await
            .unwrap();
        let private = authz.private_workspace(&alice).await.unwrap();
        eventually("the note is in the new workspace", || {
            authz.workspace_of(&loose).map(|root| root.to_string())
                == Some(private.root_doc_id.clone())
        })
        .await;
    }

    async fn rows(pool: &PgPool, doc: &DocumentId) -> (i64, i64) {
        let id = doc.to_string();
        let stored: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM storage WHERE key ~>=~ ($1 || '/') AND key ~<~ ($1 || '0')",
        )
        .bind(&id)
        .fetch_one(pool)
        .await
        .unwrap();
        let creator: i64 =
            sqlx::query_scalar("SELECT count(*) FROM doc_creators WHERE doc_id = $1")
                .bind(&id)
                .fetch_one(pool)
                .await
                .unwrap();
        (stored, creator)
    }

    #[sqlx::test(migrations = false)]
    async fn deleting_removes_the_orphans_and_what_they_hold_and_nothing_else(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let (alice, bob) = (did("alice"), did("bob"));
        let (_, root_doc) = workspace(&authz, &repo, &alice).await;
        let kept = sent(&authz, &repo, &alice, new_note("kept.md", "").unwrap()).await;
        let kept = kept.document_id().clone();
        link(&root_doc, "kept.md", "md", &kept).await;
        let folder = sent(&authz, &repo, &alice, new_folder("Tests").unwrap()).await;
        let inside = sent(&authz, &repo, &alice, new_note("t.md", "x").unwrap()).await;
        let inside = inside.document_id().clone();
        link(&folder, "t.md", "md", &inside).await;
        let folder = folder.document_id().clone();
        let loose = sent(&authz, &repo, &alice, new_note("loose.md", "").unwrap()).await;
        let loose = loose.document_id().clone();
        let bobs = sent(&authz, &repo, &bob, new_note("bobs.md", "").unwrap()).await;
        let bobs = bobs.document_id().clone();
        eventually("the kept note is in the workspace", || {
            authz.workspace_of(&kept).is_some()
        })
        .await;
        walked(&authz).await;

        let found = orphans(&authz, &alice).await;
        assert_eq!(names(&found), vec!["Tests", "loose.md"]);
        repo.stop().await;
        assert_eq!(authz.delete_orphans(&alice, &found).await.unwrap(), 3);

        for gone in [&folder, &inside, &loose] {
            assert_eq!(rows(&pool, gone).await, (0, 0));
        }
        for left in [&kept, &bobs] {
            let (stored, creator) = rows(&pool, left).await;
            assert!(stored > 0);
            assert_eq!(creator, 1);
        }
    }

    #[sqlx::test(migrations = false)]
    async fn a_document_back_in_a_workspace_stops_the_delete(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let alice = did("alice");
        let (_, root_doc) = workspace(&authz, &repo, &alice).await;
        let loose = sent(&authz, &repo, &alice, new_note("loose.md", "").unwrap()).await;
        let loose = loose.document_id().clone();
        walked(&authz).await;
        let found = orphans(&authz, &alice).await;

        link(&root_doc, "loose.md", "md", &loose).await;
        eventually("the note is in the workspace", || {
            authz.workspace_of(&loose).is_some()
        })
        .await;
        assert!(authz.delete_orphans(&alice, &found).await.is_err());
        assert_eq!(rows(&pool, &loose).await.1, 1);
        assert!(authz.delete_orphans(&did("bob"), &found).await.is_err());
    }
}
