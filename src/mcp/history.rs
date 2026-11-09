//! A note's history: its changes grouped by session, its text as it was, and
//! what changed between two versions.
//!
//! A version is named by the hash of one change, and means the note as that
//! change left it: the change and everything it was made on top of. Edits
//! another device made at the same time, not yet merged in, are not part of
//! it.
//!
//! Everything here reads. Nothing rewinds a note: an earlier version is
//! restored by reading it and creating a new note from it, so nobody's later
//! work is discarded.

use std::str::FromStr;

use automerge::{
    ActorId, Automerge, ChangeHash, ObjId, ObjType, PatchAction, ReadDoc, TextEncoding, Value, ROOT,
};
use chrono::{DateTime, Utc};

use super::notes::{refuse, Result};

/// A run of consecutive changes under one actor: one member's session on one
/// note, or a stretch of their MCP edits.
#[derive(Debug)]
pub struct Group {
    /// The newest change in the group, which names the version after it.
    pub id: ChangeHash,
    pub actor: ActorId,
    /// The device's clock at the oldest and newest change, where it gave one.
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    /// Characters of the note's text added and removed.
    pub added: usize,
    pub removed: usize,
    pub changes: usize,
}

/// What `note_history` answers with.
#[derive(Debug)]
pub enum History {
    /// The changes, newest first, and whether there are older ones.
    Changes { groups: Vec<Group>, more: bool },
    /// The text at one version.
    Text(String),
    /// What changed between two versions.
    Diff(Vec<Hunk>),
}

/// A stretch of text that differs between two versions. `line` is where it
/// starts in the later of the two, counting from 1.
#[derive(Debug, PartialEq)]
pub struct Hunk {
    pub line: usize,
    pub removed: String,
    pub added: String,
}

/// A change's timestamp, which is whatever the device's clock said. Automerge
/// stamps seconds; a value too large for seconds is read as milliseconds.
/// Zero means none was stamped.
fn device_time(stamp: i64) -> Option<DateTime<Utc>> {
    match stamp {
        s if s <= 0 => None,
        s if s > 100_000_000_000 => DateTime::from_timestamp_millis(s),
        s => DateTime::from_timestamp(s, 0),
    }
}

/// A change ID as a caller passes it back, checked against this note.
pub fn version(doc: &Automerge, id: &str) -> Result<ChangeHash> {
    match ChangeHash::from_str(id.trim()) {
        Ok(hash) if doc.get_change_by_hash(&hash).is_some() => Ok(hash),
        _ => refuse(format!(
            "{id:?} is not a change in this note; call note_history without a version to see \
             its changes"
        )),
    }
}

/// The note's text object at these heads.
fn content_at(doc: &Automerge, heads: &[ChangeHash]) -> Result<Option<ObjId>> {
    Ok(match doc.get_at(ROOT, "content", heads)? {
        Some((Value::Object(ObjType::Text), id)) => Some(id),
        _ => None,
    })
}

/// Characters one change added to and removed from the text object.
fn sizes(
    doc: &Automerge,
    content: &ObjId,
    hash: ChangeHash,
    deps: &[ChangeHash],
) -> (usize, usize) {
    let Ok(patches) = doc.diff_obj(content, deps, &[hash], false) else {
        return (0, 0);
    };
    let (mut added, mut removed) = (0, 0);
    for patch in patches {
        match patch.action {
            PatchAction::SpliceText { value, .. } => added += value.make_string().chars().count(),
            PatchAction::DeleteSeq { length, .. } => removed += length,
            _ => {}
        }
    }
    (added, removed)
}

/// The note's changes, newest first, in at most `limit` groups, and whether
/// there are older ones.
///
/// Newest first is the reverse of Automerge's causal order, so a change is
/// always listed before the ones it was made on top of. Two devices editing at
/// once interleave, which splits their sessions into several groups.
pub fn groups(doc: &Automerge, limit: usize) -> Result<(Vec<Group>, bool)> {
    let content = content_at(doc, &doc.get_heads())?;
    let changes = doc.get_changes(&[]);
    let mut groups: Vec<Group> = Vec::new();
    for change in changes.iter().rev() {
        let (added, removed) = match &content {
            Some(content) => sizes(doc, content, change.hash(), change.deps()),
            None => (0, 0),
        };
        let time = device_time(change.timestamp());
        let full = groups.len() == limit;
        match groups.last_mut() {
            Some(group) if group.actor == *change.actor_id() => {
                group.from = time.or(group.from);
                group.added += added;
                group.removed += removed;
                group.changes += 1;
            }
            _ if full => return Ok((groups, true)),
            _ => groups.push(Group {
                id: change.hash(),
                actor: change.actor_id().clone(),
                from: time,
                to: time,
                added,
                removed,
                changes: 1,
            }),
        }
    }
    Ok((groups, false))
}

/// The note's text as of a version.
pub fn text_at(doc: &Automerge, at: ChangeHash) -> Result<String> {
    match content_at(doc, &[at])? {
        Some(content) => Ok(doc.text_at(&content, &[at])?),
        None => refuse("the note had no text at that version"),
    }
}

/// How many characters of `chars` make `units` in this encoding.
fn char_index(chars: &[char], encoding: TextEncoding, units: usize) -> usize {
    let mut seen = 0;
    for (i, c) in chars.iter().enumerate() {
        if seen >= units {
            return i;
        }
        seen += match encoding {
            TextEncoding::Utf8CodeUnit => c.len_utf8(),
            TextEncoding::Utf16CodeUnit => c.len_utf16(),
            _ => 1,
        };
    }
    chars.len()
}

/// What changed from version `a` to version `b`, removed text included.
///
/// Automerge's diff says where text was deleted but not what it was, so the
/// diff is replayed on the text at `a` to recover it.
pub fn diff(doc: &Automerge, a: ChangeHash, b: ChangeHash) -> Result<Vec<Hunk>> {
    let before = text_at(doc, a)?;
    let (from, to) = (content_at(doc, &[a])?, content_at(doc, &[b])?);
    let (Some(content), true) = (&to, from == to) else {
        // The text was replaced whole between the two: say so as one hunk.
        let after = text_at(doc, b)?;
        return Ok(vec![Hunk {
            line: 1,
            removed: before,
            added: after,
        }]);
    };

    let encoding = doc.text_encoding();
    let mut text: Vec<char> = before.chars().collect();
    // Each hunk with where it starts in `text` and how long its added part is.
    let mut hunks: Vec<(usize, usize, Hunk)> = Vec::new();
    for patch in doc.diff_obj(content, &[a], &[b], false)? {
        let (at, removed, added) = match patch.action {
            PatchAction::SpliceText { index, value, .. } => {
                let at = char_index(&text, encoding, index);
                let added = value.make_string();
                text.splice(at..at, added.chars());
                (at, String::new(), added)
            }
            PatchAction::DeleteSeq { index, length } => {
                let at = char_index(&text, encoding, index);
                let end = at + char_index(&text[at..], encoding, length);
                (at, text.drain(at..end).collect(), String::new())
            }
            _ => continue,
        };
        let added_len = added.chars().count();
        match hunks.last_mut() {
            Some((start, len, hunk)) if at == *start + *len => {
                hunk.removed.push_str(&removed);
                hunk.added.push_str(&added);
                *len += added_len;
            }
            _ => hunks.push((
                at,
                added_len,
                Hunk {
                    line: 0,
                    removed,
                    added,
                },
            )),
        }
    }
    Ok(hunks
        .into_iter()
        .map(|(start, _, mut hunk)| {
            hunk.line = 1 + text[..start].iter().filter(|c| **c == '\n').count();
            hunk
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    use automerge::transaction::Transactable;

    use crate::mcp::notes::NoteError;

    /// Change the note's text as `actor`: delete `delete` characters at `at`
    /// and insert `insert` there. Returns the change's hash.
    fn splice(
        doc: &mut Automerge,
        actor: &ActorId,
        at: usize,
        delete: isize,
        insert: &str,
    ) -> ChangeHash {
        doc.set_actor(actor.clone());
        let content = content_at(doc, &doc.get_heads()).unwrap().unwrap();
        let mut tx = doc.transaction();
        tx.splice_text(&content, at, delete, insert).unwrap();
        tx.commit_with(automerge::transaction::CommitOptions::default().with_time(1_800_000_000))
            .0
            .unwrap()
    }

    /// A note Alice wrote, then edited twice, then Bob edited.
    fn written() -> (Automerge, ActorId, ActorId, Vec<ChangeHash>) {
        let (alice, bob) = (ActorId::random(), ActorId::random());
        let mut doc = super::super::notes::new_note("plan.md", "").unwrap();
        doc.set_actor(alice.clone());
        let hashes = vec![
            splice(&mut doc, &alice, 0, 0, "buy milk\n"),
            splice(&mut doc, &alice, 9, 0, "call Sam\n"),
            // Bob takes out "milk" and puts "bread".
            splice(&mut doc, &bob, 4, 4, "bread"),
        ];
        (doc, alice, bob, hashes)
    }

    #[test]
    fn changes_come_back_newest_first_grouped_by_actor() {
        let (doc, alice, bob, hashes) = written();
        let (groups, more) = groups(&doc, 10).unwrap();
        assert!(!more);
        let actors: Vec<&ActorId> = groups.iter().map(|g| &g.actor).collect();
        // Bob's edit, Alice's two edits, then the note's creation under the
        // document's own first actor.
        assert_eq!(actors[0], &bob);
        assert_eq!(actors[1], &alice);
        assert_eq!(groups[0].id, hashes[2]);
        assert_eq!((groups[0].added, groups[0].removed), (5, 4));
        assert_eq!(groups[1].id, hashes[1]);
        assert_eq!(
            (groups[1].added, groups[1].removed, groups[1].changes),
            (18, 0, 2)
        );
        assert!(groups[0].to.is_some());
    }

    #[test]
    fn a_limit_stops_early_and_says_there_is_more() {
        let (doc, _, bob, _) = written();
        let (groups, more) = groups(&doc, 1).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].actor, bob);
        assert!(more);
    }

    #[test]
    fn an_old_version_holds_text_since_deleted() {
        let (doc, _, _, hashes) = written();
        assert_eq!(text_at(&doc, hashes[1]).unwrap(), "buy milk\ncall Sam\n");
        assert_eq!(text_at(&doc, hashes[2]).unwrap(), "buy bread\ncall Sam\n");
    }

    #[test]
    fn a_diff_shows_added_and_removed_text() {
        let (doc, _, _, hashes) = written();
        let hunks = diff(&doc, hashes[1], hashes[2]).unwrap();
        assert_eq!(hunks.len(), 1);
        assert_eq!(hunks[0].removed, "milk");
        assert_eq!(hunks[0].added, "bread");
        assert_eq!(hunks[0].line, 1);

        let hunks = diff(&doc, hashes[0], hashes[1]).unwrap();
        assert_eq!(hunks[0].added, "call Sam\n");
        assert_eq!(hunks[0].line, 2);
    }

    #[test]
    fn an_id_that_is_not_a_change_in_the_note_is_refused() {
        let (doc, _, _, _) = written();
        let (_, _, _, hashes) = written();
        assert!(matches!(
            version(&doc, &hashes[0].to_string()),
            Err(NoteError::Refused(_))
        ));
        assert!(matches!(
            version(&doc, "not a hash"),
            Err(NoteError::Refused(_))
        ));
    }
}
