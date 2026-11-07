//! The wall between a connection and the repo.
//!
//! samod has no way to refuse a peer: one that names a document ID gets the
//! document and can write to it, and a frame for an unknown ID creates that
//! document. So the relay does not hand samod the websocket. It hands samod a
//! transport of its own and stands in the middle, passing each frame in either
//! direction only if the connection's caller may open the document it names.
//!
//! The filter also ends the connection when the token that opened it expires.
//! samod has no call to close one connection, and a websocket can otherwise
//! stay open for days after its owner has left the network.

use std::convert::Infallible;
use std::time::{Duration, SystemTime};

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use futures::{channel::mpsc, SinkExt, StreamExt};
use samod::{AcceptorHandle, Transport};

use crate::actors::Verdict;
use crate::auth::Caller;
use crate::authz::Authz;
use crate::wire;

/// Frames queued between the websocket and samod in each direction before the
/// faster side has to wait.
const BUFFER: usize = 64;

/// RFC 6455 "policy violation": the nearest standard code to "your token ran
/// out". The client reconnects with a fresh one.
const CLOSE_POLICY: u16 = 1008;

/// How long a request may wait for the index to admit a note another member
/// has just linked. A walk starts on the folder change and takes well under
/// this; the rest is slack for a loaded relay.
const ADMISSION_WAIT: Duration = Duration::from_secs(3);

/// How often a waiting request looks again.
const ADMISSION_POLL: Duration = Duration::from_millis(100);

pub struct Filter {
    authz: Authz,
    caller: Caller,
}

#[derive(Debug, PartialEq)]
pub enum Inbound {
    /// Hand the frame to samod.
    Pass,
    /// Discard the frame and say nothing.
    Drop,
    /// Discard the frame and send this one back.
    Deny(Vec<u8>),
}

impl Filter {
    pub fn new(authz: Authz, caller: Caller) -> Self {
        Self { authz, caller }
    }

    /// Decide what to do with a frame from the peer.
    pub async fn inbound(&self, frame: &[u8]) -> Inbound {
        let Some(envelope) = wire::read(frame) else {
            tracing::warn!(did = %self.caller.did, "dropping an unreadable frame");
            return Inbound::Drop;
        };

        match envelope.kind.as_str() {
            "join" | "leave" | "error" => Inbound::Pass,

            "request" | "sync" | "ephemeral" | "doc-unavailable" => {
                let Some(doc) = envelope.document_id else {
                    tracing::warn!(did = %self.caller.did, kind = %envelope.kind, "dropping a frame with no document ID");
                    return Inbound::Drop;
                };

                // A document nobody has sent before belongs to whoever sends
                // it first. If that cannot be recorded, nobody gets it.
                let allowed = match self.authz.record_creator(&doc, &self.caller).await {
                    Ok(_) => {
                        self.authz.may_open(&self.caller, &doc) || self.admitted_soon(&doc).await
                    }
                    Err(e) => {
                        tracing::error!(did = %self.caller.did, %doc, error = %e, "could not record a document's creator");
                        false
                    }
                };
                // Addressed back the way the frame came, and the same answer a
                // document that does not exist gets.
                let deny = || {
                    Inbound::Deny(wire::doc_unavailable(
                        envelope.target_id.as_deref().unwrap_or_default(),
                        envelope.sender_id.as_deref().unwrap_or_default(),
                        &doc,
                    ))
                };
                // No log line: a peer asking for a document it may not have is
                // ordinary.
                if !allowed {
                    return deny();
                }

                // Who made the changes it carries. If that cannot be
                // recorded, the changes do not get in.
                let data = match (envelope.kind.as_str(), envelope.data.as_deref()) {
                    ("sync" | "request", Some(data)) => data,
                    _ => return Inbound::Pass,
                };
                match self.authz.record_actors(&doc, &self.caller, data).await {
                    Ok(Verdict::Pass) => Inbound::Pass,
                    Ok(Verdict::Forged) => {
                        tracing::warn!(did = %self.caller.did, %doc, "dropping a change under another member's actor");
                        Inbound::Drop
                    }
                    Ok(Verdict::Unreadable) => {
                        tracing::warn!(did = %self.caller.did, %doc, "dropping a frame whose sync message does not decode");
                        Inbound::Drop
                    }
                    Err(e) => {
                        tracing::error!(did = %self.caller.did, %doc, error = %e, "could not record who made a document's changes");
                        deny()
                    }
                }
            }

            // What other peers hold is not this peer's to announce or learn.
            "remote-subscription-change" | "remote-heads-changed" => Inbound::Drop,

            kind => {
                tracing::warn!(did = %self.caller.did, kind, "dropping a frame of an unexpected type");
                Inbound::Drop
            }
        }
    }

    /// Wait a moment for a document another member has just linked into a
    /// workspace's vault.
    ///
    /// Their folder change reaches this peer at once, and the peer asks for
    /// the new note straight away, before the index has walked the folder. A
    /// refusal then would stick: the peer would hear "unavailable" from the
    /// filter, samod would never learn the peer wants the note, and nothing
    /// would offer it later. So the request is held until the index admits the
    /// note or [`ADMISSION_WAIT`] passes.
    ///
    /// Only a caller in a workspace, asking for someone else's document that
    /// no vault reaches yet, ever waits. Everything else is answered at once.
    async fn admitted_soon(&self, doc: &samod::DocumentId) -> bool {
        if self.caller.workspaces.is_empty() || self.authz.holder_of(doc).is_some() {
            return false;
        }
        let deadline = tokio::time::Instant::now() + ADMISSION_WAIT;
        while tokio::time::Instant::now() < deadline {
            tokio::time::sleep(ADMISSION_POLL).await;
            if self.authz.may_open(&self.caller, doc) {
                return true;
            }
        }
        false
    }

    /// May this frame from samod go to the peer?
    ///
    /// The second wall. The inbound check should mean samod never has a
    /// reason to send this peer a document it may not open; this is what holds
    /// if that turns out to be wrong.
    pub fn outbound(&self, frame: &[u8]) -> bool {
        let Some(envelope) = wire::read(frame) else {
            tracing::warn!(did = %self.caller.did, "withholding an unreadable outbound frame");
            return false;
        };
        match envelope.document_id {
            Some(doc) => {
                let allowed = self.authz.may_open(&self.caller, &doc);
                if !allowed {
                    tracing::warn!(did = %self.caller.did, %doc, kind = %envelope.kind, "withholding a frame for a document this peer may not open");
                }
                allowed
            }
            None => true,
        }
    }
}

/// Serve one connection through the filter until either side ends it or its
/// token expires.
pub async fn run(
    socket: WebSocket,
    acceptor: &AcceptorHandle,
    filter: Filter,
    expires_at: Option<SystemTime>,
) {
    let (mut ws_out, mut ws_in) = socket.split();
    let (mut to_samod, samod_in) = mpsc::channel::<Result<Vec<u8>, Infallible>>(BUFFER);
    let (samod_out, mut from_samod) = mpsc::channel::<Vec<u8>>(BUFFER);
    // Answers the inbound side wants sent. They share the websocket's write
    // half with samod's frames, so they queue for the side that owns it.
    let (mut reply, mut replies) = mpsc::channel::<Vec<u8>>(BUFFER);

    if acceptor
        .accept(Transport::new(samod_in, samod_out))
        .is_err()
    {
        tracing::warn!(did = %filter.caller.did, "repo stopped; dropping connection");
        return;
    }
    tracing::info!(did = %filter.caller.did, "peer connected");

    // Each direction runs on its own, so a full queue one way never stops the
    // other and the two cannot wait on each other.
    let inbound = async {
        while let Some(Ok(message)) = ws_in.next().await {
            let frame = match message {
                Message::Binary(frame) => frame,
                Message::Ping(_) | Message::Pong(_) => continue,
                // The protocol is binary. Text or a close ends the connection.
                Message::Text(_) | Message::Close(_) => break,
            };
            let sent = match filter.inbound(&frame).await {
                Inbound::Pass => to_samod.send(Ok(frame.into())).await.is_ok(),
                Inbound::Drop => true,
                Inbound::Deny(answer) => reply.send(answer).await.is_ok(),
            };
            if !sent {
                break;
            }
        }
    };

    let outbound = async {
        let expired = async {
            match expires_at {
                Some(at) => {
                    let left = at
                        .duration_since(SystemTime::now())
                        .unwrap_or(Duration::ZERO);
                    tokio::time::sleep(left).await
                }
                None => std::future::pending().await,
            }
        };
        tokio::pin!(expired);

        loop {
            let frame = tokio::select! {
                _ = &mut expired => {
                    tracing::info!(did = %filter.caller.did, "token expired; closing connection");
                    let _ = ws_out
                        .send(Message::Close(Some(CloseFrame {
                            code: CLOSE_POLICY,
                            reason: "token expired".into(),
                        })))
                        .await;
                    break;
                }
                frame = from_samod.next() => match frame {
                    Some(frame) if filter.outbound(&frame) => frame,
                    Some(_) => continue,
                    None => break,
                },
                answer = replies.next() => match answer {
                    Some(answer) => answer,
                    None => break,
                },
            };
            if ws_out.send(Message::Binary(frame.into())).await.is_err() {
                break;
            }
        }
    };

    // Whichever direction ends first ends the connection. Dropping samod's
    // inbound stream is what makes it let go of its side.
    tokio::select! {
        _ = inbound => {}
        _ = outbound => {}
    }
    tracing::info!(did = %filter.caller.did, "peer disconnected");
}

#[cfg(test)]
mod tests {
    use super::*;

    use automerge::Automerge;
    use sqlx::PgPool;

    use crate::auth::Did;
    use crate::authz::tests::{did, link, member_of, open, sent_by, workspace_vault};
    use crate::wire::tests::{doc_id, frame, CLIENT, RELAY};

    fn as_member(authz: &Authz, did: Did) -> Filter {
        Filter::new(authz.clone(), did.into())
    }

    fn denied(doc: &samod::DocumentId) -> Inbound {
        Inbound::Deny(wire::doc_unavailable(RELAY, CLIENT, doc))
    }

    #[sqlx::test(migrations = false)]
    async fn a_request_for_a_note_just_linked_into_a_workspace_vault_waits_for_it(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let (_, root_doc) = workspace_vault(&authz, &repo, "7").await;
        let bob = Filter::new(authz.clone(), member_of("bob", &["7"]));
        let dave = Filter::new(authz.clone(), member_of("dave", &["8"]));

        // Alice's note and her folder change land, and Bob asks for the note
        // before the index has walked the folder.
        let note = sent_by(&authz, &repo, &member_of("alice", &["7"])).await;
        link(&root_doc, "plan.md", "md", &note).await;
        assert_eq!(
            bob.inbound(&frame("request", Some(&note))).await,
            Inbound::Pass
        );
        assert!(bob.outbound(&frame("sync", Some(&note))));

        // Someone outside the workspace waits out the same moment and is
        // refused.
        assert_eq!(
            dave.inbound(&frame("request", Some(&note))).await,
            denied(&note)
        );
    }

    #[sqlx::test(migrations = false)]
    async fn frames_for_a_members_own_document_pass_both_ways(pool: PgPool) {
        let (authz, _repo) = open(&pool).await;
        let alice = as_member(&authz, did("alice"));
        let doc = doc_id(1);

        for kind in ["sync", "request", "ephemeral", "doc-unavailable"] {
            assert_eq!(alice.inbound(&frame(kind, Some(&doc))).await, Inbound::Pass);
            assert!(alice.outbound(&frame(kind, Some(&doc))));
        }
    }

    #[sqlx::test(migrations = false)]
    async fn the_first_sender_of_a_new_document_becomes_its_creator(pool: PgPool) {
        let (authz, _repo) = open(&pool).await;
        let alice = as_member(&authz, did("alice"));
        let bob = as_member(&authz, did("bob"));
        let doc = doc_id(2);

        assert_eq!(authz.creator_of(&doc), None);
        assert_eq!(
            alice.inbound(&frame("sync", Some(&doc))).await,
            Inbound::Pass
        );
        assert_eq!(authz.creator_of(&doc), Some(did("alice")));

        assert_eq!(bob.inbound(&frame("sync", Some(&doc))).await, denied(&doc));
        assert_eq!(authz.creator_of(&doc), Some(did("alice")));
    }

    #[sqlx::test(migrations = false)]
    async fn another_members_document_is_denied_and_withheld(pool: PgPool) {
        let (authz, repo) = open(&pool).await;
        let vault = authz.private_vault(&did("alice")).await.unwrap();
        let root = vault.root_doc_id.parse().unwrap();
        let note = repo.create(Automerge::new()).await.unwrap();
        let note = note.document_id();
        authz.record(note, &did("alice")).await.unwrap();
        let bob = as_member(&authz, did("bob"));

        for doc in [&root, note] {
            for kind in ["sync", "request", "ephemeral", "doc-unavailable"] {
                assert_eq!(bob.inbound(&frame(kind, Some(doc))).await, denied(doc));
                assert!(!bob.outbound(&frame(kind, Some(doc))));
            }
        }
    }

    #[sqlx::test(migrations = false)]
    async fn frames_about_no_document_follow_the_table(pool: PgPool) {
        let (authz, _repo) = open(&pool).await;
        let alice = as_member(&authz, did("alice"));
        let doc = doc_id(3);

        for kind in ["join", "leave", "error"] {
            assert_eq!(alice.inbound(&frame(kind, None)).await, Inbound::Pass);
        }
        for kind in ["remote-subscription-change", "remote-heads-changed"] {
            assert_eq!(alice.inbound(&frame(kind, Some(&doc))).await, Inbound::Drop);
        }
        // A type the relay never expects from a client, a frame that needs a
        // document ID and has none, and bytes that are not a frame.
        assert_eq!(alice.inbound(&frame("peer", None)).await, Inbound::Drop);
        assert_eq!(alice.inbound(&frame("sync", None)).await, Inbound::Drop);
        assert_eq!(alice.inbound(b"not cbor").await, Inbound::Drop);
        // None of those made her the creator of anything.
        assert_eq!(authz.creator_of(&doc), None);

        assert!(alice.outbound(&frame("peer", None)));
        assert!(!alice.outbound(b"not cbor"));
    }
}
