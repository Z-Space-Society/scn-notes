//! Handles for the DIDs the relay shows a member.
//!
//! History names each change by its member's DID, which a reader cannot turn
//! into a person and an MCP client may not be able to look up at all. The
//! relay turns it into the member's handle here, the same way Corliss does for
//! its own pages: read the handle the DID document claims, from plc.directory
//! for `did:plc:` or from the host for `did:web:`.
//!
//! **A claimed handle is only a claim.** Anyone can list another member's
//! handle in their own DID document, so a handle is shown only when it points
//! back: its `_atproto` TXT record, or else its `/.well-known/atproto-did`,
//! names the same DID. That is the check Corliss's `resolve_handle_for_admin`
//! makes, with no third-party resolver in it.
//!
//! **Nothing about a member is stored.** The answers are held in memory for a
//! while so history does not ask the network on every call, and are gone at
//! restart. A miss is held too, more briefly, so an unreachable directory is
//! not asked again on every listing.
//!
//! **A lookup never holds up an answer for long, and never fails one.** Every
//! DID in a request is looked up at once under one short budget. Whatever is
//! not verified by then is shown as its DID, which is what the listing showed
//! before handles existed.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures::future::{join_all, BoxFuture};
use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioResolver;
use serde_json::Value;

use crate::auth::Did;

/// How long one request may wait on all of its lookups together.
const BUDGET: Duration = Duration::from_secs(3);
/// How long a single HTTP request in a lookup may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
/// How long a verified handle is reused. Handles change rarely, and a stale
/// one is a display slip, not an access decision.
const FOUND_TTL: Duration = Duration::from_secs(60 * 60);
/// How long a DID with no verified handle is left alone before asking again.
const MISS_TTL: Duration = Duration::from_secs(5 * 60);

/// Turns a DID into its verified handle, or `None`.
///
/// Object-safe, as `DidVerifier` is, so tests can stand in a resolver that
/// never touches the network.
pub trait HandleResolver: Send + Sync + 'static {
    fn resolve<'a>(&'a self, did: &'a Did) -> BoxFuture<'a, Option<String>>;
}

/// Verified handles for DIDs, cached in memory.
#[derive(Clone)]
pub struct Handles(Arc<Inner>);

struct Inner {
    resolver: Arc<dyn HandleResolver>,
    budget: Duration,
    cache: Mutex<HashMap<Did, Cached>>,
}

struct Cached {
    handle: Option<String>,
    until: Instant,
}

impl Handles {
    pub fn new(resolver: Arc<dyn HandleResolver>) -> Self {
        Self::with_budget(resolver, BUDGET)
    }

    fn with_budget(resolver: Arc<dyn HandleResolver>, budget: Duration) -> Self {
        Self(Arc::new(Inner {
            resolver,
            budget,
            cache: Mutex::new(HashMap::new()),
        }))
    }

    /// The verified handle of each DID that has one. A DID missing from the
    /// answer is shown as itself.
    pub async fn handles_for<'a>(
        &self,
        dids: impl IntoIterator<Item = &'a Did>,
    ) -> HashMap<Did, String> {
        let mut found = HashMap::new();
        let mut wanted = Vec::new();
        {
            let now = Instant::now();
            let cache = self.0.cache.lock().unwrap();
            for did in dids.into_iter().collect::<HashSet<_>>() {
                match cache.get(did) {
                    Some(cached) if cached.until > now => {
                        if let Some(handle) = &cached.handle {
                            found.insert(did.clone(), handle.clone());
                        }
                    }
                    _ => wanted.push(did.clone()),
                }
            }
        }
        if wanted.is_empty() {
            return found;
        }

        // One deadline for all of them, so a request costs at most one budget
        // however many members it names.
        let deadline = tokio::time::Instant::now() + self.0.budget;
        let answers = join_all(
            wanted
                .iter()
                .map(|did| tokio::time::timeout_at(deadline, self.0.resolver.resolve(did))),
        )
        .await;

        let now = Instant::now();
        let mut cache = self.0.cache.lock().unwrap();
        for (did, answer) in wanted.into_iter().zip(answers) {
            // Out of time says nothing about the DID, so it is not held.
            let Ok(handle) = answer else { continue };
            let ttl = if handle.is_some() {
                FOUND_TTL
            } else {
                MISS_TTL
            };
            cache.insert(
                did.clone(),
                Cached {
                    handle: handle.clone(),
                    until: now + ttl,
                },
            );
            if let Some(handle) = handle {
                found.insert(did, handle);
            }
        }
        found
    }
}

/// Looks handles up on the network: the DID document, then the handle's own
/// record of its DID.
pub struct AtprotoResolver {
    client: reqwest::Client,
    dns: TokioResolver,
}

impl AtprotoResolver {
    pub fn new() -> Result<Self> {
        // The TLS provider the rest of the binary uses; see `CorlissVerifier::new`.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .context("could not build the HTTP client for handle lookups")?;
        let dns = TokioResolver::builder_tokio()
            .context("could not read the system's DNS configuration")?
            .build()
            .context("could not build the DNS resolver")?;
        Ok(Self { client, dns })
    }

    async fn lookup(&self, did: &Did) -> Option<String> {
        let url = did_document_url(&did.0)?;
        let doc: Value = self
            .client
            .get(url)
            .send()
            .await
            .ok()?
            .error_for_status()
            .ok()?
            .json()
            .await
            .ok()?;
        // A host can serve any document; only this DID's says who it is.
        if doc["id"].as_str() != Some(did.0.as_str()) {
            return None;
        }
        let handle = handle_from_doc(&doc)?;
        let points_back = self.txt_did(&handle).await.as_deref() == Some(did.0.as_str())
            || self.well_known_did(&handle).await.as_deref() == Some(did.0.as_str());
        points_back.then_some(handle)
    }

    /// The DID in the handle's `_atproto` TXT record.
    async fn txt_did(&self, handle: &str) -> Option<String> {
        let lookup = self
            .dns
            .txt_lookup(format!("_atproto.{handle}."))
            .await
            .ok()?;
        lookup
            .answers()
            .iter()
            .find_map(|record| match &record.data {
                RData::TXT(txt) => did_from_txt(&txt.txt_data),
                _ => None,
            })
    }

    /// The DID the handle's host serves at `/.well-known/atproto-did`.
    async fn well_known_did(&self, handle: &str) -> Option<String> {
        let text = self
            .client
            .get(format!("https://{handle}/.well-known/atproto-did"))
            .send()
            .await
            .ok()?
            .error_for_status()
            .ok()?
            .text()
            .await
            .ok()?;
        let did = text.trim();
        did.starts_with("did:").then(|| did.to_string())
    }
}

impl HandleResolver for AtprotoResolver {
    fn resolve<'a>(&'a self, did: &'a Did) -> BoxFuture<'a, Option<String>> {
        Box::pin(self.lookup(did))
    }
}

/// Where a DID's document is published. Only the two methods members have,
/// and for `did:web` only a bare host: a DID with a path or a port is rare
/// enough to show as itself.
fn did_document_url(did: &str) -> Option<String> {
    if let Some(id) = did.strip_prefix("did:plc:") {
        let plain = !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric());
        return plain.then(|| format!("https://plc.directory/{did}"));
    }
    let host = did.strip_prefix("did:web:")?;
    is_hostname(host).then(|| format!("https://{host}/.well-known/did.json"))
}

/// The handle a DID document claims: its first `at://` alias.
///
/// Checked as a host name before anything is asked of it, because it goes
/// into a URL and a DNS query and the document's author chose it.
fn handle_from_doc(doc: &Value) -> Option<String> {
    let handle = doc["alsoKnownAs"]
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .find_map(|aka| aka.strip_prefix("at://"))?
        .to_ascii_lowercase();
    is_hostname(&handle).then_some(handle)
}

/// The DID in an `_atproto` TXT record's `did=...` string.
fn did_from_txt(strings: &[Box<[u8]>]) -> Option<String> {
    let text: Vec<u8> = strings.iter().flat_map(|s| s.iter().copied()).collect();
    let did = std::str::from_utf8(&text).ok()?.strip_prefix("did=")?;
    did.starts_with("did:").then(|| did.to_string())
}

/// A dotted DNS name of letters, digits and hyphens, as a handle must be.
fn is_hostname(name: &str) -> bool {
    name.len() <= 253
        && name.contains('.')
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::json;

    /// Answers from a fixed map and counts what it is asked.
    #[derive(Default)]
    pub(crate) struct FakeResolver {
        pub handles: HashMap<String, String>,
        pub asked: AtomicUsize,
    }

    impl FakeResolver {
        pub(crate) fn with(pairs: &[(&str, &str)]) -> Self {
            Self {
                handles: pairs
                    .iter()
                    .map(|(did, handle)| (did.to_string(), handle.to_string()))
                    .collect(),
                asked: AtomicUsize::new(0),
            }
        }
    }

    impl HandleResolver for FakeResolver {
        fn resolve<'a>(&'a self, did: &'a Did) -> BoxFuture<'a, Option<String>> {
            self.asked.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { self.handles.get(&did.0).cloned() })
        }
    }

    /// Never answers.
    struct Hangs;

    impl HandleResolver for Hangs {
        fn resolve<'a>(&'a self, _: &'a Did) -> BoxFuture<'a, Option<String>> {
            Box::pin(futures::future::pending())
        }
    }

    fn did(s: &str) -> Did {
        Did(s.into())
    }

    #[tokio::test]
    async fn a_did_is_looked_up_once_and_a_miss_is_held() {
        let fake = Arc::new(FakeResolver::with(&[("did:plc:alice", "alice.test")]));
        let handles = Handles::new(fake.clone());
        let (alice, bob) = (did("did:plc:alice"), did("did:plc:bob"));

        let found = handles.handles_for([&alice, &alice, &bob]).await;
        assert_eq!(found.get(&alice).map(String::as_str), Some("alice.test"));
        assert!(!found.contains_key(&bob));
        assert_eq!(fake.asked.load(Ordering::SeqCst), 2);

        let found = handles.handles_for([&alice, &bob]).await;
        assert_eq!(found.len(), 1);
        assert_eq!(fake.asked.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_lookup_past_the_budget_is_left_out_and_asked_again() {
        let handles = Handles::with_budget(Arc::new(Hangs), Duration::from_millis(20));
        let alice = did("did:plc:alice");

        assert!(handles.handles_for([&alice]).await.is_empty());
        assert!(handles.0.cache.lock().unwrap().is_empty());
    }

    #[test]
    fn the_handle_is_the_first_at_alias_and_must_be_a_host_name() {
        let doc = json!({ "alsoKnownAs": ["https://example.com", "at://Alice.Example.com"] });
        assert_eq!(handle_from_doc(&doc).as_deref(), Some("alice.example.com"));

        for bad in [
            "at://evil.com/path",
            "at://user@evil.com",
            "at://localhost",
            "at://a..b",
        ] {
            assert_eq!(
                handle_from_doc(&json!({ "alsoKnownAs": [bad] })),
                None,
                "{bad}"
            );
        }
        assert_eq!(handle_from_doc(&json!({})), None);
    }

    #[test]
    fn a_txt_record_names_a_did_only_after_did_equals() {
        let record = |s: &str| vec![s.as_bytes().to_vec().into_boxed_slice()];
        assert_eq!(
            did_from_txt(&record("did=did:plc:alice")).as_deref(),
            Some("did:plc:alice")
        );
        assert_eq!(did_from_txt(&record("v=spf1 -all")), None);
        assert_eq!(did_from_txt(&record("did=alice")), None);
    }

    #[test]
    fn did_documents_are_fetched_only_from_their_own_place() {
        assert_eq!(
            did_document_url("did:plc:ewvi7nxzyoun6zhxrhs64oiz").as_deref(),
            Some("https://plc.directory/did:plc:ewvi7nxzyoun6zhxrhs64oiz")
        );
        assert_eq!(
            did_document_url("did:web:example.com").as_deref(),
            Some("https://example.com/.well-known/did.json")
        );
        assert_eq!(did_document_url("did:plc:../admin"), None);
        assert_eq!(did_document_url("did:web:example.com:8080"), None);
        assert_eq!(did_document_url("did:key:z6Mk"), None);
    }
}
