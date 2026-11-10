# AGENTS.md

Guidance for coding agents working in `scn-notes`. Read this before changing
anything that touches authentication, authorization, storage, or the wire.

`scn-notes` is the service behind SCN Notes on the Shared Computer Network: an
Automerge sync relay, an MCP server over the same documents, and the workspace
API the Obsidian plugin and Corliss use. It is one Rust binary speaking the
`automerge-repo` WebSocket protocol, persisting to Postgres, with no Node
runtime and no container.

## Read in this order

1. `README.md` — the current contract: configuration, endpoints, wire shapes,
   storage, and what the service deliberately does not do. When the README and
   the code disagree, that is a bug in one of them; do not pick silently.
2. `docs/specs/0001-spec-phase-b/0001-spec-phase-b.md` — the Phase B design
   (auth, owner-only authorization, MCP). It is historical: some names changed
   (`vault` → `workspace` in v0.7.0) and later work is not in it.
3. The module docs (`//!` at the top of each file). They explain the failure
   mode each module exists to prevent. Keep them true.

The spec's open questions are real. Do not "fix" one without confirming the
decision first.

## Build, test, lint

The toolchain is pinned in `rust-toolchain.toml` (1.98.0); `Cargo.toml` keeps
`rust-version = 1.94` for the MSRV. Use the pinned toolchain.

```sh
cargo build --release
cargo fmt --all
cargo clippy --all-targets -- -D warnings
```

Most tests need Postgres. `DATABASE_URL` is the server the test harness may
create databases on; each `#[sqlx::test]` gets and drops its own database.
`SCN_NOTES_DATABASE_URL` is the *binary's* setting (the `SCN_NOTES_` prefix is
added by `src/config.rs`); tests use plain `DATABASE_URL`.

```sh
DATABASE_URL=postgres://localhost/postgres cargo test
DATABASE_URL=postgres://localhost/postgres cargo test a_member_syncs -- --nocapture
```

Debug and release builds differ only in optimisation. Do not add a feature that
needs a Node toolchain, a container, or a non-Rust C library: the deployment
cold-builds this repository on the target's glibc.

## Module map

| Path | Holds |
|---|---|
| `src/main.rs` | Process wiring: config, Postgres pool, `samod::Repo`, the three listeners, `file-unfiled`. |
| `src/config.rs` | Environment settings. Fails closed; no config file. |
| `src/auth.rs` | `DidVerifier`, `CorlissVerifier` (RS256, JWKS cache), `AllowAll`, `Did`, `Caller`. |
| `src/authz.rs` | `Authz`: `may_open`, workspace and `doc_creators` records, the reachability index handle, actor map. |
| `src/reach.rs` | Walks folder documents from each workspace root; derived, in-memory, rebuildable. |
| `src/filter.rs` | The transport filter: per-frame allow/deny on sync, and close at token expiry. |
| `src/wire.rs` | Minimal CBOR envelope reader for the sync protocol. |
| `src/workspaces.rs` | `/vaults`, `/internal/vaults*`, `/v1/workspaces`, `/internal/workspaces*`. |
| `src/actors.rs` | Maps Automerge actors to members; owns the actor-history backfill. |
| `src/mcp/` | MCP listener (`mod.rs`), tools (`tools.rs`), note/folder document I/O (`notes.rs`), search (`search.rs`), history (`history.rs`). |
| `src/unfiled.rs` | The `file-unfiled` command: orphans, recovery folder, deletion. |
| `src/storage.rs` | samod `Storage` over one Postgres key/value table. |

## Invariants

These are load-bearing. A change that breaks one is a security or data-loss
bug, even if the tests pass.

### Authentication and authorization

- **Fail closed.** `require_auth` defaults to on. With auth on, any missing
  required setting refuses startup. With auth off (`SCN_NOTES_REQUIRE_AUTH=false`)
  the MCP listener is not started and the filter is not installed; that mode is
  for local work on a host with no route in. Never make auth optional by
  omission.
- **`Authz::may_open` is the single gate.** The sync filter checks it inbound
  and outbound, and every MCP tool checks it for every document it touches.
  Do not add a read, list, search, history, or write path that reaches a
  document without it.
- **A folder link does not grant access.** A document joins a workspace only if
  the workspace's holder admits its creator (`Holder::admits`): the member for
  a Private workspace; a token naming the group when the document was first
  sent for a shared one. The reachability walk must keep applying this rule.
- **Corliss owns membership and groups.** The relay holds no roster. A token's
  `sub` is the member DID and its `workspaces` claim is the group IDs. Leaving
  the network or a group takes effect within one token lifetime (15 minutes).
- **`doc_creators` is the store of record.** Losing it loses every member's
  access to their own notes. Writes are `INSERT … ON CONFLICT DO NOTHING`, then
  read back, so two peers racing on one ID cannot both become its creator.
- **Audiences are exact.** A token's `aud` must match the configured audience
  character for character. `PUBLIC_URL` must be an origin with no path and no
  trailing slash; the plugin's audience is that origin, MCP's is the origin
  plus `/mcp`. A mismatch surfaces only as `401`.
- **Never log a token or a query string.** A browser or phone WebSocket cannot
  set `Authorization`, so sync tokens ride in `?access_token=` and the proxy
  must not log it either. The relay's own logs must not include it.

### Repo and wire behaviour

- **samod cannot enforce authorization.** It will hand a document to a peer
  that names its ID, and a frame for an unknown ID creates that document. The
  filter is the wall; its CBOR reader must agree with samod about which
  document a frame names. A frame the reader cannot parse is never forwarded.
- **Announcing is off.** `ShareConfig::read_write().with_announce(false)` is
  deliberate: the relay never offers a document unasked and never asks one peer
  for a document on behalf of another. Clients request what their folder
  documents list, on every connection. Turning announcing on would leak
  document IDs and existence.
- **A denied document and a missing document look identical.** Answer a denied
  request with `doc-unavailable`; a `404` where a peer expects a document is
  the same surface.
- **Connections close at `exp`.** The filter sends WebSocket close code `1008`
  with reason `token expired`, then ends the inbound stream. A client reconnects
  with a fresh token. Do not keep sockets alive past expiry.
- **`/v1/` is additive only.** A breaking change is `/v2/` served beside it,
  never an edit to `/v1/`. The pre-v0.7.0 `/vaults` and `/internal/vaults`
  shapes stay until the `sync.` listener retires (issue #19); they are for
  clients up to 1.2.x and the old Corliss.

### Storage

- **No in-memory fallback.** `SCN_NOTES_DATABASE_URL` is required: a relay that
  silently ran on memory would look healthy until its first restart lost every
  document.
- **`text_pattern_ops` is load-bearing.** The default opclass follows the
  database collation and will not serve samod's `LIKE 'prefix%'` range scan,
  quietly turning every read into a full table scan.
- **`StorageKey` components contain no `/`.** The key round trip is `Display`
  out and `split('/')` back; do not add escaping or a second encoding.
- **Schema is created at startup**, idempotently. The deployment provisions the
  database and owning role, not the schema. A relay before v0.7.0 is migrated
  from `vaults` to `workspaces` in one transaction; keep that path working.
- **The reachability index is derived.** Never persist it and never treat it as
  authority; the folder documents plus `doc_creators` are.

### Runtime

- **Bind wildcards (`0.0.0.0`), not a container address.** Binding a literal
  address loses a cold-boot race with `systemd-networkd` and comes up
  loopback-only.
- **`/internal/` is not public.** It is served only on the sync listener and
  guarded by the service token for Corliss. The `notes.` listener must not
  serve it, so the proxy can route that host whole. Never add it there.
- **`/health` does not touch Postgres.** A database blip must not get the relay
  restarted out from under live connections.
- **The MCP service is stateless.** No session ID; each request carries its own
  token; GET and DELETE are not part of the flow. A relay restart needs nothing
  from the client.

## Data model and vocabulary

| Word | Meaning |
|---|---|
| workspace | The unit of access: a member's Private workspace or a group's shared one. |
| group | Corliss's word for a workspace/team. Its ID is `group_id` here and the `workspaces` claim in a token. |
| vault | The pre-v0.7.0 name. It survives only in the legacy endpoints and in cluster/deployment names. |

Tables: `storage` (samod documents), `workspaces` (root, owner, optional group,
name), `doc_creators` (creator DID and the groups its token named), and
`actor_members` (Automerge actor → member). `relay_jobs` records one-off jobs
such as the actor backfill.

A document schema is settled in the spec: folder documents are
`{"@patchwork": {"type": "folder"}, "title", "docs": [...]}`; notes are
`{"@patchwork": {"type": "file"}, "name", "extension": "md", …, "content"}`,
where `content` is an Automerge text object. Names are one path segment, NFC,
not empty, not `.`/`..`, no `/`, no leading dot. Paths match after NFC and case
folding. When two entries collide, the entry whose `url` sorts lowest is the
one the path means.

## Testing conventions

- Unit and integration tests live beside the code in `#[cfg(test)] mod tests`.
  There is no separate top-level integration test suite; `tests/fixtures/` holds
  JWKS and PEM material only.
- Use `#[sqlx::test(migrations = false)]`: the relay creates its schema itself,
  and each test gets a database of its own. `RUST_TEST_THREADS = "3"` in
  `.cargo/config.toml` is deliberate (the test harness pool is 20 connections).
- The `Relay` helper in `src/main.rs` starts all three listeners on loopback
  ports with a test issuer. Prefer it over hand-building state.
- Async index work is eventually consistent. Use `authz::tests::eventually`
  (or the same pattern) rather than fixed sleeps. A test that needs a timer to
  pass is usually testing the wrong thing.
- A fix for an access-control bug needs a test that fails without the fix and
  proves the negative case (the other member, the other workspace, the removed
  entry), not only the happy path.
- Tests must not require a real Corliss, network access, or a deployed relay.
  The test issuer and fixtures stand in.

## Style and conventions

- Rust 2021. Run `cargo fmt`; match the surrounding style rather than bringing
  in new lints or structure.
- Comments explain **why** and the failure mode, not what the code does. Module
  docs carry the design; long explanatory comments on tricky code are the
  house style. If you change behaviour, update the comment that justified the
  old behaviour.
- Errors: `anyhow` in the binary and internal paths; API errors are
  `{"error": "<code>"}` with stable snake_case codes (`invalid_did`,
  `invalid_name`, `invalid_group`). Do not leak internal reasons to a peer.
- Use `DocHandle::with_document_async` for document work in async contexts.
  Never block the runtime on a long walk or a slow edit.
- New code says **workspace**, not vault. Keep `vault` only where an external
  shape or a deployment name requires it.
- The environment prefix is `SCN_NOTES_`. Cluster names keep the old spelling
  on purpose (the `sync_relay` role, the `sync-relay` container, the
  `scn_sync_relay` database); do not rename them in a code change.

## Git and pull requests

- Work on a branch, not `main`. Keep commits and PRs focused: one concern per
  PR, with a message that says what changed and why.
- Do not bump the version or push a tag unless the task is a release. Releases
  use an **annotated** tag pushed to the remote; deployment checks out the tag,
  not a branch.
- Do not commit secrets, tokens, database URLs, or real member data. Test
  fixtures are synthetic.
- The software is `scn-notes`; the GitHub repository is
  `Z-Space-Society/scn-notes`.

## Working against the live service

The deployment is a single `scn-notes` process under systemd with Postgres,
behind a reverse proxy. Three listeners exist while the old hosts are still
served:

| Listener | Public host | Serves |
|---|---|---|
| `PUBLIC_BIND` (:7032) | `notes.` | `/mcp`, `/v1/sync`, `/v1/workspaces`, `/v1/documents/{id}/actors`, `/.well-known/oauth-protected-resource*`, `/health`. |
| `BIND` (:7030) | `sync.` (legacy) | `/` and `/sync` WebSockets, `/vaults`, `/internal/*`, `/.well-known/oauth-protected-resource`, `/health`. |
| `MCP_BIND` (:7031) | `mcp.` (legacy) | MCP at its configured path, plus its resource metadata. |

Members' clients should use the `notes.` host. The legacy sync and MCP listeners
retire in issue #19. `/internal/` is for Corliss on the internal network only.

The production MCP endpoint is `https://notes.sharedcomputer.network/mcp`.
Access is per member through Corliss OAuth; there is no shared token. In
OpenCode, authenticate the remote server with `opencode mcp auth scn-notes`
after it is configured. Tokens are personal: never commit, paste, or share
them, and never use another member's token to act as them.

## When in doubt

- Access-control change: write the negative test first.
- Wire or storage change: re-read the matching section of `README.md` and the
  spec, then update both if the contract changes.
- A change that only makes the code simpler but changes an audience, a path, a
  table, or a token claim is not a simplification; it is a compatibility
  decision. Ask.
