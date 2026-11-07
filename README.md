# scn-sync-relay

An Automerge sync relay for the Shared Computer Network. It speaks the
automerge-repo WebSocket protocol, so a standard `@automerge/automerge-repo`
client connects to it with nothing changed but a token in the URL, and it
persists documents to Postgres. It also serves those documents to MCP clients.

Built on [`samod`](https://crates.io/crates/samod), the Rust automerge-repo
implementation. A single static binary under systemd: no Node runtime, no
container.

## Status: Phase B

Every connection is authenticated as an SCN member and can open only that
member's own vaults and their workspaces' vaults.

- **Sign-in is Corliss's.** The relay accepts access tokens issued by
  [Corliss](https://github.com/Z-Space-Society/Corliss), the network's OAuth
  provider, and resolves each to the member's DID. Corliss re-checks
  membership every time it issues one and they last 15 minutes, so access
  stops within one token lifetime of leaving the network.
- **A vault belongs to one member or one workspace.** A vault is a tree of
  folder and note documents under a root. A member's own vault opens to them
  alone. A workspace's vault opens to every member whose token names that
  workspace. Workspaces are Corliss's: it puts the member's workspace IDs in
  each token it issues, so the relay holds no roster, and leaving a workspace
  takes effect within one token lifetime.
- **MCP is built in.** A second listener serves the member's notes to an MCP
  client, acting as that member, from the same documents sync uses.
- **Each change is traced to a member.** Automerge stamps every change with a
  random actor ID, and the JS client picks a new one each time it opens a
  note, so an actor is one note on one device for one session. The relay
  records which member each actor belongs to when its first new change
  arrives on that member's connection. A change under an actor another member
  owns is dropped. MCP edits are written under an actor of the member's own.
  History stored before v0.6.0 is mapped once at startup: a note's first
  change goes to whoever created it, and every change in a private vault to
  its owner.

What this does not do:

- **It does not unshare the past.** A former member, of the network or of a
  workspace, keeps whatever their devices already hold.
- **It is not live co-editing.** Members' edits merge as they sync, the same
  way one member's devices do. Two people rewriting one sentence at once get
  both sets of characters interleaved.
- **It is not end-to-end encrypted.** The relay, and so its operators, can
  read every note. Notes sit in plaintext in Postgres.
- **It cannot name every past author.** Edits made before v0.6.0 to workspace
  notes, other than each note's first change, stay unknown. Before v0.6.0 an
  MCP edit was written under the relay's actor for that note until the next
  restart, so when MCP created a note, other members' MCP edits to it in
  that time are traced to its creator. A note moved into a private vault from a workspace has its
  other members' earlier edits traced to the owner.

The design is in [`docs/specs/0001-spec-phase-b`](docs/specs/0001-spec-phase-b/0001-spec-phase-b.md).

## Configuration

All settings come from the environment; systemd loads them from an
`EnvironmentFile` written by Ansible.

| Variable | Default | Notes |
| --- | --- | --- |
| `SCN_SYNC_RELAY_DATABASE_URL` | *required* | No in-memory fallback: a relay that silently ran on memory would look healthy until its first restart. |
| `SCN_SYNC_RELAY_BIND` | `0.0.0.0:7030` | Sync and the vault endpoints. Bind a wildcard. Binding a literal container address loses a cold-boot race with `systemd-networkd` and comes up loopback-only. |
| `SCN_SYNC_RELAY_REQUIRE_AUTH` | `true` | Defaults on, so the safe posture is the one you get by forgetting. See "Running without auth". |
| `SCN_SYNC_RELAY_OIDC_ISSUER` | *required with auth* | The `iss` every token must carry: Corliss's public URL, no trailing slash. |
| `SCN_SYNC_RELAY_OIDC_JWKS_URL` | *required with auth* | Where to fetch Corliss's signing keys. Use its internal address. |
| `SCN_SYNC_RELAY_SYNC_AUDIENCE` | *required with auth* | The `aud` a sync token must carry: the public sync URL, spelled exactly as Corliss's `OIDC_RESOURCES` spells it. |
| `SCN_SYNC_RELAY_MCP_AUDIENCE` | *required with auth* | The `aud` an MCP token must carry: the public MCP URL, in lowercase with no trailing slash and no default port. Also the only `Host` the MCP service answers to, and its path is where the service is mounted. |
| `SCN_SYNC_RELAY_MCP_BIND` | `0.0.0.0:7031` | The MCP listener. |
| `SCN_SYNC_RELAY_SERVICE_TOKEN` | *required with auth* | The shared credential Corliss presents on `/internal/vaults`. |
| `RUST_LOG` | `scn_sync_relay=info,samod=info` | Standard `tracing` filter. |

With auth on and any of the required settings missing or blank, the relay
refuses to start and names the one it wants.

- **The two audiences must match Corliss character for character.** A token
  whose `aud` differs by a trailing slash is refused, and the only symptom is
  a `401`. Define each URL once in the deployment and render it to both
  services.
- **The JWKS is cached.** It is fetched at startup and again when a token
  names a key the relay has not seen, at most every 30 seconds. If Corliss is
  down when the relay starts, the relay starts anyway and refuses every token
  until a fetch succeeds.

### Running without auth

`SCN_SYNC_RELAY_REQUIRE_AUTH=false` runs the relay with no verifier and no
filter: any peer that can reach the port can sync any document it holds. It is
for local work and is only sound where the service has no route in. The MCP
service is not started in this mode, because there is no member for it to act
as.

## Endpoints

On the sync listener (`BIND`):

| Path | Caller | Purpose |
| --- | --- | --- |
| `GET /` | sync client | WebSocket upgrade; the automerge-repo sync protocol. **This is the one clients use**: `WebSocketClientAdapter` connects to exactly the URL it is given and appends no path, so clients are configured with a bare `wss://host`. |
| `GET /sync` | sync client | The same handler, for a client configured with an explicit path. |
| `GET /vaults` | member | The caller's private vault and their token's workspaces' vaults. Makes the private vault if they have none yet. Also answers `folders`, the groups vaults are listed under (`Private`, `Workspaces`), named even when empty. `Authorization: Bearer` with a sync token. |
| `GET /internal/vaults?did=&workspaces=` | Corliss | A member's private vault, plus the vaults of the comma-separated workspace IDs. Makes the private vault if they have none yet. `Authorization: Bearer` with the service token. |
| `PUT /internal/vaults/workspace` | Corliss | A workspace's vault: `{"did", "workspace", "name"}`, `did` being the member asking. Made if the workspace has none, and given `name` either way, so the same call serves the workspace's page, its creation and its rename. Returns `200` and the vault. |
| `GET /internal/vaults/all` | Corliss | Every vault with the DID that made it, and per creator the documents no vault reaches. For Corliss's admin view. Takes no parameters. `Authorization: Bearer` with the service token. |
| `GET /.well-known/oauth-protected-resource` | anyone | Which authorization server issues sync tokens: `resource` is `SYNC_AUDIENCE`, `authorization_servers` is the issuer. A sync client given only the sync URL finds Corliss here. Not served with auth off. |
| `GET /health` | anyone | Liveness and the current auth mode. Does not touch Postgres, so a database blip cannot get the relay restarted out from under live connections. |

On the MCP listener (`MCP_BIND`):

| Path | Purpose |
| --- | --- |
| `POST <MCP path>` | MCP over Streamable HTTP. `Authorization: Bearer` with an MCP token. |
| `GET /.well-known/oauth-protected-resource<MCP path>` | Which authorization server issues tokens for this resource. Unauthenticated; it is how an MCP client finds Corliss. |

Things the proxy in front has to get right:

- **Do not route `/internal/`.** Those endpoints are for Corliss on the
  internal network. The service token is the only thing guarding them.
- **Do not log query strings on the sync route.** A browser or phone
  websocket cannot send an `Authorization` header, so a sync client connects
  to `wss://host/?access_token=<token>`. The relay never logs it.

### Sync

A connection with no token, or an expired or wrong-audience one, gets `401`
before the upgrade. Once connected:

- A request for a document the member may not open is answered with
  `doc-unavailable`, the same answer a document that does not exist gets.
- A request from a workspace member for a document someone else has just
  linked into a vault waits up to 3 seconds for the relay to admit it, rather
  than being refused while the relay catches up. A refusal would stick until
  the client reconnected.
- The relay never offers a document unasked. A client requests the documents
  its folder documents list, on every connection.
- The connection is closed with code `1008` and reason `token expired` when
  its token's `exp` passes. The client reconnects with a fresh token.

### Vaults

A vault is one JSON object:

```json
{
  "root_doc_id": "<document ID>",
  "url": "automerge:<document ID>",
  "name": "<the workspace's name, or null for a member's private vault>",
  "workspace": "<workspace ID, or null for a member's private vault>",
  "path": "<Private, or Workspaces/<name>>",
  "created_at": "<RFC 3339 timestamp>",
  "last_change_at": "<RFC 3339 timestamp, or null>",
  "note_count": "<integer, or null>",
  "bytes": "<integer, or null>"
}
```

`note_count` and `bytes` are null until the relay has walked the vault
since it started, and `bytes` is filled in by the listing endpoints only:
the MCP tools list vaults on every call and do not pay for the query. It is
the bytes the vault's documents take in storage, which is their Automerge
history. It grows with every edit and reads larger than the notes as files.

Listings return `{"vaults": [...]}`, oldest first. Errors on the internal
endpoints are `{"error": "<code>"}`: `400` with `invalid_did`,
`invalid_name` or `invalid_workspace`. A member has one private vault, which
has no name. A workspace has one vault, named 1 to 100 characters.

`path` is `Private` for a member's private vault, and the name under
`Workspaces` for a workspace's. The
relay is the only place those words are spelled: MCP names vaults by `path`,
the Obsidian plugin puts each vault in a folder at its `path`, and Corliss shows
it. A client builds none of it.

In a token, workspaces are the `workspaces` claim, an array of workspace
IDs such as `["7", "12"]`. A token without it is in no workspace. An ID is 1
to 64 ASCII letters, digits, `-` and `_`, and is opaque on purpose: a sync
client sends its token in a websocket URL, so the token names no workspace in
words. A workspace's vault carries the workspace's name, which Corliss sends
with every `PUT /internal/vaults/workspace`, a rename included.

**Admission.** A document joins a vault only if the vault admits its
creator: for a member's vault, the member made it; for a workspace's, its
creator's token named the workspace when they first sent it. So a member
cannot pull someone else's document into a vault by writing its URL into a
folder, and a note stays in a workspace's vault after its author leaves.

Vaults are made by the relay and nowhere else: a member's private vault the
first time any listing asks for it, a workspace's the first time Corliss asks
for it. The relay sees workspace IDs only, never names, which is why a
workspace's vault waits for Corliss. No sync client makes one.

From v0.5.0 a member has one private vault. At startup the relay clears the
names private vaults carried before, and makes one unique per member. If a
member has two, startup fails rather than merge them silently.

**The admin listing.** `GET /internal/vaults/all` answers:

```json
{
  "vaults": [{ "owner_did": "<DID>", "...": "a vault, as above" }],
  "unfiled": [{ "did": "<DID>", "docs": 3, "bytes": 1234 }]
}
```

- **It takes no parameters, on purpose.** The other listings name a member,
  and a request choosing whose vaults it gets is the thing Corliss guards
  against. This one has nothing to choose: it is everyone's or a `401`. A
  query string is ignored rather than read. Who may see the answer is
  Corliss's question, asked by the admin gate on the one page that calls it.
- **Counts and sizes, never titles or text.** It walks no folder for names
  and reads no note. Seeing what members have stored is a different
  decision from seeing what they wrote.
- **`owner_did` is here and in no member's listing.** For a workspace's vault
  it is the member who made it, which the workspace's other members have no
  need to learn.
- **`unfiled` is each creator's documents that no vault reaches**, by
  `doc_creators`: deleted entries, a move cut off part way, a note whose
  folder never arrived, and entries of a type the relay does not index. With
  the vaults' `bytes`, it adds up to what each member holds in storage. It is
  `null` until every vault has been walked since startup, because until then
  an unwalked vault's notes would be counted as unfiled.
- **It runs the size query over every vault and every unfiled document.**
  That is fine at today's size, and it is what to revisit if the admin page
  gets slow.

**Filing a member's unfiled documents.** `scn-sync-relay file-unfiled <did>
[--folder <name>] [--apply | --delete]` lists the documents of `<did>` that no vault
reaches. With `--apply`, it links them into a new folder (`Recovered` unless
named) at the root of that member's private vault, where they appear on every
device. With `--delete`, it removes them instead, each with everything it
holds: their stored history and their creator rows, in one transaction, after
checking again that each is still the member's and in no vault.

- **Run it with the service stopped**, with the service's environment, so
  that nothing else writes the vault's root folder at the same time. It waits
  for the index to walk every vault, and exits once the folder is written.
- **It reads what the admin listing does not**: each note's name and first
  line, and each folder's title. Run it for a member who asked, and show the
  list to them.
- **Only the top of each tree is filed.** A deleted folder comes back whole
  with its notes inside it, and its notes are not filed a second time. Two
  entries with one name get the plugin's conflict name. Documents that are
  neither notes nor folders are listed and left where they are.
- **It refuses rather than guesses** when the vault already has an entry
  with the folder's name.

### MCP tools

Every tool acts as the member the token names, in the workspaces it names.
A tool's `vault` argument is `Private` or `Workspaces/<name>`, as
`list_vaults` gives it, or a workspace's bare name. Left out, it is the
caller's private vault, which every member has. Two workspaces sharing a name
are refused rather than guessed between.

| Tool | Does |
| --- | --- |
| `list_vaults` | The caller's vaults in two groups, `Private` and `Workspaces` |
| `list_notes` | Notes and folders in a vault or one of its folders |
| `read_note` | A note's markdown |
| `search_notes` | Notes containing every word of a query |
| `create_note` | A new note at a path, with any folders on the way |
| `edit_note` | Replace one piece of a note's text with another |
| `append_note` | Add text to the end of a note |

The service is stateless: no session is issued and each request carries its
own token, so a relay restart needs nothing from the client. There is no tool
to delete a note.

## Storage

Three tables, created at startup. The deployment provisions the database and
its owning role, not the schema.

```sql
CREATE TABLE storage (key TEXT PRIMARY KEY, value BYTEA NOT NULL);
CREATE INDEX storage_key_prefix ON storage (key text_pattern_ops);

CREATE TABLE vaults (
  root_doc_id    TEXT PRIMARY KEY,
  owner_did      TEXT NOT NULL,
  name           TEXT NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_change_at TIMESTAMPTZ,
  workspace_id   TEXT
);
CREATE UNIQUE INDEX vaults_member_name ON vaults (owner_did, lower(name))
  WHERE workspace_id IS NULL;
CREATE UNIQUE INDEX vaults_workspace ON vaults (workspace_id)
  WHERE workspace_id IS NOT NULL;

CREATE TABLE doc_creators (
  doc_id      TEXT PRIMARY KEY,
  creator_did TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  workspaces  TEXT[] NOT NULL DEFAULT '{}'
);
```

`storage` holds the documents. `vaults` names each vault's creator, its
workspace if it has one, and its root document. A relay before v0.4.0 is
brought up to this shape at startup: the two columns are added and the old
`vaults_owner_name` index is replaced. `doc_creators` records who first sent
each document and the workspaces their token named then, and is what decides
ownership: losing it loses every member's access to their own notes,
so it is as much the store of record as `storage` is.

samod's `StorageKey` guarantees no component contains a `/`, so a key round
trips as `Display` out and `split('/')` back, with no escaping.

`text_pattern_ops` is load-bearing: the default opclass follows the database
collation and will not serve a `LIKE 'prefix%'` scan, which would quietly turn
every range read into a full scan of a table that only grows.

### Inspecting storage

A vault's `bytes` is the one per-vault figure: only the relay's index knows
which documents a vault holds, so SQL alone cannot split `storage` by vault.
`GET /internal/vaults/all` gives it for every vault, with each member's
unfiled documents beside it. These answer the rest, in `psql` against the
relay's database.

```sql
-- The database and the storage table, on disk.
SELECT pg_size_pretty(pg_database_size(current_database())),
       pg_size_pretty(pg_total_relation_size('storage'));

-- Snapshot and incremental rows: many incrementals means not yet compacted.
SELECT split_part(key, '/', 2) AS kind, count(*),
       pg_size_pretty(sum(octet_length(value)))
FROM storage GROUP BY 1;

-- Documents nobody is recorded as sending: open to nobody, in no vault.
-- This is how leftovers get spotted.
SELECT split_part(key, '/', 1) AS doc, sum(octet_length(value)) AS bytes
FROM storage
WHERE split_part(key, '/', 1) NOT IN (SELECT doc_id FROM doc_creators)
GROUP BY 1 ORDER BY 2 DESC;
```

## Building

```sh
cargo build --release
```

`Cargo.lock` and `rust-toolchain.toml` are committed, so two builds months
apart produce the same binary from the same contents. Build against the
target's glibc — building on macOS would need a cross-compile or a static musl
target.

## Testing

```sh
DATABASE_URL=postgres://localhost/postgres cargo test
```

Most tests need a Postgres server. `DATABASE_URL` names any database on it
that the user may create databases from: each test gets a database of its own
and drops it when it passes.

## Releasing

Deployment checks out an **annotated tag**, so the tag has to reach the remote:

```sh
git tag -a v0.1.0 -m "v0.1.0"
git push origin main --follow-tags
git ls-remote --tags origin       # the check that matters
```

A tag that exists only locally fails at checkout with `pathspec 'v0.1.0' did
not match`, which reads like a bad version pin rather than an unpushed tag.

## License

Apache-2.0.
