# 0002 Spec: Attachment storage

Status: Draft for review, 2026-11-10 (quill); revised 2026-11-23 (Jacob)

Decision record:
[0001-postgres-for-attachments](../../decisions/0001-postgres-for-attachments.md)

Related:

- [scn-notes#11](https://github.com/Z-Space-Society/scn-notes/issues/11) — attachment storage in Postgres, HTTP upload/download
- [scn-obsidian#37](https://github.com/Z-Space-Society/scn-obsidian/issues/37) — attachments as real files on disk, hash-verified cache
- [scn-notes#12](https://github.com/Z-Space-Society/scn-notes/issues/12) — full-text search, extraction and attachment text
- [scn-obsidian#27](https://github.com/Z-Space-Society/scn-obsidian/issues/27) — one host, versioned paths and the release sequence

## Goal

A member can put a file or an image in a workspace, see it in every device's
Obsidian folder tree, and read it back from another device or from an MCP client.
The bytes live in the relay's Postgres, behind the same Corliss token and
workspace authorization as notes. Bytes never travel over the Automerge socket.

v1 is one workspace's files: upload, download, metadata in the folder tree, and
read access over MCP. It is not a general file host, a CDN, or an object-store
replacement.

## Non-goals

- **Garage/S3.** The estate has an object store; v1 does not use it. See the
  decision record.
- **Encryption at rest.** Attachments are not encrypted at rest, as notes are
  not.
- **OCR, PDF thumbnails, server-side rendering.** A PDF is bytes; text is a
  later extraction job.
- **Global dedupe.** Dedupe is per workspace in v1. The same bytes in two
  workspaces are stored twice.
- **A delete route.** Removing a file's folder entry is the delete. The relay
  removes bytes that no folder entry in the workspace has named for the grace
  period (see [Unreferenced bytes](#unreferenced-bytes)).
- **Range requests and conditional GET.** The plugin writes whole files to disk
  and Obsidian reads them there, and the plugin compares hashes, so it never
  re-fetches bytes it holds.
- **A public or signed URL.** Every byte route requires the member's token.
- **Binary Automerge documents.** `.canvas` and `.base` are text-only in the
  plugin and are out of scope here.
- **A general MCP upload tool.** The plugin uploads over HTTP; MCP is read-only
  for attachments in v1.

## Current state

- The relay models a workspace as a tree of folder and note documents. A folder
  entry is `{"name", "type", "url"}`; `type` is `folder` or a file extension,
  and the relay acts only on `folder` and `md`.
- `src/reach.rs` ignores every other entry: it does not walk it, list it, count
  it as a note, search it, or admit it to the workspace's reachable set.
- A workspace is a row in `workspaces` keyed by `root_doc_id TEXT`, with
  `owner_did` and an optional `group_id`. There is no `vaults(id) uuid`;
  Automerge document IDs are text.
- The `notes.` host serves `/v1/sync`, `/v1/workspaces`,
  `/v1/documents/{id}/actors`, `/mcp` and `/health`. The plugin's token has the
  public notes URL as its audience; MCP's has the same URL with `/mcp`.
- The plugin's `src/vaultfiles.ts` syncs `.md` only. There is no binary path.
- MCP tools take one path starting with `Private` or `Workspaces/<name>`, and
  resolve it by walking folder documents at call time.

The original issue #11 schema used `vaults(id) uuid`. The v0.7.0 update on the
issue replaces that with the workspace root document ID; this spec follows the
update.

## Decisions

| Date | Decision | Who | Where |
|---|---|---|---|
| 2026-11-06 | Attachment bytes live in Postgres, not Garage, in v1. | Boris, quill | [ADR 0001](../../decisions/0001-postgres-for-attachments.md) |
| 2026-11-06 | Bytes are immutable and content-addressed by SHA-256; a new version is a new hash. | Boris, quill | issue #11 |
| 2026-11-06 | Dedupe is per workspace, not global. | Boris, quill | issue #11 |
| 2026-11-09 | "Vault" becomes "workspace"; the workspace ID is `root_doc_id TEXT`; member HTTP routes are under `/v1/` on the `notes.` host; MCP tools take one path. | Jacob | issue #11 update, scn-obsidian#27 |
| 2026-11-10 | No surrogate `uuid` for an attachment. The identity is `(workspace_root_doc_id, sha256)`, which is the content address and the dedupe key. | quill | this spec |
| 2026-11-10 | The folder entry carries `size` and `mime` as additive fields; the relay ignores them and the plugin uses them to decide whether to fetch eagerly. | quill | this spec |
| 2026-11-23 | An upload is staged to a temporary file while it is hashed, then written in one transaction. A row exists only once its bytes are verified; there is no `pending` or `failed` state. | Jacob | this spec |
| 2026-11-23 | No delete route. The relay removes bytes no folder entry has named for 30 days; `unreferenced_since` replaces `deleted_at`. | Jacob | this spec |
| 2026-11-23 | No `Range`, `ETag` or `If-None-Match` in v1. | Jacob | this spec |

## Storage

Two tables beside `storage`, created at startup with the rest of the schema.
Names follow the current code, not the issue's pre-v0.7.0 names.

```sql
CREATE TABLE attachments (
  workspace_root_doc_id TEXT NOT NULL
    REFERENCES workspaces (root_doc_id) ON DELETE CASCADE,
  sha256                BYTEA NOT NULL,
  content_type          TEXT NOT NULL,
  size                  BIGINT NOT NULL,
  chunk_size            INT NOT NULL DEFAULT 1048576,
  text_content          TEXT,
  description           TEXT,
  extractor             TEXT,
  extracted_at          TIMESTAMPTZ,
  created_by            TEXT NOT NULL,          -- DID
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  unreferenced_since    TIMESTAMPTZ,
  PRIMARY KEY (workspace_root_doc_id, sha256),
  CONSTRAINT attachments_sha256_len
    CHECK (octet_length(sha256) = 32),
  CONSTRAINT attachments_size_nonnegative
    CHECK (size >= 0),
  CONSTRAINT attachments_chunk_size_positive
    CHECK (chunk_size > 0),
  CONSTRAINT attachments_content_type_present
    CHECK (content_type <> '')
);

CREATE INDEX attachments_workspace_created
  ON attachments (workspace_root_doc_id, created_at);

CREATE INDEX attachments_unreferenced
  ON attachments (unreferenced_since)
  WHERE unreferenced_since IS NOT NULL;

CREATE TABLE attachment_chunks (
  workspace_root_doc_id TEXT NOT NULL,
  sha256                BYTEA NOT NULL,
  chunk_no              INT NOT NULL,
  data                  BYTEA NOT NULL,
  PRIMARY KEY (workspace_root_doc_id, sha256, chunk_no),
  FOREIGN KEY (workspace_root_doc_id, sha256)
    REFERENCES attachments (workspace_root_doc_id, sha256)
    ON DELETE CASCADE,
  CONSTRAINT attachment_chunks_no_nonnegative CHECK (chunk_no >= 0)
);

ALTER TABLE attachment_chunks
  ALTER COLUMN data SET STORAGE EXTERNAL;
```

- **Why no `id uuid`.** The content address is the identity. A surrogate ID
  would let two rows name the same bytes, which is the duplication dedupe exists
  to prevent, and it would add a UUID generator (or the `uuid` crate) for a value
  nobody outside the database needs. The URL uses the hex hash; the database uses
  `BYTEA` and `decode($1, 'hex')` at the boundary.
- **1 MiB chunks.** Large enough to keep the row count and the per-row overhead
  down, small enough that a download streams one row at a time. `chunk_size` is
  stored per attachment so a later change can be a new value, not a migration of
  old rows.
- **`STORAGE EXTERNAL`.** Image and PDF bytes are already compressed. Letting
  Postgres try to compress a 1 MiB chunk wastes CPU and can make it larger.
  TOAST still moves large values out of the main heap; this only turns off the
  compression attempt.
- **Chunks are immutable.** No update path. A change to the file is a new hash,
  a new row and a new folder entry. That is what makes a cache, a grace window
  and a future version history tractable.
- **A row means verified bytes.** The row and every chunk are inserted in one
  transaction, after the upload's hash has been checked (see
  [Upload](#upload)). There is no partial state: a row that exists is complete
  and downloadable. Nothing a failed or abandoned upload did is ever visible.
- **Dedupe.** `(workspace_root_doc_id, sha256)` is unique. An upload checks
  for the row first and returns `200` with its metadata. Two uploads of the same
  hash that both get as far as the insert are settled by the primary key: the
  second insert waits on the first transaction, finds the row, writes nothing
  and returns `200`.
- **Quota.** The workspace's `size` values sum to its attachment bytes. Every
  row counts, including one in its grace window, so bytes uploaded and never
  named in a folder cannot sidestep the quota. The sum is checked against a
  configurable quota before the body is read and again before the insert. A
  race can overshoot by one file; that is acceptable for v1 and is why the quota
  is a guardrail, not a security boundary.
- **No path column.** A path is a position in a folder document, not a property
  of the bytes. A rename or a move changes the entry only; the attachment row and
  its chunks do not move. The same hash can be linked from two folders in one
  workspace, and both entries show it.
- **`unreferenced_since`.** When the relay first saw that no folder entry in
  the workspace names this hash, or null while one does. It is written by the
  GC, never by a client. A row with it set is still downloadable, so a file
  put back from Obsidian's trash or a folder's history within the grace period
  still opens. See [Unreferenced bytes](#unreferenced-bytes).
- **Text fields.** `text_content`, `description`, `extractor` and `extracted_at`
  are the contract with the search/extraction work in #12. v1 leaves them null;
  `get_attachment_text` reports that no text has been extracted yet.

### Accounting in the workspace listing

`Workspace` already carries `bytes` (Automerge history, filled only by the
listing endpoints through `add_sizes`) and `note_count`. Attachments are a second
kind of bytes. Add two fields, filled by the same `add_sizes` path so the MCP
tools do not pay for the query:

- `attachment_bytes: Option<i64>`: the sum of `size`, the figure the quota
  checks.
- `attachment_count: Option<i64>`: the number of rows.

`bytes` stays exactly what it is today: the storage the workspace's Automerge
documents take. Adding attachment bytes into it would make the figure mean two
different things and would silently change a number Corliss shows. The listing
shows both, and the quota uses `attachment_bytes`.

A single query per listed workspace is enough:

```sql
SELECT COALESCE(SUM(size), 0)::BIGINT, COUNT(*)::BIGINT
FROM attachments
WHERE workspace_root_doc_id = $1;
```

If the admin listing later needs the same figure, it uses the same query. It
must never select `text_content`, `description` or chunk bytes: the admin view
is counts and sizes, not content.

## Folder entry

An attachment is an entry in a folder document, in the same `docs` list as
folders and notes:

```json
{
  "name": "diagram.png",
  "type": "png",
  "url": "attachment:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "size": 184320,
  "mime": "image/png"
}
```

- **`url` is `attachment:<sha256 hex>`.** The hex is 64 lowercase characters.
  It is the canonical content address. It is not an `automerge:` URL, so
  `Entry::doc_id()` returns `None` and the reachability index ignores the entry.
  That is intended: the bytes are not an Automerge document and must not be
  admitted to the workspace's reachable set.
- **`type` is the extension**, as it is for a note (`md`). A file with no
  extension is `type: "file"`. The relay's walk already ignores anything that is
  not `folder` or `md`, so it needs no change to skip attachments.
- **`size` and `mime` are additive.** Older relay code and older plugins ignore
  them. The plugin uses them to decide whether to fetch eagerly (below the
  threshold) or on demand, and to show a placeholder with the right icon. They
  are hints, never authority: the HTTP response's `Content-Length` and
  `Content-Type` are what the client verifies against.
- **`name` is the human name.** A rename changes `name` only. The hash, the
  bytes and the URL stay. Two entries with the same name follow the existing
  rule: the one whose `url` sorts lowest is the one the path names; clients
  rename the other.
- **Where the file lives is a plugin decision, not a relay rule.** The plugin's
  convention is `<workspace>/Attachments/`, so `Private/Attachments/` and
  `Workspaces/<name>/Attachments/`. The relay only knows that the entry is in
  some folder; it does not create an `Attachments` folder, require one, or
  enforce a location.
- **A note is still a note.** A file whose extension is `md` is a note document,
  not an attachment. A binary file named `.md` is a client problem; the plugin
  must not write one.
- **Compatibility.** The plugin that implements #37 writes the entry and the bytes. Older
  plugins see an entry they do not understand; they must leave it alone, not
  delete it. The relay ignores it. This is additive to the folder shape and does
  not need a `/v2/`.

## Unreferenced bytes

There is no delete route. A file is deleted by removing its folder entry, which
is what the plugin already does for a note. The relay removes the bytes once no
entry in the workspace has named them for a grace period of 30 days.

- **The walk collects hashes.** `src/reach.rs` already reads every entry of
  every folder it admits. While it skips non-`folder`/`md` entries for
  reachability, it also collects the hash from each `attachment:` URL into the
  workspace's set of referenced attachments. The set is kept only from a
  complete walk: every folder loaded and no link still waiting for its
  creator. Any other walk keeps the previous set, and a workspace that has not
  been walked since startup has none.
- **Why the derived index may drive a delete.** The index is never authority
  for access, and this does not make it so. It only sets a mark; a row is
  removed only if no complete walk in 30 days found an entry naming it, and
  the walk reads the folder documents themselves. One wrong walk costs
  nothing, because the next complete walk that sees the entry clears the mark.
- **The GC marks, then removes.** At startup and hourly, for each workspace
  with a referenced set:
  - set `unreferenced_since = now()` on rows whose hash is not in the set and
    whose `unreferenced_since` is null;
  - clear `unreferenced_since` on rows whose hash is in the set again;
  - delete rows whose `unreferenced_since` is older than 30 days. Chunks
    cascade.
  A workspace without a referenced set is skipped, so a relay that has just
  started, or a folder that will not load, never makes bytes look unreferenced.
- **The grace period is the trash.** Obsidian's trash, an undo, or a folder
  restored from history can put an entry back within 30 days, and the bytes are
  still there. After that, an entry pointing at a removed hash is a `404`; a
  plugin that still has the file uploads it again.
- **It also cleans up after interruptions.** Bytes uploaded whose folder entry
  was never written are unreferenced from the first pass and go after the
  grace period.
- **References are per workspace.** An entry in another workspace does not keep
  a row alive, because a hash in another workspace is not readable from this
  one. Moving a file between workspaces is an upload to the new one.
- The grace period is a constant, like the chunk size. Rows in their grace
  period count against the quota until they are removed.

## HTTP API

Three routes on the `notes.` listener, beside `/v1/workspaces`:

| Route | Does |
|---|---|
| `POST /v1/workspaces/{root_doc_id}/attachments` | Stream a body, verify its hash, store the chunks, return metadata. |
| `HEAD /v1/workspaces/{root_doc_id}/attachments/{sha256}` | Existence and dedupe check. |
| `GET /v1/workspaces/{root_doc_id}/attachments/{sha256}` | Stream the bytes. |

`{root_doc_id}` is the workspace's root Automerge document ID from
`GET /v1/workspaces`, never Corliss's group number and never a workspace name.
`{sha256}` is the lowercase hex digest.

### Authentication and authorization

- `Authorization: Bearer <token>`, with the same token and audience as
  `/v1/sync` and `/v1/workspaces` (`PUBLIC_URL`). No token in the query string:
  these are ordinary HTTP requests, not a browser WebSocket.
- The handler loads the workspace row by `root_doc_id` and builds a
  `Holder::Member(owner_did)` or `Holder::Group(group_id)`. It calls
  `Holder::opens_to(&caller)`. A workspace that does not exist and a workspace
  the caller may not open are both `404`, the same answer a denied note gets.
- **Do not authorize from the reachability index.** The index is derived and
  eventually consistent; an empty workspace just after startup is the case that
  gets it wrong. The `workspaces` row is the authority for "who holds this
  workspace", and it is one indexed lookup.
- The token's `groups` claim is Corliss's roster at issue time. A member removed
  from a group keeps access until the token is renewed, exactly as sync does.
- There is no cross-workspace route. Every query joins or filters on
  `workspace_root_doc_id`; a hash in another workspace is `404`, not a redirect.
- Corliss does not get a service route for attachment bytes. The admin listing
  gets counts and sizes only.

### Upload

```http
POST /v1/workspaces/{root_doc_id}/attachments
Authorization: Bearer <token>
Content-Type: image/png
X-Content-SHA256: <64 lowercase hex characters>
Content-Length: 184320
```

- **Required headers.** `Content-Type` (stored; bounded to a sane length) and
  `X-Content-SHA256` (64 lowercase hex characters). A missing or malformed hash
  is `400 invalid_sha256`; a missing content type is `400 missing_content_type`.
- **Stage, then write.** Stream the body to a temporary file on the relay's
  disk, hashing every byte as it arrives. Never hold the whole file in memory,
  and hold no database connection while a slow client is still sending.
- **Verify, never trust.** The header is a hint for the dedupe check. The server
  compares the hash of what it staged. A mismatch is `422 hash_mismatch`; the
  temporary file is removed and nothing reaches the database.
- **One transaction.** Once the hash matches, insert the row and every chunk,
  read back from the temporary file in 1 MiB pieces, in one short transaction,
  then remove the file. An interrupted upload, a mismatch or a crash leaves no
  row and no chunks; a stale temporary file is removed at startup.
- **Dedupe.** If the row for `(workspace, hash)` exists, return `200` with its
  metadata and do not read the body. The plugin should `HEAD` first for large
  files; a client that goes straight to `POST` must tolerate an early response.
  Two uploads of the same hash at once both stage; the second insert finds the
  first's row and returns `200`.
- **Size.** `Content-Length`, when present, is checked against the per-file cap
  before reading. When absent, the handler counts and stops at the cap. A body
  over the cap is `413 too_large`.
- **Quota.** After dedupe, and again before the insert, sum the workspace's
  rows. If adding this file would exceed the workspace quota, return
  `413 quota_exceeded`. The staging step stops at the per-file cap, so a
  missing `Content-Length` cannot stage more than one file's worth.
- **Response.**
  - `201 Created` when this request stored the bytes.
  - `200 OK` when the hash was already complete.
  - Body:

    ```json
    {
      "sha256": "<64 hex>",
      "size": 184320,
      "content_type": "image/png",
      "workspace_root_doc_id": "<root doc id>",
      "url": "attachment:<64 hex>",
      "existing": false
    }
    ```

    `existing` is `true` for the dedupe answer. The plugin does not need it to
    decide anything; it is there so a log or a test can tell the two apart.
- **No filename in the request.** The name is the folder entry's `name`. The
  upload route stores bytes and metadata; the plugin writes the entry after the
  upload succeeds. If the entry write fails, the bytes are unreferenced and go
  after the grace period; that is cheaper than a two-phase commit across HTTP
  and Automerge.

### Download

```http
GET /v1/workspaces/{root_doc_id}/attachments/{sha256}
Authorization: Bearer <token>
```

- **Any row.** A hash with no row is `404`, as is a workspace the caller
  cannot open. A row in its grace period is served.
- **Headers.**
  - `Content-Type` from the row.
  - `Content-Length` from the row.
  - `Cache-Control: private, max-age=31536000, immutable`, because the bytes
    behind a hash never change.
  - `X-Content-Type-Options: nosniff`.
  - `Content-Security-Policy: default-src 'none'; sandbox` — an uploaded SVG or
    HTML file must not run script if a browser opens the URL.
- **No `Range` or conditional GET.** A `Range` header is ignored and the whole
  file is sent with `200`; `If-None-Match` is ignored. The plugin writes whole
  files to disk, Obsidian's viewers read the local file, and the plugin never
  fetches a hash it already holds. Either is additive later if a client needs
  it.
- **Zero-length file.** A `200` with `Content-Length: 0`.
- **Streaming.** The body is a stream of chunk rows in order, not a `Vec` of the
  whole file. A 50 MiB file must not become 50 MiB of heap per download.
- **No `Content-Disposition`.** The row has no filename; the plugin knows the
  name from the folder entry and writes the file itself. A browser opening the
  URL sees an opaque hash, which is acceptable.

### HEAD

`HEAD` on the download path returns the same status and headers as `GET`, with
no body. It is the plugin's cheap duplicate check before an upload: `200` means
the bytes are already there; `404` means upload.

### Errors

Errors use the existing shape, `{"error": "<code>"}`, with stable snake_case
codes:

| Status | Code | When |
|---|---|---|
| 400 | `invalid_workspace` | The root ID is not a document ID. |
| 400 | `invalid_sha256` | The hash is not 64 lowercase hex characters. |
| 400 | `missing_content_type` | No `Content-Type` on an upload. |
| 401 | — | No token, or a token for another audience. |
| 404 | — | Workspace not open, or attachment not found. |
| 413 | `too_large` | Over the per-file cap. |
| 413 | `quota_exceeded` | Over the workspace quota. |
| 422 | `hash_mismatch` | The streamed bytes do not match `X-Content-SHA256`. |
| 500 | `internal` | A storage failure. The reason is logged, not returned. |

A denied workspace and a missing workspace are the same `404`, the same way a
denied document and a missing document are the same `doc-unavailable` on sync.

## MCP

Two read-only tools, in a new `src/mcp/attachments.rs` and registered in
`src/mcp/tools.rs`. They act as the member the token names, in the groups it
names, like every other tool.

### `read_attachment`

Takes one path, the same path the folder entry has:
`Workspaces/Garden/Attachments/diagram.png`.

- Resolve the path through the folder documents exactly as `read_note` does:
  `Notes::locate` picks the workspace, then a new folder walk finds the final
  entry whatever its `type`. The existing duplicate-name rule applies.
- The entry's `url` must start with `attachment:` and the hash must be valid.
  An `md` entry is not an attachment; a folder is not a file.
- Load the attachment row by `(located.root, hash)`. If it is missing, return
  a tool error that says so, not a 500.
- **Images up to the MCP image cap** (`SCN_NOTES_MCP_IMAGE_MAX_BYTES`, proposed
  4 MiB) are returned as MCP `image` content: base64 data and the stored
  `mimeType`. This is what lets an agent see a diagram without a second
  protocol.
- **Everything else** — a larger image, a PDF, a zip — is returned as an MCP
  `resource_link` with the canonical HTTP URL, `name`, `mimeType` and `size`,
  plus a text note that `get_attachment_text` has the words. The link requires
  the member's token; a client that only has the MCP token may not be able to
  fetch it. That is a known v1 limitation, not a promise of an unauthenticated
  URL. If the client needs the bytes, the plugin is the path.
- Never return another workspace's bytes. The row's
  `workspace_root_doc_id` must equal the located workspace's root. A folder
  entry that points at a hash from another workspace is refused, the same way a
  folder link to someone else's note is refused by the admission rule.

### `get_attachment_text`

Takes the same path and returns the extracted text and description:

```json
{
  "path": "Workspaces/Garden/Attachments/scan.pdf",
  "sha256": "<64 hex>",
  "content_type": "application/pdf",
  "text": "…",
  "description": "A scanned page of the seed inventory.",
  "extractor": "pdf-extract",
  "extracted_at": "2026-11-12T09:00:00Z"
}
```

- If `text_content` and `description` are both null, return a successful tool
  result that says no text has been extracted yet, with the extractor state. It
  is not an error: the file is there, extraction has not run.
- Extraction is not part of this spec. The columns and the tool contract are.
  The work is in #12, and the extractor sets `extractor`, `extracted_at` and
  `text_content`/`description` when it runs.
- The same authorization and path checks as `read_attachment`.

### `list_notes`

Unchanged in v1. It lists notes and folders, not attachments. The plugin sees
attachment entries in the folder documents it already syncs, and an agent that
knows the path can read one. Whether `list_notes` should gain attachments (and
with what `type` value) is an open question; adding them is additive to the
tool's JSON, but it changes what a client thinks a "note" is.

## Ops

- **Backups.** The cluster's Postgres backup is a daily, cluster-wide
  `pg_dumpall` streamed into restic. A dump writes `bytea` as hex text, about
  twice the stored size, and dumps every byte on every run; restic's
  deduplication keeps the repository's growth near the change, but the dump's
  duration and transfer grow with the total. Before enabling uploads in
  production, measure the current dump's duration and size and project them
  with the proposed quota across the expected workspaces; if the daily window
  does not fit, lower the quota or move to an object store. This is the cost the
  ADR accepted.
- **WAL.** Each upload writes its bytes to WAL once. There is no WAL archiving
  in the backup tier, so this is disk churn on the Postgres host, not backup
  size.
- **TOAST and bloat.** Chunks are 1 MiB values, so Postgres TOASTs them into the
  toast table. `SET STORAGE EXTERNAL` turns off compression, not TOAST. Deleted
  chunks leave dead tuples; autovacuum handles them, and `pg_repack` or a
  partition swap is the escape hatch if a large delete leaves a table bloated.
  Partitioning `attachment_chunks` by workspace or month is the later move
  suggested in the issue; v1 does not do it.
- **GC.** The background task in [Unreferenced bytes](#unreferenced-bytes),
  at startup and hourly. It also removes temporary upload files left by a
  crash. It uses the existing `Authz` pool and logs counts, not file names.
- **Metrics to watch.** Database and toast table size
  (`pg_total_relation_size('attachments')`,
  `pg_total_relation_size('attachment_chunks')`), WAL generation, `pg_dumpall`
  duration, upload/download latency, 413/422 counts, and rows marked and
  removed by the GC.
- **The admin listing** gets `attachment_bytes` and `attachment_count` with the
  workspaces, never text or bytes. It runs one aggregate per workspace, like the
  existing `bytes` query. The same "counts and sizes, never titles or text" rule
  applies.
- **No new backup story.** The database is already backed up; attachments ride
  with it. There is no separate object-store bucket to back up, which is part of
  why v1 chose Postgres.

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `SCN_NOTES_ATTACHMENT_MAX_BYTES` | `52428800` (50 MiB) | Per file. `0` disables uploads, not reads. Proposed; confirm in review. |
| `SCN_NOTES_ATTACHMENT_WORKSPACE_QUOTA_BYTES` | `2147483648` (2 GiB) | Sum of every row per workspace, including rows in their grace period. Proposed; confirm in review. |
| `SCN_NOTES_MCP_IMAGE_MAX_BYTES` | `4194304` (4 MiB) | Larger images become a resource link. |
| `SCN_NOTES_ATTACHMENTS_ENABLED` | `false` | Serves the routes only when true. Lets the schema ship before the plugin. |

The chunk size is a constant, not a setting: 1 MiB. A deployment that needs a
different value changes the constant and the default in the same PR; old rows
carry their own `chunk_size`. The grace period for unreferenced bytes is a
constant too: 30 days.

Temporary upload files go in the system temporary directory. At most one
per-file cap per upload in flight is staged there.

The proposed caps are deliberately conservative for the first deployment. They
are guardrails, not product decisions; the review should set the real numbers
after measuring the backup window.

## Module layout

| Path | Holds |
|---|---|
| `src/attachments.rs` | The store (schema, chunk writes/reads, quota, GC) and the three HTTP handlers. |
| `src/mcp/attachments.rs` | `read_attachment`, `get_attachment_text`, and the attachment path resolver. |
| `src/authz.rs` | `holder_of_workspace(&DocumentId) -> Option<Holder>` (a row lookup, not the reach index) and the `attachment_bytes`/`attachment_count` aggregate in `add_sizes`. |
| `src/config.rs` | The four settings above. |
| `src/main.rs` | The three routes on `notes_router`; the GC task in `open_relay`/`main`. |
| `src/mcp/tools.rs` | Tool registration and descriptions. |
| `src/reach.rs` | The walk also collects `attachment:` hashes into each workspace's referenced set, kept only from a walk that loaded every folder. Reachability is unchanged: these entries are still not walked, listed or admitted. |

The store and the handlers in one file keep the chunk format and the streaming
logic together; the file will be large, and a `src/attachments/` directory is
the split if it grows past that.

## Test plan

Unit tests:

- **Store.** A chunk boundary at exactly 1 MiB and at 1 MiB + 1; a zero-byte
  file; a hash mismatch leaves no row, no chunks and no temporary file; an
  upload cut off mid-body leaves the same; dedupe returns the existing row;
  quota counts rows in their grace period.
- **GC.** A hash named by no entry is marked; a marked hash named again is
  cleared; a hash marked 31 days ago is removed with its chunks; a workspace
  whose last walk missed a folder or left a link pending, or that has not been
  walked, is not touched;
  a hash named only in another workspace is marked here.
- **Path resolver.** An attachment under a nested folder; a name collision
  resolves to the lowest URL; a note path is not an attachment; a folder is not
  an attachment; an `attachment:` URL with a bad hash is refused.
- **Config.** `0` max bytes disables uploads; a negative quota is refused at
  startup; the defaults parse.

Integration tests, with the `Relay` helper and `#[sqlx::test]`:

- **Auth.** Alice uploads to her Private workspace; Bob cannot read it, cannot
  `HEAD` it, cannot upload to it. Alice in group 7 uploads to group 7's
  workspace; Bob in group 7 reads it; Bob with a token that does not name 7 gets
  `404`. A service token is not a member token and is refused.
- **Round trip.** Upload a 3 MiB image, read it byte for byte, `HEAD` it.
  The folder entry the plugin writes is
  visible in the folder document but absent from `note_count` and from
  `search_notes`.
- **Dedupe.** A second upload of the same bytes returns `200`, `existing: true`,
  and does not grow the quota. Two concurrent uploads of the same hash both
  succeed and leave one row.
- **Limits.** A body over the per-file cap is `413 too_large`; a file over the
  workspace quota is `413 quota_exceeded`; a hash mismatch is `422`.
- **Restart.** Upload, restart the app on the same database, download the same
  bytes. A GC pass right after restart, before the walk, marks nothing.
- **Unreferenced.** Upload and link a file, remove the entry, run the GC: the
  row is marked and still downloadable; put the entry back and it is cleared.
- **MCP.** `read_attachment` on an image returns image content under the cap and
  a resource link over it; `get_attachment_text` reports "not extracted" before
  extraction; a path in another workspace is refused; an entry whose row has
  been removed is a tool error, not a 500.
- **Compatibility.** A folder with an attachment entry is listed by
  `list_notes` without the attachment, and the reach index does not count it as
  a note. A note and an attachment must not both claim one name.

Acceptance checks that need a real client (deployed, not in this repo's tests):

- Obsidian on desktop and iOS uploads a pasted image, sees it on the other
  device, renames it, and re-downloads it after a cache eviction.
- The PDF viewer opens a PDF through the plugin's local file, on desktop and
  iOS.
- Deleting an embedded image in Obsidian and restoring it from the trash the
  same day brings it back on the other device.
- Claude (web, desktop, Code) can call `read_attachment` on an image and
  `get_attachment_text` on a PDF.

## Rollout

1. Agree this spec in a PR. The status line becomes `Agreed` with the date and
   reviewers.
2. Relay: schema, store, HTTP routes, `holder_of_workspace`,
   `attachment_bytes`/`attachment_count`, GC, tests. `ATTACHMENTS_ENABLED` stays
   false in production until step 4.
3. Relay: MCP read tools. They are additive; the tool list grows.
4. Plugin: the index, fetch policy, verify, upload, rename and delete work from
   scn-obsidian#37. Release as a plugin version that reads the new entry and
   ignores it gracefully when the relay does not serve it.
5. Enable attachments in production after measuring the backup window; set the
   caps from the measurement, not from this draft. Watch WAL and table size for
   a week.
6. Update `README.md` (configuration, endpoints, storage, "What this does not
   do") in the relay PR that first serves the routes.

The order matters: the schema and routes can ship dark; the plugin can ship and
do nothing until the flag is on; the flag is the day the backup window is
measured. A rollback is the flag off, which leaves the rows in place and the
routes `404`.

## Open questions

1. **Per-file cap and workspace quota.** Proposed 50 MiB / 2 GiB. Decide after
   measuring the daily `pg_dumpall`; the values are config, so the decision is
   cheap to change.
2. **Extraction inline or queued.** Inline on upload blocks the request and
   couples the attachment route to a PDF parser; a queued worker needs service
   auth to read chunks. Recommendation: queue, in #12, with the attachment row
   carrying the extraction state.
3. **Thumbnails.** Server-side generation (the `image` crate) is CPU and a new
   dependency; the plugin can downscale locally. Recommendation: defer, and let
   the plugin render the image it fetched.
4. **Should `list_notes` include attachments?** Adding them is additive to the
   JSON but changes what a client thinks a note is. Recommendation: no in v1;
   the plugin's tree and a known path are enough. Revisit if agents need to
   discover files.
5. **Resource links for PDFs.** A link to the authenticated HTTP URL is not
   usable by an MCP client that has only the MCP token. Options: an MCP
   `resources/read` over `attachment:<sha256>`, a short-lived signed URL, or
   accept the limitation and point at `get_attachment_text`. Recommendation:
   accept the limitation in v1; add `resources/read` if a client needs bytes.
6. **Content-type safety.** Should SVG, HTML and other active types be refused
   at upload, or stored with `Content-Security-Policy: sandbox` and `nosniff`?
   Recommendation: store them with the headers, and add a deny list only if a
   browser path exposes them.
7. **Per-member accounting.** Attachments count against a workspace quota. Does
   a member's total (the #1 storage figure) include the workspaces they are in,
   or only the ones they created? Recommendation: per workspace in v1; member
   accounting is a separate figure.
8. **`.canvas` and `.base`.** They are text files with their own semantics. They
   are not attachments in v1; the plugin keeps them text-only.
9. **Global dedupe.** The same bytes in two workspaces are stored twice. This
    is deliberate for accounting. Revisit only if storage, not permission,
    becomes the constraint.

## What this does not do

- **It does not unshare the past.** A member who leaves a group keeps whatever
  their devices already downloaded. The relay's bytes remain while a folder
  entry names them.
- **It is not encrypted at rest.** Attachments are stored as notes are.
- **It does not make a note's attachment atomic with the note.** The plugin
  writes bytes first, then the folder entry. An interruption leaves unreferenced
  bytes, which the GC removes after the grace period; it does not corrupt a
  note.
- **It does not hide text in images.** An image's description is extracted text
  or a caption, not a guarantee that the image has no other content.
