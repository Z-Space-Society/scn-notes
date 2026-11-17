# 0002 Spec: Attachment storage

Status: Draft for review, 2026-11-10 (quill)

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
- **End-to-end encryption.** The relay can read every attachment, as it can
  every note. Postgres operators can too.
- **OCR, PDF thumbnails, server-side rendering.** A PDF is bytes; text is a
  later extraction job.
- **Global dedupe.** Dedupe is per workspace in v1. The same bytes in two
  workspaces are stored twice.
- **Automatic deletion when a note is deleted.** The plugin's trash decision
  decides; the relay keeps bytes until a later GC.
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
  status                TEXT NOT NULL DEFAULT 'pending',
  text_content          TEXT,
  description           TEXT,
  extractor             TEXT,
  extracted_at          TIMESTAMPTZ,
  created_by            TEXT NOT NULL,          -- DID
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at            TIMESTAMPTZ,
  PRIMARY KEY (workspace_root_doc_id, sha256),
  CONSTRAINT attachments_sha256_len
    CHECK (octet_length(sha256) = 32),
  CONSTRAINT attachments_size_nonnegative
    CHECK (size >= 0),
  CONSTRAINT attachments_chunk_size_positive
    CHECK (chunk_size > 0),
  CONSTRAINT attachments_status_known
    CHECK (status IN ('pending', 'complete', 'failed')),
  CONSTRAINT attachments_content_type_present
    CHECK (content_type <> '')
);

CREATE INDEX attachments_workspace_created
  ON attachments (workspace_root_doc_id, created_at);

CREATE INDEX attachments_deleted
  ON attachments (deleted_at)
  WHERE deleted_at IS NOT NULL;

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
  down, small enough that a range read touches one or two rows. `chunk_size` is
  stored per attachment so a later change can be a new value, not a migration of
  old rows.
- **`STORAGE EXTERNAL`.** Image and PDF bytes are already compressed. Letting
  Postgres try to compress a 1 MiB chunk wastes CPU and can make it larger.
  TOAST still moves large values out of the main heap; this only turns off the
  compression attempt.
- **Chunks are immutable.** No update path. A change to the file is a new hash,
  a new row and a new folder entry. That is what makes a range read, a cache, a
  trash window and a future version history tractable.
- **Status.**
  - `pending`: rows are being written; no download.
  - `complete`: every chunk is present and the size matches; downloadable.
  - `failed`: an upload was abandoned or mismatched; chunks are removed by GC.
  A `pending` row older than the GC window is treated as abandoned.
- **Dedupe.** `(workspace_root_doc_id, sha256)` is unique. An upload checks
  for a complete row first and returns `200` with its metadata. If a row is
  `pending`, an upload of the same hash may help finish it: chunks are inserted
  with `ON CONFLICT DO NOTHING`, and whichever request finishes marks it
  `complete`. If a row is `failed`, it is deleted first, chunks and all, and the
  upload starts again.
- **Quota.** The workspace's complete, not-deleted `size` values sum to its
  attachment bytes. The sum is checked against a configurable quota before a new
  row is created and again as the body streams. A race can overshoot by one
  file; that is acceptable for v1 and is why the quota is a guardrail, not a
  security boundary.
- **No path column.** A path is a position in a folder document, not a property
  of the bytes. A rename or a move changes the entry only; the attachment row and
  its chunks do not move. The same hash can be linked from two folders in one
  workspace, and both entries show it.
- **`deleted_at`.** Reserved for the trash decision. v1 has no HTTP delete
  route. A row with `deleted_at` set is not downloadable and does not count
  against the quota. A later GC removes its chunks after a grace period.
- **Text fields.** `text_content`, `description`, `extractor` and `extracted_at`
  are the contract with the search/extraction work in #12. v1 leaves them null;
  `get_attachment_text` reports that no text has been extracted yet.

### Accounting in the workspace listing

`Workspace` already carries `bytes` (Automerge history, filled only by the
listing endpoints through `add_sizes`) and `note_count`. Attachments are a second
kind of bytes. Add two fields, filled by the same `add_sizes` path so the MCP
tools do not pay for the query:

- `attachment_bytes: Option<i64>` — sum of complete, not-deleted `size`.
- `attachment_count: Option<i64>` — count of complete, not-deleted rows.

`bytes` stays exactly what it is today: the storage the workspace's Automerge
documents take. Adding attachment bytes into it would make the figure mean two
different things and would silently change a number Corliss shows. The listing
shows both, and the quota uses `attachment_bytes`.

A single query per listed workspace is enough:

```sql
SELECT COALESCE(SUM(size), 0)::BIGINT, COUNT(*)::BIGINT
FROM attachments
WHERE workspace_root_doc_id = $1
  AND status = 'complete'
  AND deleted_at IS NULL;
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

## HTTP API

Three routes on the `notes.` listener, beside `/v1/workspaces`:

| Route | Does |
|---|---|
| `POST /v1/workspaces/{root_doc_id}/attachments` | Stream a body, verify its hash, store the chunks, return metadata. |
| `HEAD /v1/workspaces/{root_doc_id}/attachments/{sha256}` | Existence and dedupe check. |
| `GET /v1/workspaces/{root_doc_id}/attachments/{sha256}` | Stream the bytes, with `Range` support. |

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
- **Stream, never buffer.** Read the body as a stream into a 1 MiB buffer. Hash
  every byte as it arrives. Never hold the whole file in memory.
- **Verify, never trust.** The header is a hint for the dedupe check. The server
  hashes the streamed body and compares. A mismatch is `422 hash_mismatch`; the
  row is left for GC or for another upload to complete, never marked complete.
- **Dedupe.** If a complete row for `(workspace, hash)` exists, return `200` with
  its metadata and do not read the body. The plugin should `HEAD` first for
  large files; a client that goes straight to `POST` must tolerate an early
  response.
- **Pending races.** If a `pending` row exists, this request may write the
  missing chunks and mark it complete. Chunk inserts are
  `ON CONFLICT DO NOTHING`, so two uploads of the same hash are idempotent.
- **Size.** `Content-Length`, when present, is checked against the per-file cap
  before reading. When absent, the handler counts and stops at the cap. A body
  over the cap is `413 too_large`.
- **Quota.** After dedupe and before creating a new row, sum the workspace's
  complete rows. If adding this file would exceed the workspace quota, return
  `413 quota_exceeded`. The check is repeated as the body grows so a missing
  `Content-Length` cannot overshoot by a whole file.
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
  upload succeeds. If the entry write fails, the bytes are orphaned until GC;
  that is cheaper than a two-phase commit across HTTP and Automerge.

### Download

```http
GET /v1/workspaces/{root_doc_id}/attachments/{sha256}
Authorization: Bearer <token>
```

- **Only complete, not-deleted rows.** A pending, failed or deleted row is
  `404`, as is a workspace the caller cannot open.
- **Headers.**
  - `Content-Type` from the row.
  - `Content-Length` from the row.
  - `Accept-Ranges: bytes`.
  - `ETag: "<sha256>"`, quoted.
  - `Cache-Control: private, max-age=31536000, immutable` — the bytes behind a
    hash never change.
  - `X-Content-Type-Options: nosniff`.
  - `Content-Security-Policy: default-src 'none'; sandbox` — an uploaded SVG or
    HTML file must not run script if a browser opens the URL.
- **Conditional GET.** `If-None-Match` matching the ETag is `304 Not Modified`,
  with no body.
- **Range.** A single `Range: bytes=start-end` (or `start-` or `-suffix`) is
  `206 Partial Content` with `Content-Range: bytes start-end/total` and a
  `Content-Length` of the slice. The handler reads only the chunks the range
  touches and slices the first and last. Multiple ranges are `416` in v1; the
  plugin asks for one at a time.
- **Range bounds.** A range outside the file is `416` with
  `Content-Range: bytes */<size>`. A zero-length file is a `200` with
  `Content-Length: 0`; a range on it is `416`.
- **Streaming.** The body is a stream of chunk rows in order, not a `Vec` of the
  whole file. A 50 MiB file must not become 50 MiB of heap per download.
- **No `Content-Disposition`.** The row has no filename; the plugin knows the
  name from the folder entry and writes the file itself. A browser opening the
  URL sees an opaque hash, which is acceptable.

### HEAD

`HEAD` on the download path returns the same status and headers as `GET`, with
no body. It is the plugin's cheap duplicate check before an upload: `200` means
the bytes are already there and complete; `404` means upload. `409` is not used
here; a pending row is `404` until it is complete.

### Errors

Errors use the existing shape, `{"error": "<code>"}`, with stable snake_case
codes:

| Status | Code | When |
|---|---|---|
| 400 | `invalid_workspace` | The root ID is not a document ID. |
| 400 | `invalid_sha256` | The hash is not 64 lowercase hex characters. |
| 400 | `missing_content_type` | No `Content-Type` on an upload. |
| 401 | — | No token, or a token for another audience. |
| 404 | — | Workspace not open, attachment not found, pending or deleted. |
| 413 | `too_large` | Over the per-file cap. |
| 413 | `quota_exceeded` | Over the workspace quota. |
| 416 | `invalid_range` | A multi-range or out-of-bounds request. |
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
- Load the attachment row by `(located.root, hash)`. If it is missing, pending,
  failed or deleted, return a tool error that says so, not a 500.
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

- **Backups and WAL.** Base backups and WAL now grow with attachment bytes. A
  workspace with a 2 GiB quota is 2 GiB in every base backup and in WAL until the
  next base backup. Before enabling uploads in production, measure the current
  base-backup window and the WAL volume for the largest workspace; if the window
  does not fit, lower the quota or move to an object store. This is the cost the
  ADR accepted.
- **TOAST and bloat.** Chunks are 1 MiB values, so Postgres TOASTs them into the
  toast table. `SET STORAGE EXTERNAL` turns off compression, not TOAST. Deleted
  chunks leave dead tuples; autovacuum handles them, and `pg_repack` or a
  partition swap is the escape hatch if a large delete leaves a table bloated.
  Partitioning `attachment_chunks` by workspace or month is the later move
  suggested in the issue; v1 does not do it.
- **GC.** A background task at startup and hourly:
  - `pending` rows older than 24 hours: delete, chunks cascade.
  - `failed` rows older than 24 hours: delete.
  - `deleted_at` older than the trash grace (when delete exists): delete.
  The task uses the existing `Authz` pool and logs a count, not file names.
- **Metrics to watch.** Database and toast table size
  (`pg_total_relation_size('attachments')`,
  `pg_total_relation_size('attachment_chunks')`), WAL generation, base-backup
  duration, upload/download latency, 413/422 counts, and GC deletions.
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
| `SCN_NOTES_ATTACHMENT_WORKSPACE_QUOTA_BYTES` | `2147483648` (2 GiB) | Sum of complete, not-deleted rows per workspace. Proposed; confirm in review. |
| `SCN_NOTES_MCP_IMAGE_MAX_BYTES` | `4194304` (4 MiB) | Larger images become a resource link. |
| `SCN_NOTES_ATTACHMENTS_ENABLED` | `false` | Serves the routes only when true. Lets the schema ship before the plugin. |

The chunk size is a constant, not a setting: 1 MiB. A deployment that needs a
different value changes the constant and the default in the same PR; old rows
carry their own `chunk_size`.

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
| `src/reach.rs` | No change: it already ignores non-`folder`/`md` entries. |

The store and the handlers in one file keep the chunk format and the range
logic together; the file will be large, and a `src/attachments/` directory is
the split if it grows past that.

## Test plan

Unit tests:

- **Store.** A pending row becomes complete; a chunk boundary at exactly
  1 MiB and at 1 MiB + 1; a zero-byte file; a hash mismatch leaves nothing
  complete; dedupe returns the existing row; a failed row is replaced; quota
  counts only complete, not-deleted rows; the GC removes pending and failed rows
  and leaves complete ones.
- **Range.** First chunk only, last chunk only, a range spanning three chunks, a
  suffix range, an out-of-bounds range, a zero-length file, `If-None-Match`.
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
- **Round trip.** Upload a 3 MiB image, read it byte for byte, `HEAD` it,
  `Range` the middle, `If-None-Match` it. The folder entry the plugin writes is
  visible in the folder document but absent from `note_count` and from
  `search_notes`.
- **Dedupe.** A second upload of the same bytes returns `200`, `existing: true`,
  and does not grow the quota. Two concurrent uploads of the same hash both
  succeed and leave one row.
- **Limits.** A body over the per-file cap is `413 too_large`; a file over the
  workspace quota is `413 quota_exceeded`; a hash mismatch is `422`.
- **Restart.** Upload, restart the app on the same database, download the same
  bytes. A pending row is cleaned by the GC after its window.
- **MCP.** `read_attachment` on an image returns image content under the cap and
  a resource link over it; `get_attachment_text` reports "not extracted" before
  extraction; a path in another workspace is refused; a deleted row is refused.
- **Compatibility.** A folder with an attachment entry is listed by
  `list_notes` without the attachment, and the reach index does not count it as
  a note. A note and an attachment must not both claim one name.

Acceptance checks that need a real client (deployed, not in this repo's tests):

- Obsidian on desktop and iOS uploads a pasted image, sees it on the other
  device, renames it, and re-downloads it after a cache eviction.
- The PDF viewer opens a PDF through the plugin's local file, including a range
  read on iOS.
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
   measuring the base-backup window; the values are config, so the decision is
   cheap to change.
2. **Extraction inline or queued.** Inline on upload blocks the request and
   couples the attachment route to a PDF parser; a queued worker needs service
   auth to read chunks. Recommendation: queue, in #12, with the attachment row
   carrying the extraction state.
3. **Thumbnails.** Server-side generation (the `image` crate) is CPU and a new
   dependency; the plugin can downscale locally. Recommendation: defer, and let
   the plugin render the image it fetched.
4. **Trash and `deleted_at`.** Does the relay own a grace window, or does the
   plugin decide and tell the relay to delete? Recommendation: the plugin's
   trash decides; the relay keeps bytes until a GC grace after `deleted_at`.
   Decide with the trash feature, not here.
5. **Should `list_notes` include attachments?** Adding them is additive to the
   JSON but changes what a client thinks a note is. Recommendation: no in v1;
   the plugin's tree and a known path are enough. Revisit if agents need to
   discover files.
6. **Resource links for PDFs.** A link to the authenticated HTTP URL is not
   usable by an MCP client that has only the MCP token. Options: an MCP
   `resources/read` over `attachment:<sha256>`, a short-lived signed URL, or
   accept the limitation and point at `get_attachment_text`. Recommendation:
   accept the limitation in v1; add `resources/read` if a client needs bytes.
7. **Content-type safety.** Should SVG, HTML and other active types be refused
   at upload, or stored with `Content-Security-Policy: sandbox` and `nosniff`?
   Recommendation: store them with the headers, and add a deny list only if a
   browser path exposes them.
8. **Per-member accounting.** Attachments count against a workspace quota. Does
   a member's total (the #1 storage figure) include the workspaces they are in,
   or only the ones they created? Recommendation: per workspace in v1; member
   accounting is a separate figure.
9. **`.canvas` and `.base`.** They are text files with their own semantics. They
   are not attachments in v1; the plugin keeps them text-only.
10. **Global dedupe.** The same bytes in two workspaces are stored twice. This
    is deliberate for accounting. Revisit only if storage, not permission,
    becomes the constraint.

## What this does not do

- **It does not unshare the past.** A member who leaves a group keeps whatever
  their devices already downloaded. The relay's bytes remain until a delete.
- **It is not end-to-end encrypted.** The relay can read every attachment, as it
  can every note. Postgres operators can too.
- **It does not make a note's attachment atomic with the note.** The plugin
  writes bytes first, then the folder entry. An interruption leaves unreferenced
  bytes, which the GC removes; it does not corrupt a note.
- **It does not hide text in images.** An image's description is extracted text
  or a caption, not a guarantee that the image has no other content.
