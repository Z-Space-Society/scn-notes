# 0001: Attachment bytes live in Postgres

Status: Accepted, 2026-11-06
Deciders: Boris, quill
Related: [scn-notes#11](https://github.com/Z-Space-Society/scn-notes/issues/11), [scn-obsidian#37](https://github.com/Z-Space-Society/scn-obsidian/issues/37)

## Context

Members want files and images in their notes. SCN Notes syncs `.md` only: the
plugin writes markdown, and the relay models one Automerge text document per
note. Attachment bytes have no path today.

Garage, the estate's S3-compatible object store, was the first home considered.
It is the right home for bytes in the long run, but it adds a second storage
system to provision, monitor and back up, and a second place where access has to
agree with the relay's workspace rules.

The relay's Postgres is already the permission boundary: `workspaces` says who
holds a workspace, `doc_creators` says who made a document, and the sync and MCP
code already sit beside it. In v1, one store and one authorization model is worth
more than the object store's economics.

## Decision

Attachment bytes live in Postgres, chunked into a second table and
content-addressed by SHA-256 within a workspace. There is no object store in v1.
The schema is in
[the attachment spec](../specs/0002-spec-attachment-storage/0002-spec-attachment-storage.md).

## Alternatives

- **Garage/S3.** Better for large objects and offloads backup cost, but a second
  system to run and a second permission check to keep in step with `may_open`.
  Revisit when bytes outgrow the daily Postgres dump, or when an object store
  can be reached with the same workspace grant.
- **Filesystem on the relay host.** Simple to write, but backup, replication and
  per-workspace accounting all become the relay's problem, and a file has no row
  to join against for authorization.
- **Postgres large objects (`lo`).** Streaming built in, but a separate API,
  awkward with sqlx, and no content addressing per workspace.

## Consequences

- The daily `pg_dumpall` grows with attachment bytes, at about twice their
  stored size, since a dump writes `bytea` as hex. The spec measures the dump
  before uploads are enabled and leaves partitioning as the escape hatch.
- Removing a file does not shrink the table at once. Bytes no folder entry names
  are removed after a grace period; partition by workspace or month if bloat
  matters.
- Per-workspace dedupe is cheap; global dedupe is a later change because it
  complicates accounting and cross-workspace existence.
- Attachments are not encrypted at rest, as notes are not.
