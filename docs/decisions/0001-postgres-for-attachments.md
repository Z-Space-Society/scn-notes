# 0001: Attachment bytes live in Postgres

Status: Accepted, 2026-11-06
Deciders: Boris, quill
Related: [scn-notes#11](https://github.com/Z-Space-Society/scn-notes/issues/11), [scn-obsidian#37](https://github.com/Z-Space-Society/scn-obsidian/issues/37)
Supersedes: the Garage suggestion in the 2026-11-06 review of "Feature - Support for Files" in the SCN Members workspace

## Context

Members want files and images in their notes. SCN Notes syncs `.md` only: the
plugin writes markdown, and the relay models one Automerge text document per
note. Attachment bytes have no path today.

The first review of the feature note suggested Garage, the estate's S3-compatible
object store. That is the right home for bytes in the long run, but it adds a
second storage system to provision, monitor and back up, and a second place
where access has to agree with the relay's workspace rules.

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

- **Garage/S3 (the earlier suggestion).** Better for large objects and offloads
  backup cost, but a second system to run and a second permission check to keep
  in step with `may_open`. Revisit when bytes outgrow the Postgres backup window,
  or when an object store can be reached with the same workspace grant.
- **Filesystem on the relay host.** Simple to write, but backup, replication and
  per-workspace accounting all become the relay's problem, and a file has no row
  to join against for authorization.
- **Postgres large objects (`lo`).** Streaming built in, but a separate API,
  awkward with sqlx, and no content addressing or chunk-level range reads.

## Consequences

- WAL volume and base-backup size grow with attachment bytes. The spec measures
  the backup window before large files are enabled and leaves partitioning as the
  escape hatch.
- Deleting a file does not shrink the table. `deleted_at` and a GC job are the
  path to reclaiming space; partition by workspace or month if bloat matters.
- Per-workspace dedupe is cheap; global dedupe is a later change because it
  complicates accounting and cross-workspace existence.
- The relay's operators can read every attachment, as they can every note. This
  is consistent with the service's existing "not end-to-end encrypted" posture.
