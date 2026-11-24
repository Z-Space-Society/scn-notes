//! Attachment bytes: files and images in a workspace, stored in Postgres.
//!
//! The design is `docs/specs/0002-spec-attachment-storage`. An attachment is
//! immutable and content-addressed: its identity is `(workspace, sha256)`, so
//! the same bytes uploaded twice to one workspace are stored once, and a
//! changed file is a new hash. A folder document names it with an entry whose
//! `url` is `attachment:<sha256>`; the bytes never travel over sync.
//!
//! **A row means verified bytes.** An upload is staged to a temporary file
//! while it is hashed, and only a body whose hash matches is written, row and
//! chunks in one transaction. Without that, a mismatched or interrupted upload
//! could leave chunks that a later upload of the same hash would complete
//! around, storing wrong bytes under a right hash. Nothing a failed upload did
//! is ever visible, and no database connection is held while a slow client is
//! still sending.
//!
//! **Access is the workspace row.** Every route loads the `workspaces` row for
//! the root in its path and asks [`Holder::opens_to`]. It does not ask the
//! reachability index, which is derived and can be empty just after startup.
//! A workspace that does not exist and one the caller may not open are the
//! same `404`, as a denied document and a missing one are on sync.

use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    body::{Body, Bytes},
    extract::{Path as UrlPath, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use futures::StreamExt;
use samod::DocumentId;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::auth::Caller;
use crate::workspaces::{bearer, error, internal_error, unauthorized};
use crate::AppState;

/// The size of a stored chunk. Large enough to keep the row count and per-row
/// overhead down, small enough that a download streams one row at a time.
/// Each row records its own `chunk_size`, so changing this is not a migration.
pub(crate) const CHUNK_SIZE: usize = 1 << 20;

/// The longest `Content-Type` stored. A header is the client's to choose, and
/// the row keeps it for every later download.
const MAX_CONTENT_TYPE: usize = 255;

/// The header an upload names its hash in.
const SHA256_HEADER: &str = "x-content-sha256";

/// The bytes behind a hash never change.
const CACHE_CONTROL: &str = "private, max-age=31536000, immutable";

/// An uploaded SVG or HTML file must not run script if a browser opens it.
const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; sandbox";

/// Startup statements, run after `workspaces` exists. Idempotent.
const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS attachments (
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
         created_by            TEXT NOT NULL,
         created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
         unreferenced_since    TIMESTAMPTZ,
         PRIMARY KEY (workspace_root_doc_id, sha256),
         CONSTRAINT attachments_sha256_len CHECK (octet_length(sha256) = 32),
         CONSTRAINT attachments_size_nonnegative CHECK (size >= 0),
         CONSTRAINT attachments_chunk_size_positive CHECK (chunk_size > 0),
         CONSTRAINT attachments_content_type_present CHECK (content_type <> '')
     )",
    "CREATE INDEX IF NOT EXISTS attachments_workspace_created
         ON attachments (workspace_root_doc_id, created_at)",
    "CREATE INDEX IF NOT EXISTS attachments_unreferenced
         ON attachments (unreferenced_since)
         WHERE unreferenced_since IS NOT NULL",
    "CREATE TABLE IF NOT EXISTS attachment_chunks (
         workspace_root_doc_id TEXT NOT NULL,
         sha256                BYTEA NOT NULL,
         chunk_no              INT NOT NULL,
         data                  BYTEA NOT NULL,
         PRIMARY KEY (workspace_root_doc_id, sha256, chunk_no),
         FOREIGN KEY (workspace_root_doc_id, sha256)
             REFERENCES attachments (workspace_root_doc_id, sha256)
             ON DELETE CASCADE,
         CONSTRAINT attachment_chunks_no_nonnegative CHECK (chunk_no >= 0)
     )",
    // Image and PDF bytes are already compressed; trying again wastes CPU
    // and can make a chunk larger. TOAST still moves the values out of line.
    "ALTER TABLE attachment_chunks ALTER COLUMN data SET STORAGE EXTERNAL",
];

/// Create the attachment tables. Called from the startup migration once the
/// `workspaces` table they reference exists.
pub(crate) async fn migrate(pool: &PgPool) -> Result<(), sqlx::Error> {
    for &statement in SCHEMA {
        sqlx::query(statement).execute(pool).await?;
    }
    Ok(())
}

/// The caps a deployment sets.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Per file. `0` refuses every upload; downloads still work.
    pub max_bytes: u64,
    /// The sum of a workspace's attachment sizes.
    pub quota_bytes: u64,
}

/// The attachment store, present on the `notes.` listener only when
/// attachments are enabled.
#[derive(Clone)]
pub struct Attachments(Arc<Inner>);

struct Inner {
    pool: PgPool,
    limits: Limits,
    /// Where uploads are staged while they are hashed. This process's own:
    /// it is emptied at startup, which is what removes a file a crash left.
    staging: PathBuf,
    next_upload: AtomicU64,
}

/// A stored attachment, as the routes answer with it.
struct Stored {
    content_type: String,
    size: i64,
    chunk_size: i32,
}

/// What an insert found.
enum Inserted {
    New,
    /// A concurrent upload of the same hash committed first.
    Existing,
    QuotaExceeded,
}

impl Attachments {
    /// Open the store and empty its staging directory.
    pub async fn open(pool: PgPool, limits: Limits, staging: PathBuf) -> Result<Self> {
        match tokio::fs::remove_dir_all(&staging).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e).with_context(|| format!("could not empty {}", staging.display()))
            }
        }
        tokio::fs::create_dir_all(&staging)
            .await
            .with_context(|| format!("could not create {}", staging.display()))?;
        Ok(Self(Arc::new(Inner {
            pool,
            limits,
            staging,
            next_upload: AtomicU64::new(0),
        })))
    }

    async fn find(&self, root: &DocumentId, hash: &[u8; 32]) -> Result<Option<Stored>> {
        let row = sqlx::query(
            "SELECT content_type, size, chunk_size FROM attachments
             WHERE workspace_root_doc_id = $1 AND sha256 = $2",
        )
        .bind(root.to_string())
        .bind(&hash[..])
        .fetch_optional(&self.0.pool)
        .await?;
        row.map(|row| {
            Ok(Stored {
                content_type: row.try_get("content_type")?,
                size: row.try_get("size")?,
                chunk_size: row.try_get("chunk_size")?,
            })
        })
        .transpose()
    }

    /// The bytes a workspace's attachments take, the figure the quota checks.
    async fn used(&self, root: &DocumentId) -> Result<u64> {
        let used: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(size), 0)::BIGINT FROM attachments
             WHERE workspace_root_doc_id = $1",
        )
        .bind(root.to_string())
        .fetch_one(&self.0.pool)
        .await?;
        Ok(used.max(0) as u64)
    }

    /// Write a verified upload: the row and every chunk, read back from the
    /// staged file, in one transaction.
    async fn insert(
        &self,
        root: &DocumentId,
        hash: &[u8; 32],
        content_type: &str,
        size: u64,
        creator: &Caller,
        staged: &mut tokio::fs::File,
    ) -> Result<Inserted> {
        let root = root.to_string();
        let mut tx = self.0.pool.begin().await?;
        // A concurrent insert of the same key waits here for the other
        // transaction, then finds its row.
        let inserted = sqlx::query(
            "INSERT INTO attachments
                 (workspace_root_doc_id, sha256, content_type, size, chunk_size, created_by)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT DO NOTHING",
        )
        .bind(&root)
        .bind(&hash[..])
        .bind(content_type)
        .bind(size as i64)
        .bind(CHUNK_SIZE as i32)
        .bind(&creator.did.0)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if inserted == 0 {
            return Ok(Inserted::Existing);
        }

        // Again, now that the row is in: another upload may have landed since
        // the first check. Two at once can still overshoot by one file.
        let used: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(size), 0)::BIGINT FROM attachments
             WHERE workspace_root_doc_id = $1",
        )
        .bind(&root)
        .fetch_one(&mut *tx)
        .await?;
        if used.max(0) as u64 > self.0.limits.quota_bytes {
            return Ok(Inserted::QuotaExceeded);
        }

        staged.rewind().await?;
        let mut chunk = vec![0u8; CHUNK_SIZE];
        let mut chunk_no: i32 = 0;
        loop {
            let filled = fill(staged, &mut chunk).await?;
            if filled == 0 {
                break;
            }
            sqlx::query(
                "INSERT INTO attachment_chunks (workspace_root_doc_id, sha256, chunk_no, data)
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(&root)
            .bind(&hash[..])
            .bind(chunk_no)
            .bind(&chunk[..filled])
            .execute(&mut *tx)
            .await?;
            chunk_no += 1;
            if filled < CHUNK_SIZE {
                break;
            }
        }
        tx.commit().await?;
        Ok(Inserted::New)
    }

    /// A staging path no other upload in this process is using.
    fn staging_path(&self) -> PathBuf {
        let n = self.0.next_upload.fetch_add(1, Ordering::Relaxed);
        self.0.staging.join(format!("upload-{n}"))
    }
}

/// Read until `buf` is full or the file ends. Returns how much was read.
async fn fill(file: &mut tokio::fs::File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = file.read(&mut buf[filled..]).await?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

/// A staged upload, removed however the request ends: success, refusal, an
/// error, or the client going away mid-body, which drops the handler.
struct Staged {
    path: PathBuf,
    file: tokio::fs::File,
}

impl Staged {
    async fn create(path: PathBuf) -> std::io::Result<Self> {
        let file = tokio::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .await?;
        Ok(Self { path, file })
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        remove_quietly(&self.path);
    }
}

fn remove_quietly(path: &Path) {
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(error = %e, path = %path.display(), "could not remove a staged upload");
        }
    }
}

/// 64 lowercase hex characters, as a digest.
fn parse_sha256(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut hash = [0u8; 32];
    hex::decode_to_slice(text, &mut hash).ok()?;
    Some(hash)
}

fn not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

/// Why a request does not reach a workspace.
enum Denied {
    Unauthorized,
    InvalidWorkspace,
    /// Missing, or not the caller's to open: the same answer either way.
    NotFound,
    Internal(anyhow::Error),
}

impl IntoResponse for Denied {
    fn into_response(self) -> Response {
        match self {
            Denied::Unauthorized => unauthorized(),
            Denied::InvalidWorkspace => error(StatusCode::BAD_REQUEST, "invalid_workspace"),
            Denied::NotFound => not_found(),
            Denied::Internal(e) => internal_error(e),
        }
    }
}

/// The caller, if their token is good and they may open the workspace.
async fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    root: &str,
) -> Result<(Caller, DocumentId), Denied> {
    let verified = match state
        .verifier
        .verify(bearer(headers), &state.audience)
        .await
    {
        Ok(verified) => verified,
        Err(e) => {
            tracing::info!(error = %e, "refused an attachment request");
            return Err(Denied::Unauthorized);
        }
    };
    let Ok(root) = DocumentId::from_str(root) else {
        return Err(Denied::InvalidWorkspace);
    };
    match state.authz.holder_of_workspace(&root).await {
        Ok(Some(holder)) if holder.opens_to(&verified.caller) => Ok((verified.caller, root)),
        Ok(_) => Err(Denied::NotFound),
        Err(e) => Err(Denied::Internal(e)),
    }
}

fn metadata(
    root: &DocumentId,
    hash: &[u8; 32],
    stored: &Stored,
    existing: bool,
) -> serde_json::Value {
    let hex = hex::encode(hash);
    json!({
        "sha256": hex,
        "size": stored.size,
        "content_type": stored.content_type,
        "workspace_root_doc_id": root.to_string(),
        "url": format!("attachment:{hex}"),
        "existing": existing,
    })
}

/// The content type to store: present, short, and a valid header value, since
/// every download sends it back.
fn content_type_of(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::CONTENT_TYPE)?.to_str().ok()?.trim();
    (!value.is_empty() && value.len() <= MAX_CONTENT_TYPE).then(|| value.to_string())
}

/// `POST /v1/workspaces/{root_doc_id}/attachments`: stage, verify, store.
pub async fn upload(
    State(state): State<AppState>,
    UrlPath(root): UrlPath<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(store) = state.attachments.clone() else {
        return not_found();
    };
    let (caller, root) = match authorize(&state, &headers, &root).await {
        Ok(found) => found,
        Err(denied) => return denied.into_response(),
    };
    let Some(hash) = headers
        .get(SHA256_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_sha256)
    else {
        return error(StatusCode::BAD_REQUEST, "invalid_sha256");
    };
    let Some(content_type) = content_type_of(&headers) else {
        return error(StatusCode::BAD_REQUEST, "missing_content_type");
    };

    // Dedupe before reading a byte of the body.
    match store.find(&root, &hash).await {
        Ok(Some(stored)) => {
            return (StatusCode::OK, Json(metadata(&root, &hash, &stored, true))).into_response()
        }
        Ok(None) => {}
        Err(e) => return internal_error(e),
    }

    let limits = store.0.limits;
    let declared: Option<u64> = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok());
    if limits.max_bytes == 0 || declared.is_some_and(|n| n > limits.max_bytes) {
        return error(StatusCode::PAYLOAD_TOO_LARGE, "too_large");
    }
    match store.used(&root).await {
        Ok(used) if used.saturating_add(declared.unwrap_or(0)) > limits.quota_bytes => {
            return error(StatusCode::PAYLOAD_TOO_LARGE, "quota_exceeded")
        }
        Ok(_) => {}
        Err(e) => return internal_error(e),
    }

    let mut staged = match Staged::create(store.staging_path()).await {
        Ok(staged) => staged,
        Err(e) => {
            return internal_error(anyhow::Error::from(e).context("could not stage an upload"))
        }
    };
    let mut hasher = Sha256::new();
    let mut size: u64 = 0;
    let mut stream = body.into_data_stream();
    while let Some(frame) = stream.next().await {
        let bytes: Bytes = match frame {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::info!(error = %e, "an upload ended before its body did");
                return StatusCode::BAD_REQUEST.into_response();
            }
        };
        size += bytes.len() as u64;
        if size > limits.max_bytes {
            return error(StatusCode::PAYLOAD_TOO_LARGE, "too_large");
        }
        hasher.update(&bytes);
        if let Err(e) = staged.file.write_all(&bytes).await {
            return internal_error(anyhow::Error::from(e).context("could not stage an upload"));
        }
    }
    if let Err(e) = staged.file.flush().await {
        return internal_error(anyhow::Error::from(e).context("could not stage an upload"));
    }
    if hasher.finalize().as_slice() != hash {
        return error(StatusCode::UNPROCESSABLE_ENTITY, "hash_mismatch");
    }

    let stored = Stored {
        content_type,
        size: size as i64,
        chunk_size: CHUNK_SIZE as i32,
    };
    match store
        .insert(
            &root,
            &hash,
            &stored.content_type,
            size,
            &caller,
            &mut staged.file,
        )
        .await
    {
        Ok(Inserted::New) => (
            StatusCode::CREATED,
            Json(metadata(&root, &hash, &stored, false)),
        )
            .into_response(),
        Ok(Inserted::Existing) => match store.find(&root, &hash).await {
            Ok(Some(stored)) => {
                (StatusCode::OK, Json(metadata(&root, &hash, &stored, true))).into_response()
            }
            Ok(None) => internal_error(anyhow::anyhow!(
                "an attachment row vanished after its insert"
            )),
            Err(e) => internal_error(e),
        },
        Ok(Inserted::QuotaExceeded) => error(StatusCode::PAYLOAD_TOO_LARGE, "quota_exceeded"),
        Err(e) => internal_error(e),
    }
}

/// `GET` and `HEAD /v1/workspaces/{root_doc_id}/attachments/{sha256}`: the
/// whole file, streamed one chunk row at a time. `HEAD` reads no chunks.
pub async fn download(
    State(state): State<AppState>,
    UrlPath((root, sha256)): UrlPath<(String, String)>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    let Some(store) = state.attachments.clone() else {
        return not_found();
    };
    let (_, root) = match authorize(&state, &headers, &root).await {
        Ok(found) => found,
        Err(denied) => return denied.into_response(),
    };
    let Some(hash) = parse_sha256(&sha256) else {
        return error(StatusCode::BAD_REQUEST, "invalid_sha256");
    };
    let stored = match store.find(&root, &hash).await {
        Ok(Some(stored)) => stored,
        Ok(None) => return not_found(),
        Err(e) => return internal_error(e),
    };

    let mut response = if method == Method::HEAD {
        Response::new(Body::empty())
    } else {
        let chunks = if stored.size == 0 {
            0
        } else {
            (stored.size - 1) / i64::from(stored.chunk_size) + 1
        };
        let pool = store.0.pool.clone();
        let root = root.to_string();
        let stream = futures::stream::unfold(0i64, move |chunk_no| {
            let pool = pool.clone();
            let root = root.clone();
            async move {
                if chunk_no >= chunks {
                    return None;
                }
                let data: Result<Vec<u8>, sqlx::Error> = sqlx::query_scalar(
                    "SELECT data FROM attachment_chunks
                     WHERE workspace_root_doc_id = $1 AND sha256 = $2 AND chunk_no = $3",
                )
                .bind(&root)
                .bind(&hash[..])
                .bind(chunk_no as i32)
                .fetch_one(&pool)
                .await;
                if let Err(e) = &data {
                    tracing::error!(error = %e, "an attachment download failed mid-stream");
                }
                Some((data.map(Bytes::from), chunk_no + 1))
            }
        });
        Response::new(Body::from_stream(stream))
    };

    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&stored.content_type) {
        headers.insert(header::CONTENT_TYPE, value);
    }
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(stored.size));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(CACHE_CONTROL),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    response
}

#[cfg(test)]
pub(crate) mod tests {
    use super::parse_sha256;

    /// A staging directory of a test relay's own. Tests run in parallel in one
    /// process, and opening the store empties its directory.
    pub(crate) fn staging_dir() -> std::path::PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!("scn-notes-test-uploads-{}-{n}", std::process::id()))
    }

    #[test]
    fn a_hash_is_64_lowercase_hex_characters() {
        let good = "0123456789abcdef".repeat(4);
        assert_eq!(parse_sha256(&good).unwrap()[0], 0x01);
        for bad in [
            "",
            &good[..63],
            &format!("{good}0"),
            &"0123456789ABCDEF".repeat(4),
            &format!("{}g", &good[..63]),
        ] {
            assert!(parse_sha256(bad).is_none(), "{bad:?}");
        }
    }
}
