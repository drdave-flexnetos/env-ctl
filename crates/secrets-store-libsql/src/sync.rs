//! Async-to-sync bridge. The engine's [`envctl_secrets::vault::Store`] trait is fully sync
//! (`&self` methods returning `anyhow::Result`); the libSQL remote client is async. This module
//! owns a PRIVATE current-thread tokio runtime and adapts every async libSQL call to a blocking
//! one via `Runtime::block_on`.
//!
//! ## Why a private current-thread runtime
//!
//! The runtime is `Arc`-wrapped and reused for the life of one store instance (one connection).
//! A `new_current_thread` runtime is intentional: the Store is called from the daemon's blocking
//! worker context (never from inside an outer tokio worker — calling `block_on` from a tokio worker
//! thread panics), and a single-threaded reactor is sufficient to drive one HTTP/Hrana connection.
//! Keeping the runtime private to this crate is what lets the engine stay completely async-free.

use std::sync::Arc;

use tokio::runtime::Runtime;

use crate::error::{Error, Result};

/// A sync wrapper over one libSQL [`libsql::Connection`] plus the private runtime that drives it.
/// Cloneable: the `Arc<Runtime>` and the (cheaply-cloneable) `Connection` are shared, so the engine
/// can hold the store behind an `Arc` and every method reuses the one reactor + connection.
#[derive(Clone)]
pub struct SyncConnection {
    rt: Arc<Runtime>,
    conn: libsql::Connection,
}

impl SyncConnection {
    /// Build the private current-thread runtime, open the remote database, and connect. All async
    /// work happens on the runtime we own here.
    pub fn open_remote(url: &str, auth_token: &str) -> Result<Self> {
        // A PRIVATE current-thread runtime (no `rt-multi-thread` feature, no worker pool). One
        // reactor drives one HTTP/Hrana connection; `enable_all` turns on the I/O + time drivers
        // the libSQL client needs.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| Error::RuntimeCreation(e.to_string()))?;
        let conn = rt.block_on(async {
            let db = libsql::Builder::new_remote(url.to_string(), auth_token.to_string())
                .build()
                .await
                .map_err(|e| Error::Connect(e.to_string()))?;
            db.connect().map_err(|e| Error::Connect(e.to_string()))
        })?;
        Ok(Self {
            rt: Arc::new(rt),
            conn,
        })
    }

    /// Borrow the underlying runtime handle (used by `store` for multi-statement `block_on`s such as
    /// `reserve_secret_row_id` and `put_secret`, which must run several awaits under one future).
    pub fn runtime(&self) -> &Arc<Runtime> {
        &self.rt
    }

    /// Borrow the underlying connection (used inside runtime-driven async blocks in `store`).
    pub fn conn(&self) -> &libsql::Connection {
        &self.conn
    }

    /// Run a `SELECT` and return the FIRST row (or `None`). Parameterized only — `params` is a
    /// `Vec<libsql::Value>` bound positionally to the `?` placeholders in `sql`.
    pub fn query_one(
        &self,
        sql: &str,
        params: Vec<libsql::Value>,
    ) -> Result<Option<libsql::Row>> {
        self.rt.block_on(async {
            let mut rows = self
                .conn
                .query(sql, params)
                .await
                .map_err(|e| Error::QueryFailed(e.to_string()))?;
            rows.next()
                .await
                .map_err(|e| Error::QueryFailed(e.to_string()))
        })
    }

    /// Run a `SELECT` and collect ALL rows.
    pub fn query_all(
        &self,
        sql: &str,
        params: Vec<libsql::Value>,
    ) -> Result<Vec<libsql::Row>> {
        self.rt.block_on(async {
            let mut rows = self
                .conn
                .query(sql, params)
                .await
                .map_err(|e| Error::QueryFailed(e.to_string()))?;
            let mut out = Vec::new();
            while let Some(r) = rows
                .next()
                .await
                .map_err(|e| Error::QueryFailed(e.to_string()))?
            {
                out.push(r);
            }
            Ok(out)
        })
    }

    /// Run an `INSERT`/`UPDATE`/`DELETE`/`PRAGMA` and return the affected-row count.
    pub fn execute(&self, sql: &str, params: Vec<libsql::Value>) -> Result<u64> {
        self.rt.block_on(async {
            self.conn
                .execute(sql, params)
                .await
                .map_err(|e| Error::ExecuteFailed(e.to_string()))
        })
    }
}
