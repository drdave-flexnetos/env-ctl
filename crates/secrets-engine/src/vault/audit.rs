//! The durable, hash-chained audit log's chain math — the single source of truth that BOTH the
//! `InMemStore` and the future libSQL store funnel through, so the two backends can never disagree
//! on the chain (HF-14). Pure-Rust (std + blake3 + serde_json, all already deps).
//!
//! ## The chain
//!
//! Each [`AuditRecord`] carries `seq` (1-based, contiguous), `prev_hash` (the previous row's
//! `row_hash`, or [`genesis_hash`] for `seq == 1`) and `row_hash = blake3(prev_hash ||
//! canonical_row(rec))`. [`verify_chain`] is tamper-EVIDENT against PARTIAL mutation: tampering
//! with any covered field, reordering rows, or deleting/inserting a row in the middle all break it.
//!
//! It is NOT, by itself, resistant to a WHOLE-CHAIN rewrite or a TAIL TRUNCATION: the chain is
//! unkeyed (its hashes are public constants — see [`genesis_hash`]), so a store-level attacker can
//! recompute a fresh, internally-valid shorter chain from genesis, dropping the most recent rows.
//! Full-rewrite / truncation resistance comes from the DEK-keyed tail ANCHOR maintained ABOVE this
//! module by the engine (`vault.audit_head`, `Engine::verify_audit_anchor`), which binds the
//! expected `(max_seq, tail_row_hash)` to the unlocked DEK; only an unlocked vault can advance it.
//!
//! ## Why blake3, why canonical, why length-prefixed
//!
//! BLAKE3 1.5 is already a dependency (and is used for the header MAC + bearer MAC), so it is the
//! primary chain hash; the spec's SHA-256 fallback is satisfiable by swapping the one
//! `blake3::Hasher` here for `Sha256` without touching any call site. [`canonical_row`] is
//! length-prefixed / fixed-width so two *distinct* rows can never serialize to the same bytes
//! (no field-boundary ambiguity), which is what makes a single flipped byte detectable. `detail`
//! is serialized to JSON exactly once at append time and that byte string is what is both hashed
//! and stored, so re-serialization can never drift the chain even if serde's map ordering changed.

use crate::event::{AuditOutcome, AuditRecord};

/// Domain-separation prefix for an audit row's canonical content. Versioned (`/v1/`) and distinct
/// from every other BLAKE3 use in the crate so a row-content blob can never be replayed as some
/// other hashed/MAC'd blob.
const AUDIT_ROW_DOMAIN: &[u8] = b"env-ctl/v1/audit-row";

/// `prev_hash` of the FIRST row. Domain-separated constant so `seq == 1` is unambiguous — there is
/// no all-zero `prev_hash` an attacker could forge a "genesis" against.
pub fn genesis_hash() -> [u8; 32] {
    *blake3::hash(b"env-ctl/v1/audit-genesis").as_bytes()
}

/// Fixed wire byte for each outcome (canonical, stable — never reorder).
fn outcome_byte(o: AuditOutcome) -> u8 {
    match o {
        AuditOutcome::Ok => 0x01,
        AuditOutcome::Refused => 0x02,
        AuditOutcome::Failed => 0x03,
    }
}

/// Append a length-prefixed byte field: `u32` BE length, then the bytes. Distinct-length-or-bytes
/// inputs never collide, so no two distinct rows serialize to the same canonical bytes.
fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    debug_assert!(
        bytes.len() <= u32::MAX as usize,
        "length-prefixed audit field exceeds u32 width (canonical-encoding invariant)"
    );
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Canonical bytes of an audit row's CONTENT — everything the hash commits to EXCEPT `prev_hash`
/// and `row_hash`. `prev_hash` is folded in separately by [`row_hash`]; `row_hash` cannot cover
/// its own output. Layout (all multi-byte ints big-endian):
///
/// ```text
///   AUDIT_ROW_DOMAIN                 (20-byte domain prefix, constant)
///   i64be seq
///   u32be len(ts)  | ts bytes        (length-prefixed RFC3339 timestamp)
///   u8 actor-present | u32be actor_uid (present-byte then the uid; uid bytes still emitted as
///                                       0 when absent so the field stays fixed-width)
///   u32be len(event_type) | event_type
///   u8 subject-present | u32be len(subject) | subject  (len+bytes emitted only when present)
///   u32be len(detail_json) | detail_json   (the exact serde_json::to_vec(detail) bytes)
///   u8 outcome
/// ```
pub fn canonical_row(rec: &AuditRecord) -> Vec<u8> {
    let mut out = Vec::with_capacity(AUDIT_ROW_DOMAIN.len() + 64);
    out.extend_from_slice(AUDIT_ROW_DOMAIN);
    out.extend_from_slice(&rec.seq.to_be_bytes());
    push_len_prefixed(&mut out, rec.ts.as_bytes());
    match rec.actor_uid {
        Some(uid) => {
            out.push(0x01);
            out.extend_from_slice(&uid.to_be_bytes());
        }
        None => {
            out.push(0x00);
            out.extend_from_slice(&0u32.to_be_bytes());
        }
    }
    push_len_prefixed(&mut out, rec.event_type.as_bytes());
    match &rec.subject {
        Some(s) => {
            out.push(0x01);
            push_len_prefixed(&mut out, s.as_bytes());
        }
        None => {
            out.push(0x00);
        }
    }
    // Serialize the detail exactly once; this byte string is what is hashed AND what the store
    // persists, so two backends (or two runs) can never disagree on the detail encoding.
    let detail_json = serde_json::to_vec(&rec.detail)
        .expect("serde_json::Value always serializes to bytes");
    push_len_prefixed(&mut out, &detail_json);
    out.push(outcome_byte(rec.outcome));
    out
}

/// `row_hash = blake3( prev_hash || canonical_row(rec) )`. `prev_hash` is the previous row's
/// `row_hash`, or [`genesis_hash`] for the first row.
pub fn row_hash(prev_hash: &[u8], rec: &AuditRecord) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(prev_hash);
    h.update(&canonical_row(rec));
    *h.finalize().as_bytes()
}

/// Build an unsealed [`AuditRecord`] (seq = 0, `prev_hash`/`row_hash` empty) from the engine's
/// intent. The store seals it with [`link_row`] before persisting; keeps engine call sites tidy
/// and the `event_type` strings canonical (the caller passes a `&str` literal).
pub fn new_row(
    ts: String,
    actor_uid: Option<u32>,
    event_type: &str,
    subject: Option<String>,
    detail: serde_json::Value,
    outcome: AuditOutcome,
) -> AuditRecord {
    AuditRecord {
        seq: 0,
        ts,
        actor_uid,
        event_type: event_type.to_string(),
        subject,
        detail,
        outcome,
        prev_hash: Vec::new(),
        row_hash: Vec::new(),
    }
}

/// Given the chain tail (`prev`) and a freshly-built record whose seq/prev_hash/row_hash are
/// placeholders, stamp the linked `seq`, `prev_hash` and `row_hash` and return a sealed record
/// ready to persist. `next_seq = prev.map(|r| r.seq).unwrap_or(0) + 1`.
pub fn link_row(prev: Option<&AuditRecord>, mut rec: AuditRecord) -> AuditRecord {
    rec.seq = prev.map(|r| r.seq).unwrap_or(0) + 1;
    rec.prev_hash = match prev {
        Some(p) => p.row_hash.clone(),
        None => genesis_hash().to_vec(),
    };
    // row_hash must be computed over the FINAL seq + prev_hash (canonical_row covers seq).
    rec.row_hash = row_hash(&rec.prev_hash, &rec).to_vec();
    rec
}

/// Walk rows in `seq` order and verify the whole chain. `seq` must be `1..=n` contiguous;
/// `rows[0].prev_hash == genesis_hash()`; each `row.prev_hash == previous row.row_hash`; each
/// `row.row_hash == row_hash(prev_hash, row)`. Returns `Err(seq)` at the FIRST violation (tampered
/// field, reordered row, deleted/inserted row, broken linkage). Constant-time comparison is NOT
/// required — audit hashes are public.
pub fn verify_chain(rows: &[AuditRecord]) -> Result<(), i64> {
    let genesis = genesis_hash();
    let mut prev_hash: Vec<u8> = genesis.to_vec();
    for (i, row) in rows.iter().enumerate() {
        let expected_seq = (i as i64) + 1;
        if row.seq != expected_seq {
            return Err(row.seq);
        }
        if row.prev_hash != prev_hash {
            return Err(row.seq);
        }
        let computed = row_hash(&row.prev_hash, row);
        if row.row_hash.as_slice() != computed.as_slice() {
            return Err(row.seq);
        }
        prev_hash = row.row_hash.clone();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn unsealed(seq_hint: i64, event: &str, detail: serde_json::Value) -> AuditRecord {
        // seq_hint is ignored by link_row but lets the fixtures read clearly.
        let _ = seq_hint;
        new_row(
            "2026-06-02T00:00:00Z".to_string(),
            Some(1000),
            event,
            Some("claude".to_string()),
            detail,
            AuditOutcome::Ok,
        )
    }

    /// Build a sealed chain of `n` rows via repeated `link_row`.
    fn build_chain(n: usize) -> Vec<AuditRecord> {
        let mut rows: Vec<AuditRecord> = Vec::new();
        for i in 0..n {
            let prev = rows.last();
            let rec = unsealed(0, "vault_unlocked", json!({ "i": i }));
            rows.push(link_row(prev, rec));
        }
        rows
    }

    #[test]
    fn genesis_is_stable_and_nonzero() {
        let g = genesis_hash();
        assert_eq!(g, genesis_hash(), "genesis must be deterministic");
        assert_ne!(g, [0u8; 32], "genesis must not be all-zero (no ambiguity)");
    }

    #[test]
    fn linked_chain_verifies() {
        let rows = build_chain(5);
        assert_eq!(rows[0].seq, 1);
        assert_eq!(rows[0].prev_hash, genesis_hash().to_vec());
        for w in rows.windows(2) {
            assert_eq!(w[1].prev_hash, w[0].row_hash, "links must chain");
            assert_eq!(w[1].seq, w[0].seq + 1, "seq contiguous");
        }
        verify_chain(&rows).expect("a freshly linked chain must verify");
    }

    #[test]
    fn empty_chain_verifies() {
        verify_chain(&[]).expect("an empty chain is trivially valid");
    }

    #[test]
    fn field_flip_breaks_chain_at_that_seq() {
        let mut rows = build_chain(4);
        // Flip the subject of the middle row WITHOUT recomputing row_hash.
        rows[2].subject = Some("tampered".to_string());
        assert_eq!(verify_chain(&rows), Err(3), "tamper detected at seq 3");

        // Flip the detail byte-string instead.
        let mut rows2 = build_chain(4);
        rows2[1].detail = json!({ "i": 999 });
        assert_eq!(verify_chain(&rows2), Err(2));

        // Flip the outcome.
        let mut rows3 = build_chain(4);
        rows3[3].outcome = AuditOutcome::Failed;
        assert_eq!(verify_chain(&rows3), Err(4));
    }

    #[test]
    fn reorder_breaks_chain() {
        let mut rows = build_chain(4);
        rows.swap(1, 2);
        // After the swap, seq is no longer contiguous at the swapped position.
        assert!(verify_chain(&rows).is_err());
    }

    #[test]
    fn delete_breaks_chain() {
        let mut rows = build_chain(4);
        rows.remove(1); // removes seq=2; remaining are seq 1,3,4 -> not contiguous.
        assert_eq!(verify_chain(&rows), Err(3));
    }

    #[test]
    fn insert_breaks_chain() {
        let mut rows = build_chain(3);
        // Insert a forged row in the middle with a plausible-looking but wrong linkage.
        let forged = link_row(rows.first(), unsealed(0, "forged", json!({})));
        rows.insert(1, forged);
        // The forged row claims seq=2 but the row after it expects seq=3 / a different prev_hash.
        assert!(verify_chain(&rows).is_err());
    }

    #[test]
    fn canonical_row_distinguishes_none_from_present_subject() {
        let mut a = unsealed(0, "e", json!({}));
        a.subject = None;
        let mut b = unsealed(0, "e", json!({}));
        b.subject = Some(String::new());
        assert_ne!(canonical_row(&a), canonical_row(&b), "None vs Some(\"\") must differ");
    }

    #[test]
    fn canonical_row_distinguishes_none_from_present_actor() {
        let mut a = unsealed(0, "e", json!({}));
        a.actor_uid = None;
        let mut b = unsealed(0, "e", json!({}));
        b.actor_uid = Some(0);
        assert_ne!(canonical_row(&a), canonical_row(&b), "None vs Some(0) must differ");
    }

    #[test]
    fn row_hash_depends_on_prev_hash() {
        let rec = unsealed(0, "e", json!({}));
        let h_genesis = row_hash(&genesis_hash(), &rec);
        let h_other = row_hash(&[0xAB; 32], &rec);
        assert_ne!(h_genesis, h_other, "prev_hash must fold into row_hash");
    }
}
