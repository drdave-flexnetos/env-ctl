# env-ctl ops — Vault backup/restore + DEK & keyslot rotation runbook

> Scope: a concrete operational design for backing up, restoring, and rotating
> the env-ctl secrets vault on **the dual-RTX-5090 dev box (Profile A, on-box,
> USB-PARTUUID auto-unlock)**, with notes for the deferred VPS profile (Profile B).
> Grounded in the locked design docs (`ARCHITECTURE.md`, `SERVER-MODE.md`,
> `THREAT-MODEL.md`, `DESIGN-NOTES.md`, `ROADMAP.md`, `db/schema.sql`,
> `research/03`, `research/13`). **READ-ONLY analysis — no code was changed.**
>
> Status legend: **[VERIFIED]** = directly grounded in a cited repo doc/line.
> **[PROPOSED]** = recommended ops design not yet present in the scaffold (no CLI
> verb or `Store` method exists for it as of Phase 0). **[UNVERIFIED]** = external
> claim or version not confirmed against an upstream source in this pass.
>
> Phasing reality check (do not skip): per `ROADMAP.md` lines 5–43, **Phase 0
> ships only the fail-closed `SecGuard` engine + `inmem-store`**; the libSQL
> backend (`vault.db`) lands in **Phase 1**, keymgmt/USB unlock in **Phase 2**,
> DEK rotation in **Phase 1** (full re-encryption defined there), and the
> `envctl install secretd` `SystemdUnit` component in **Phase 7**. Everything in
> this runbook that names a CLI verb (`vault dek-rotate`, `vault enroll-usb`,
> `vault verify-audit`, etc.) is **[PROPOSED]** — the verb surface is not yet cut.
> The *engine* methods that DO exist in the scaffold are `unlock`, `lock`,
> `secret_put`, `secret_get`, `relay_mint`, `relay_revoke`,
> `relay_revoke_bearer`, `relay_swap` (`SCAFFOLD-SPEC.md` lines 206–216).

---

## 0. TL;DR recommended posture

1. **Back up exactly one file: `~/.local/share/env-ctl/vault.db`** (dir `0700`,
   file `0600`). It is 100% app-AEAD ciphertext + non-secret metadata; the DEK
   and unlock factors are never in it. A stolen backup is useless without a
   factor (`THREAT-MODEL.md` A4, line 26; `ARCHITECTURE.md` line 66).
2. **Take backups via `sqlite3 ... 'VACUUM INTO'` against the loopback `sqld`,
   not `cp` of a live file** (WAL-consistent snapshot). [PROPOSED]
3. **Two rotation classes, very different costs:**
   - **Keyslot rotation = O(1)** one-blob rewrite of `keyslots.wrapped_dek`
     (passphrase change, USB re-enroll). Re-seal the DEK under a new KEK.
   - **DEK rotation = O(all-secrets)** full re-encryption under one resumable
     atomic txn (`meta.rotation_in_progress`). Use on compromise or schedule.
     (`ARCHITECTURE.md` line 79; `DESIGN-NOTES.md` HF-1 line 42; `schema.sql`
     lines 66–69; `ROADMAP.md` line 19.)
4. **Back up the 64-byte USB keyfile content separately and offline.** Losing
   *both* the USB keyfile and the passphrase = unrecoverable vault, by design
   (`THREAT-MODEL.md` A5 line 27; `DESIGN-NOTES.md` OI-18 line 121).
5. **Verify the hash-chained audit log on every restore.** A restore that fails
   `verify_audit_chain()` must NOT be trusted (`research/13`; `schema.sql`
   lines 159–169; `ROADMAP.md` line 20).
6. **systemd hardening on the unit is part of the threat-model contract**
   (`mlockall` + `RLIMIT_CORE=0` + `MADV_DONTDUMP`; daemon refuses to start if
   `mlockall` fails — `DESIGN-NOTES.md` HF-4 line 45; `ARCHITECTURE.md` line 23;
   `EngineError::MlockFailed`, `SCAFFOLD-SPEC.md` line 336).

---

## 1. What to back up (scope) — and why it is safe off-box

### 1.1 The single backup target

`~/.local/share/env-ctl/vault.db` is the **sole required** target
(`ARCHITECTURE.md` lines 125–127; `schema.sql` line 15). Everything else under
`~/.local/share/env-ctl/` is either public (`ca/ca.pem`, `0644`) or
regenerable. The audit mirror at `~/.local/state/env-ctl/` (`0700`) is a
second home for the audit head (`ARCHITECTURE.md` lines 126–127) and is worth
co-archiving as an independent tamper cross-check, but it is not required for
data recovery.

### 1.2 What the file actually contains (all ciphertext or non-secret)

Every row below is **app-encrypted XChaCha20-Poly1305** (24-byte `OsRng` nonce +
ciphertext + 16-byte Poly1305 tag), AAD recomputed at decrypt from trusted
identity columns and never stored. libSQL's own at-rest encryption is **never**
relied on — `sqld` is untrusted storage (`SERVER-MODE.md` line 41; `schema.sql`
lines 10–11). Verified against `db/schema.sql`:

| Table / column | Contents | Protection |
|---|---|---|
| `secret_versions.ciphertext` | secret bodies | AEAD(DEK, body, aad=`v1‖u8(table_tag)‖u64be(secret_id)‖u64be(version)‖u64be(dek_generation)`) — `schema.sql` 94–103, `ARCHITECTURE.md` line 77 |
| `keyslots.wrapped_dek` | the DEK, wrapped per factor | AEAD(KEK, DEK, aad=`keyslot_aad`); KEK = HKDF-SHA256 (USB) or Argon2id (passphrase) — `schema.sql` 45–63 |
| `hmac_key.ciphertext` | 32-byte keyed-BLAKE3 key for bearer hashing | AEAD(DEK, …); **re-wrapped, not re-derived, across DEK rotation** so live bearers survive (`schema.sql` 30–39; `DESIGN-NOTES.md` OI-9 line 112) |
| `ca_key.key_ciphertext` | PKCS#8 DER of the local CA private key | AEAD(DEK, …) — `schema.sql` 174–186 |
| `certs[*].key_ciphertext` | control-plane leaf keys | AEAD(DEK, …); **MITM leaf keys are NOT persisted** (in-RAM only, OI-19) — `schema.sql` 188–209 |
| `ca_key.cert_pem`, `certs[*].cert_pem` | public certs | plaintext, safe to back up |
| `meta.*` | schema_version, vault_id, active_dek_generation, **header_mac**, **rotation_in_progress**, issuance_floor_ms, audit_head, created_at | non-secret control state — `schema.sql` 24–28 |
| `dek_generation.*` | rotation history (active row has `tombstoned_at IS NULL`) | non-secret — `schema.sql` 70–75 |
| `secrets.*`, `relay_policies.*`, `relay_bearers.*` (minus raw bearer) | names, kinds, providers, allowlists, TTL ceilings, bearer **hashes only** | non-secret metadata; raw bearer never persists (`schema.sql` 128–151) |
| `audit_log.*` | hash-chained tamper-evident trail | integrity-protected by chaining — `schema.sql` 159–169 |

### 1.3 The keyslot envelope (how the DEK is protected at rest) [VERIFIED]

Two LUKS-style keyslots wrap **one** DEK; either factor opens the vault
(1-of-2, *not* 2FA — `DESIGN-NOTES.md` line 14; `THREAT-MODEL.md` A12 line 34):

- **USB slot:** `KEK_usb = HKDF-SHA256(salt32, keyfile, info=b"env-ctl/v1/kek/usb")`
  (the keyfile is already 64 B CSPRNG, so HKDF, not Argon2 — `DESIGN-NOTES.md`
  line 75; `ARCHITECTURE.md` line 75).
- **Passphrase slot:** `KEK_pp = Argon2id(passphrase, salt, m=1 GiB, t=4, p=4,
  version=0x13)`, built explicitly via `Argon2::new(...)`, never `default()`;
  a code-level param floor refuses to unwrap a downgraded slot
  (`DESIGN-NOTES.md` line 75; `ARCHITECTURE.md` line 75; `schema.sql` 51–54).
- **`keyslot_aad` binding (HF-3):**
  `b"env-ctl/v1/keyslot" ‖ u8(factor) ‖ u8(kdf_id) ‖ u32be(m_kib) ‖
  u32be(t_cost) ‖ u32be(p_lanes) ‖ len32(salt)‖salt ‖ len32(uuid)‖uuid ‖
  u64be(dek_generation) ‖ u64be(slot_id)` (`ARCHITECTURE.md` line 76).
- **`meta.header_mac` (OI-8):** a DEK-authenticated MAC over the keyslot set +
  KDF params + generation; recomputed on unlock; drift → `HeaderMacMismatch`
  fail-closed (`schema.sql` 22–23, 42–44; `ARCHITECTURE.md` line 81;
  `EngineError::HeaderMacMismatch`, `SCAFFOLD-SPEC.md` line 337).

### 1.4 Why the backup is safe to store off-box [VERIFIED → A4]

The entire file is ciphertext under a DEK that **never touches disk** and lives
only in mlocked daemon RAM, zeroized on drop (`ARCHITECTURE.md` line 23). A
thief with `vault.db` faces an **offline attack against the weaker keyslot**,
i.e. the passphrase's Argon2id work (A12, line 34) — there is no SQLCipher and
no C-SQLite weak-default surface (A4, line 26). Acceptable backup destinations:

- A separate **LUKS-encrypted** external drive.
- Off-box object storage **with client-side encryption** (the file is already
  AEAD'd, but defense-in-depth + integrity is still worth it).
- Air-gapped / safe-deposit media — **provided the USB keyfile is NOT
  co-located** with the backup (co-location collapses A4 to A5).

---

## 2. How to take a backup (concrete) [PROPOSED]

### 2.1 Recommended: WAL-consistent snapshot, not a live `cp`

The recommended on-box wiring is an **embedded `sqld` bound to loopback only**,
with `secretd` talking to it over the pure-Rust `remote` libSQL client
(`SERVER-MODE.md` lines 7–9, 75, 247). Because the DB runs `journal_mode=WAL`
(`schema.sql` line 13), a raw `cp` of `vault.db` during a write can capture a
torn page or miss un-checkpointed WAL frames. Use a **consistent snapshot**:

```bash
# Snapshot the loopback sqld to a fresh file (WAL-consistent, no daemon stop).
# 'VACUUM INTO' produces a clean, fully-checkpointed copy of the database.
SNAP="$HOME/backups/env-ctl/vault-$(date -u +%Y%m%dT%H%M%SZ).db"
mkdir -p "$(dirname "$SNAP")" && chmod 0700 "$(dirname "$SNAP")"

# Against the loopback sqld Hrana/HTTP endpoint (loopback-only, never exposed):
#   the C-SQLite client lives in sqld's process; this shells the sqlite3 CLI
#   that ships with the sqld toolchain. Adjust the bind to match the unit.
sqlite3 "$HOME/.local/share/env-ctl/vault.db" "VACUUM INTO '$SNAP'"
chmod 0600 "$SNAP"
```

> `VACUUM INTO 'file'` is the standard SQLite mechanism to produce a transactionally
> consistent copy without locking out writers for the whole copy — see the SQLite
> docs: <https://www.sqlite.org/lang_vacuum.html#vacuuminto>. libSQL inherits
> SQLite's SQL surface (libSQL is a SQLite fork; `research/03` line 9). **[UNVERIFIED:
> exact libSQL CLI invocation against the loopback endpoint; confirm whether the
> snapshot is taken via the sqld admin API or the sqlite3 CLI on the backing
> file once the merged `secretctl vault backup` verb exists.]**

If the daemon is stopped, a plain copy is safe **after** a checkpoint:

```bash
# Cold copy path (daemon stopped — see §4 for the stop command per unit type):
cp --reflink=auto "$HOME/.local/share/env-ctl/vault.db" "$SNAP"
chmod 0600 "$SNAP"
```

### 2.2 Integrity sidecar (store the hash OUT of band)

```bash
b3sum "$SNAP" | tee "${SNAP}.b3"     # BLAKE3 of the snapshot (env-ctl already depends on blake3)
# Record the hash somewhere the backup itself cannot reach (password manager,
# a second host, paper). This detects a tampered/swapped backup at restore time,
# above and beyond the in-file audit chain.
```

`b3sum` matches the project's `blake3 = "1.5"` dependency (`SCAFFOLD-SPEC.md`
dep list; `DESIGN-NOTES.md` crypto stack). **[UNVERIFIED: that the `b3sum` CLI
is installed on the box — `cargo install b3sum` or use `sha256sum` as a
fallback.]**

### 2.3 First-class verb (target state) [PROPOSED]

The clean end state, once the merge lands the verb surface (`ARCHITECTURE.md`
line 137: verbs fold under `envctl secret|vault|relay|ca|run`):

```bash
envctl vault backup --out "$SNAP" --json        # WAL-consistent snapshot + b3 sidecar
envctl vault backup --out s3://bucket/vault.db   # streamed, client-side pre-encrypted
```

This verb does **not exist in the Phase-0 scaffold** — the engine `Store` trait
exposes `fsync_barrier()` and `health()` but **no `backup`/`snapshot` method**
(`SERVER-MODE.md` lines 54–66). Cutting `vault backup` is a recommended
post-Phase-1 ops addition; it should: (a) call `fsync_barrier()` first, (b)
snapshot, (c) write the `.b3` sidecar, (d) append a durable `audit_log` row.

### 2.4 Automating it (systemd timer, on-box) [PROPOSED]

If `secretd` runs as a **system** service (the `envctl install secretd`
`SystemdUnit` component, `ROADMAP.md` line 43 / `ARCHITECTURE.md` line 137 —
[UNVERIFIED whether the shipped unit is system or `--user`]), pair a oneshot +
timer:

```ini
# /etc/systemd/system/env-ctl-backup.service     [PROPOSED]
[Unit]
Description=env-ctl vault snapshot
After=secretd.service
Requires=secretd.service

[Service]
Type=oneshot
User=drdave
# Snapshot only; rotation/keyslot ops are NEVER automated (require apply+confirm, §3).
ExecStart=/usr/local/bin/envctl vault backup --out /var/backups/env-ctl/vault-%i.db --json
# Inherit the hardening contract even for the helper:
ProtectSystem=strict
ReadWritePaths=/var/backups/env-ctl
NoNewPrivileges=true
PrivateTmp=true
```

```ini
# /etc/systemd/system/env-ctl-backup.timer       [PROPOSED]
[Unit]
Description=Daily env-ctl vault snapshot
[Timer]
OnCalendar=*-*-* 03:30:00
Persistent=true
[Install]
WantedBy=timers.target
```

```bash
systemctl enable --now env-ctl-backup.timer
systemctl list-timers env-ctl-backup.timer
```

> systemd timer semantics (`OnCalendar`, `Persistent`):
> <https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html>.
> Retention pruning (keep N dailies + M monthlies) is an ops-policy choice; a
> simple `find /var/backups/env-ctl -name 'vault-*.db' -mtime +30 -delete`
> in a separate prune oneshot is sufficient for a single-operator vault.

---

## 3. Rotation

Two operations with the **same name family but radically different cost and
semantics**. Conflating them is the classic footgun the design explicitly calls
out (`ARCHITECTURE.md` line 79: "Passphrase rotation is the cheap one-blob
keyslot rewrite; DEK rotation is the expensive full re-seal").

### 3.1 Keyslot rotation — O(1), milliseconds [VERIFIED semantics]

Re-seal the **same DEK** under a **new KEK**. Ciphertext bodies are untouched;
only `keyslots.wrapped_dek` (+ `wrap_nonce`, KDF params, `rewrapped_at`, and the
recomputed `meta.header_mac`) change for the affected slot. **Does NOT bump
`dek_generation`.** (`ARCHITECTURE.md` line 79; `schema.sql` 45–63.)

When:
- Passphrase change every 6–12 months, or immediately on suspected passphrase
  exposure.
- USB keyfile replacement (wear, loss-with-passphrase-fallback).
- Decommission a factor (revoke the USB slot, leave passphrase-only — **but
  note FS-S22**, §5.2).

Commands **[PROPOSED — verbs not yet cut; engine has only `unlock`/`lock`]**:

```bash
# Rotate the passphrase keyslot (prove current factor, set new):
envctl vault rotate-passphrase --apply        # REQ-SEC-1: apply=false (dry-run) is the default

# Enroll a NEW USB keyfile slot (both slots active afterward; either opens):
envctl vault enroll-usb --apply

# Revoke the USB slot (future unlocks passphrase-only):
envctl keyslot revoke --factor usb_keyfile --apply --confirm   # root-of-trust → apply && confirm
```

Per REQ-SEC-1 (`THREAT-MODEL.md` line 38) every destructive RPC defaults to
dry-run (`apply=false` on the wire) and root-of-trust ops additionally need
`confirm`. `vault rekey/destroy`, `relay revoke-all`, CA root ops, and trust
unwire are explicitly enumerated there. No `--force` bypasses any guard
(FS-S12, line 63).

### 3.2 DEK rotation — O(all-secrets), full re-encryption [VERIFIED semantics]

This is **NOT** a keyslot rewrite. Under one atomic, resumable transaction
gated by `meta.rotation_in_progress` (`schema.sql` 66–69; `ARCHITECTURE.md`
line 79; `DESIGN-NOTES.md` HF-1 line 42; `ROADMAP.md` line 19):

1. Set `meta.rotation_in_progress = 1`; create a new `dek_generation` row.
2. For **every** ciphertext row (`secret_versions`, `ca_key`, `certs` with a
   persisted key), decrypt under the OLD DEK and re-seal under the NEW DEK with
   a **fresh nonce** and AAD bound to the new generation.
3. Re-wrap `keyslots.wrapped_dek` for every enabled slot under the new DEK.
4. **Re-wrap (not re-derive) `hmac_key`** so live bearers survive (OI-9,
   `schema.sql` 30–39).
5. Advance `meta.active_dek_generation`; tombstone the old generation
   (`dek_generation.tombstoned_at`); drop the old DEK from RAM; clear
   `rotation_in_progress`.

When (`dek_generation.reason` enum, `schema.sql` line 74):
- `scheduled-rotation` (e.g. quarterly).
- `compromise` (daemon crashed/analyzed, key exposure suspected).
- `init` (vault creation) / `passphrase-change` (note: a passphrase change is a
  keyslot op; the `passphrase-change` reason exists but the *cheap* path is
  §3.1 — only force a full DEK rotation on passphrase change if you also suspect
  DEK exposure).

Crash recovery (acceptance-tested in `ROADMAP.md` line 20): if the daemon dies
mid-rotation, the next unlock sees `rotation_in_progress = 1` and **resumes** —
already-resealed rows (tagged with the new generation) are skipped, the rest are
re-sealed, then the flag is cleared.

Commands **[PROPOSED]**:

```bash
envctl vault dek-rotate                            # dry-run: reports row count to re-seal, no changes (REQ-SEC-1/5)
envctl vault dek-rotate --reason scheduled-rotation --apply --confirm
envctl vault dek-rotate --reason compromise --apply --confirm
envctl vault status | grep -E 'dek_generation|rotation_in_progress'   # confirm advance + clean flag
```

Cost note (REQ-SEC-5, `THREAT-MODEL.md` line 42): linear in secret count and
**documented as such**. For a single-operator vault (dozens–hundreds of
secrets) this is sub-second; do not let it run on every passphrase change.

### 3.3 Rotation interaction with live relay bearers [VERIFIED]

DEK rotation does **not** invalidate live `≤24h` relay bearers, because the
`hmac_key` used for keyed-BLAKE3 bearer hashing is re-wrapped, not re-derived
(`DESIGN-NOTES.md` OI-9 line 112; `schema.sql` 30–39). If you *want* to kill
bearers during a compromise response, do it explicitly with `relay revoke --all`
(durable, count-reporting, HF-16) and/or `lock` (the true panic stop, DEK
zeroize — `ARCHITECTURE.md` line 103).

---

## 4. Restore

### 4.1 Pre-flight

1. Locate: the snapshot (`vault-*.db`), the `.b3` sidecar (verify hash), the
   USB keyfile (or the passphrase), and confirm `meta.schema_version` will match
   the installed binary's expected version (`StoreHealth.schema_version`,
   `SERVER-MODE.md` line 66).
2. Verify the off-band hash before trusting the file:

```bash
b3sum -c "$SNAP.b3"      # must print OK
```

### 4.2 Same-machine restore

```bash
# 1. Stop the daemon (pick the form matching the installed unit):
systemctl stop secretd            # system unit
# systemctl --user stop secretd   # user unit  [UNVERIFIED which the shipped component uses]

# 2. Restore the file with the correct mode:
install -m 0600 "$SNAP" "$HOME/.local/share/env-ctl/vault.db"

# 3. Start the daemon. With the USB inserted it auto-unlocks (USB-PARTUUID default):
systemctl start secretd

# 4. Verify the audit chain (see §6) and that secrets are readable:
envctl vault verify-audit                  # [PROPOSED verb] — recompute chain seq=1..head
envctl secret list                         # metadata only
envctl secret get anthropic/api-key        # broker path; --reveal is apply-gated + audited
```

The unlock itself enforces the tamper checks: `meta.header_mac` recomputation
(`HeaderMacMismatch` if the keyslot set drifted) and the monotonic
`issuance_floor_ms` / `CLOCK_BOOTTIME` cross-check against clock rollback
(`ARCHITECTURE.md` line 81; OI-6). A failure here is fail-closed — investigate
the backup source rather than forcing past it (no `--force` exists, FS-S12).

### 4.3 Disaster recovery onto a NEW box

The audit chain, keyslots, and DEK generations all travel **inside `vault.db`**,
so the correct sequence is **restore first, enroll never** (enrolling creates a
*fresh* vault and would discard the restore):

```bash
# 1. Install env-ctl + the daemon component on the new box:
envctl install secretd                     # Phase-7 SystemdUnit component (ARCHITECTURE line 137)

# 2. Remove any fresh vault the installer created:
rm -f "$HOME/.local/share/env-ctl/vault.db"

# 3. Restore the snapshot (verify hash first, §4.1):
install -m 0600 "$SNAP" "$HOME/.local/share/env-ctl/vault.db"

# 4. Provide a factor and start. The restored keyslots already wrap the DEK:
#    - USB path: insert the SAME enrolled USB (PARTUUID recorded in keyslots) and start.
#    - Passphrase path: start, then `envctl vault unlock` and supply the backup passphrase.
systemctl start secretd

# 5. Verify the chain + readability (as §4.2 steps 4).
```

> On-box gate self-check (FS-S22, `SERVER-MODE.md` line 169): if topology is
> on-box and the restored vault has **no enabled `usb_keyfile` keyslot**, the
> daemon refuses to start (or forces every `usb_gated=0` to be an explicit,
> audited operator choice). Do not "fix" this by disabling the gate — it is the
> A12-posture guard. If you restored a vault whose only surviving factor is the
> passphrase, re-enroll a USB slot (§3.1) immediately after a successful unlock.

### 4.4 Cross-box audit continuity (intentional, not a bug) [VERIFIED]

The `audit_log` is restored **as-is**: rows `1..N` in any older snapshot are
byte-identical to rows `1..N` in a later one (same `seq`, `ts`, `prev_hash`,
`row_hash`). Restoring does **not** rewind the chain — the chain is append-only
and resumes from the restored head (`schema.sql` 159–169; `research/13`). This
is the correct semantics for disaster recovery.

---

## 5. Interaction with the storage backend (libSQL / `sqld`)

### 5.1 Backups target the primary; the C core is isolated [VERIFIED]

The recommended on-box wiring is **embedded `sqld` on loopback + the pure-Rust
`remote` client in `secretd`** (`SERVER-MODE.md` lines 7–9, 75; `research/03`
line 99: pure-Rust path = `libsql = { version = "0.9", default-features =
false, features = ["remote"] }`). Backups snapshot the **primary `sqld`
node**'s database. App-AEAD is authoritative; `sqld` is untrusted storage and
its built-in at-rest encryption is **never** used (disabled/unimplemented per
libSQL issue #1756 — `SERVER-MODE.md` line 41).

If `sqld` is unhealthy, `Store::health()` returns non-`durable` and gates
daemon startup fail-closed (`SERVER-MODE.md` lines 62–66). On crash, `sqld`
recovers from its WAL on restart (standard SQLite WAL recovery,
<https://www.sqlite.org/wal.html>); if the file is corrupted beyond WAL
recovery, restore from the last good snapshot (§4).

> **Pinned versions [VERIFIED in `research/03` line 95, 99]:** `libsql = "0.9"`;
> the C backend `libsql-ffi = "0.9.30"` is pulled ONLY by `core`/`replication`
> (the embedded modes), never by the `remote` client. The C SQLite waiver
> (NEW-3) is quarantined in a separate `secrets-store-libsql` crate consumed
> only by `secretd` (`SERVER-MODE.md` line 17). **[UNVERIFIED: that 0.9.30 is
> still the latest libsql-ffi as of the build date — re-check before pinning.]**

### 5.2 Embedded-replica sync — OUT OF SCOPE for now [VERIFIED]

libSQL embedded-replica sync is **offline / Last-Push-Wins**; if it is ever
adopted, **replicate only NON-secret metadata, read-only, and NEVER make
revocation or the audit log Last-Push-Wins** (`SERVER-MODE.md` OI-SM-8 line 327;
`research/03` lines 37–46). Replication is WAL-frame-based with a rolling
checksum (`research/03` lines 41–42, source
<https://blog.canoozie.net/libsql-replication/>; Turso embedded-replicas reached
GA in 2024, <https://docs.turso.tech/features/embedded-replicas/introduction>).
For Phase 1 the backend is a single loopback `sqld` with **no replication** —
DEK/keyslot state lives only on the primary and replicas would have no write
path to it.

### 5.3 DEK rotation + Profile B (deferred VPS) [VERIFIED design]

In Profile B the `sqld` node is untrusted storage on the VPS and `secretd` /
the operator-box holds the USB and the DEK (`SERVER-MODE.md` lines 165, 237–238,
254). DEK rotation is initiated **on the operator-box** (where the DEK is); the
re-sealed ciphertext rows flow to the VPS `sqld`. Remote clients' in-flight
streams that depend on the rotation tear down fail-closed; the operator-box-
signed presence/authorizer link gates **issuance**, never decryption, and cannot
invoke any vault-management verb (`SERVER-MODE.md` line 210). The VPS profile is
**deferred** (`ROADMAP.md` line 5, Phase 8 + open trusted-time items).

---

## 6. Audit-chain continuity across backup/restore [VERIFIED]

`audit_log` is a dense, monotonic, hash-chained, append-only log
(`schema.sql` 159–169):

```
row_hash(seq) = BLAKE3( canonical(seq, ts, actor_uid, event_type, subject, detail, outcome)
                        || prev_hash )
prev_hash(seq) = row_hash(seq-1)          # zeroes for seq=1
```

Security-relevant outcomes (`unlock`, `secret_read`, `relay_mint`,
`relay_swap`, `dek_rotate`, `revoke`, `leaf_mint`) are committed **durably
before the RPC returns** (HF-14, `schema.sql` 155–158; `DESIGN-NOTES.md` line
56). On unlock/restore, `verify_audit_chain()` recomputes seq=1→head and
**refuses** on any gap, reorder, or hash mismatch — at the correct `seq`
(`ROADMAP.md` line 20).

**Recommended hardening (Phase 1+, `research/13`):** sign the audit head with
Ed25519 after each rotation / on a schedule and hold the public key off-box, so
an attacker who rewrites the *entire* backup cannot forge a self-consistent
chain. Canonicalization should follow RFC 8785 (JSON Canonicalization Scheme,
<https://www.rfc-editor.org/rfc/rfc8785>). **[PROPOSED — head-signing is design,
not yet implemented; `research/13` §4.]**

---

## 7. Recommended operational cadence

| Cadence | Action | Command (✱ = [PROPOSED] verb) |
|---|---|---|
| Daily (automated) | WAL-consistent snapshot + `.b3` sidecar, off-box copy | `env-ctl-backup.timer` (§2.4) |
| Weekly | Verify audit chain (no side effects) | `envctl vault verify-audit` ✱ |
| Monthly | Test-restore a snapshot onto a scratch box; re-verify chain | §4.3 |
| 6–12 mo | Rotate passphrase keyslot (O(1)) | `envctl vault rotate-passphrase --apply` ✱ |
| Quarterly | DEK rotation (O(all), gated by USB presence) | `envctl vault dek-rotate --reason scheduled-rotation --apply --confirm` ✱ |
| On compromise | (1) revoke all bearers, (2) lock, (3) rotate passphrase, (4) DEK rotate, (5) pull USB | see §7.1 |

### 7.1 Compromise response (order matters) [VERIFIED commands where they exist]

```bash
envctl relay revoke --all --apply --confirm     # durable, count-reporting (HF-16); kills live bearers
envctl vault lock                                # PANIC STOP: zeroizes DEK + in-RAM CA Issuer (ARCH line 103)
# ... investigate; restore from a known-good snapshot if integrity is in doubt ...
envctl vault rotate-passphrase --apply           # ✱ cheap, if the passphrase may be known
envctl vault dek-rotate --reason compromise --apply --confirm   # ✱ full re-seal under a new DEK
# Physically pull the USB → new egress stops within the (short) grace window (FS-S5).
```

`lock` and `relay revoke --all` are the two documented containment actions
(`ARCHITECTURE.md` line 103). Pulling the USB defaults to auto-relock (zeroize
DEK + CA Issuer after a short drain grace; `ARCHITECTURE.md` line 103; FS-S5,
`THREAT-MODEL.md` line 56).

---

## 8. The systemd unit hardening contract [VERIFIED requirements, PROPOSED unit]

The threat model *requires* these process protections; `secretd` **refuses to
start if `mlockall` fails** (`EngineError::MlockFailed`, FS-S4 — `SCAFFOLD-SPEC.md`
line 336; `DESIGN-NOTES.md` HF-4 line 45; `ARCHITECTURE.md` line 23). The
`envctl install secretd` component (Phase 7) should generate a unit equivalent
to:

```ini
# secretd.service   [PROPOSED illustrative unit; the actual file is emitted by the merge]
[Unit]
Description=env-ctl secrets daemon (secretd)
After=network-online.target

[Service]
ExecStart=/usr/local/bin/secretd
# --- Threat-model contract: no key plaintext to swap/coredump (HF-4 / FS-S4) ---
LimitCORE=0                          # RLIMIT_CORE=0  → no coredump leaks the DEK
LimitMEMLOCK=infinity                # allow mlockall(MCL_CURRENT|MCL_FUTURE) to succeed
# (the daemon itself sets MADV_DONTDUMP + mlockall; the unit must not block them)
# --- Surface reduction ---
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only                # but allow the vault + state dirs:
ReadWritePaths=%h/.local/share/env-ctl %h/.local/state/env-ctl
RuntimeDirectory=env-ctl             # $XDG_RUNTIME_DIR/env-ctl (0700) for control.sock
RuntimeDirectoryMode=0700
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6   # UDS control + loopback sqld + relay edge
# Do NOT set MemoryDenyWriteExecute if rustls/ring needs it; verify against the build.

[Install]
WantedBy=default.target
```

> systemd resource-limit directives (`LimitCORE`, `LimitMEMLOCK`):
> <https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#LimitCPU=>.
> The listener self-check (`SERVER-MODE.md` line 91) independently refuses to
> start unless exactly one non-loopback listener (the relay HTTPS edge) exists
> and control is a UDS under `$XDG_RUNTIME_DIR` with no TCP control bind — so the
> unit and the daemon double-gate the network surface.

---

## 9. Failure scenarios & recovery

| Scenario | Detection | Recovery |
|---|---|---|
| Snapshot corrupted | `b3sum -c` fails, or SQLite integrity error / `verify_audit_chain()` fails at restore | Use an older snapshot. If none: data is lost (DEK + ciphertext are inseparable). |
| DEK rotation crash mid-way | `meta.rotation_in_progress = 1` at next unlock | Auto-resumes: resealed rows skipped, rest resealed, flag cleared (`ROADMAP.md` 20) |
| Keyslot set tampered post-backup | `meta.header_mac` mismatch → `HeaderMacMismatch`, unlock refuses (FS-S13) | Restore a known-good snapshot; investigate the source. No `--force`. |
| Audit chain tampered | `verify_audit_chain()` mismatch at a `seq` | Restore known-good; investigate. Fail-closed by design. |
| USB lost **and** passphrase lost | Unlock fails (no valid factor) | Unrecoverable by design (A5). This is why §0.4 mandates an independent offline USB-keyfile backup. |
| `sqld` process crash | `Store::health()` non-durable; daemon gated at startup | WAL auto-recovery on `sqld` restart; if corrupt, restore `vault.db` (§4). |
| Passphrase-only on-box vault after DR | FS-S22 startup refusal (`SERVER-MODE.md` 169) | Re-enroll a USB keyslot (§3.1) before relying on the box. |

---

## 10. Threat-model compliance summary

| REQ / threat | How backup/restore + rotation honors it | Source |
|---|---|---|
| REQ-SEC-1 (dry-run default on the wire) | `dek-rotate`/`rotate-passphrase`/`keyslot revoke`/`relay revoke --all` default `apply=false`; root-of-trust ops need `apply && confirm` | THREAT-MODEL 38 |
| REQ-SEC-5 (relay TTL ceiling; DEK rotation O(all) documented) | Full re-encryption is atomic + resumable; cost linear, stated; bearers survive via re-wrapped hmac_key | THREAT-MODEL 42; schema 66–69; OI-9 |
| REQ-SEC-6 (real-key isolation) | DEK never in the backup, never in a child env or on the wire; only ≤24h scoped bearers leave the TCB | THREAT-MODEL 43; ARCH 23 |
| REQ-SEC-8 (back up before clobber) | The "snapshot + `.b3` sidecar before any destructive op" discipline mirrors the trust-store backup-before-clobber rule | THREAT-MODEL 45 |
| A4 (stolen disk/backup) | Whole file is AEAD ciphertext; unwrappable only with the USB keyfile (64 B CSPRNG) OR the passphrase (Argon2id 1 GiB) | THREAT-MODEL 26; ARCH 66 |
| A5 (stolen USB) | USB is one slot; revoke + DEK-rotate after loss; keyfile *content* (not UUID) is the secret | THREAT-MODEL 27 |
| A12 (forced passphrase downgrade) | OR (1-of-2): strength == the weaker factor; mitigate with enforced passphrase entropy + Argon2id floor + optional require-both | THREAT-MODEL 34 |
| FS-S2 (no plaintext at rest) | Per-record XChaCha20-Poly1305; no SQLCipher/C-default surface; FS-S2 negative test in Phase 1 | THREAT-MODEL; ROADMAP 20 |
| FS-S13 (keyslot tamper) | `meta.header_mac` over slots+params; param floor in code; unlock refuses on drift | schema 22–23, 42–44; ARCH 81 |
| FS-S22 (on-box no-USB posture) | Daemon refuses to start without an enabled USB keyslot on-box | SERVER-MODE 169 |

---

## 11. Open questions / UNVERIFIED items

1. **Backup verb + `Store` method.** No `Store::backup`/`snapshot` exists
   (only `fsync_barrier()`/`health()`, `SERVER-MODE.md` 54–66). Decide: shell
   `VACUUM INTO` against loopback `sqld`, or add a first-class
   `envctl vault backup` that calls `fsync_barrier()` → snapshot → `.b3` →
   durable audit row. **[PROPOSED]**
2. **Exact snapshot mechanism against `sqld`.** Is the snapshot taken via the
   `sqld` admin/HTTP API, or the `sqlite3` CLI on the backing file? Confirm WAL
   consistency for the chosen path. **[UNVERIFIED]**
3. **System vs `--user` unit.** Which does the Phase-7 `envctl install secretd`
   component emit? It changes the stop/start commands, the `LimitMEMLOCK`
   plumbing, and `ReadWritePaths`. **[UNVERIFIED]**
4. **`LimitMEMLOCK=infinity` vs a bounded value.** Argon2id at m=1 GiB plus the
   mlocked key buffers want headroom; HF-4 notes the argon2 arena may be a
   "documented residual" if not mlocked. Size the limit deliberately. **[OPEN]**
5. **Ed25519 audit-head signing.** Recommended (`research/13` §4) but not
   implemented; needed so a full-backup-rewrite attacker cannot forge a
   consistent chain. **[PROPOSED]**
6. **Per-install / TPM-sealed USB salt (OI-18).** Until implemented, a bare
   keyfile copy on vfat/exfat is sufficient to unwrap the USB slot — physical
   possession is the boundary. Affects how the USB-keyfile backup itself must be
   stored. **[OPEN]**
7. **libsql-ffi version drift.** `0.9.30` pinned in `research/03`; re-verify it
   is still current and CVE-clean before the merge, and keep a periodic libSQL
   CVE watch for the scoped C waiver (`SERVER-MODE.md` 312). **[UNVERIFIED]**
8. **Off-box backup encryption layer.** The file is already AEAD'd; decide
   whether to add a transport/storage envelope (age, S3 SSE-C) for
   defense-in-depth + integrity, and where the off-band `.b3` reference lives.
   **[OPEN]**
9. **Replication adoption.** If embedded replicas are ever turned on, enforce
   "non-secret metadata only, read-only, never Last-Push-Wins for
   audit/revocation" (OI-SM-8). Currently out of scope. **[VERIFIED out-of-scope]**

---

## 12. Sources

**Repo (verified this pass, 2026-06-02):**
- `/home/drdave/Desktop/env-ctl/docs/ARCHITECTURE.md` — lines 20–23 (TCB/mlock),
  65–66 (backup boundary), 73–81 (key hierarchy, DEK rotation, header MAC),
  103 (USB-pull auto-relock, lock as panic stop), 111–113 (CA/trust),
  125–127 (paths), 134–137 (merge, verbs, SystemdUnit).
- `/home/drdave/Desktop/env-ctl/docs/SERVER-MODE.md` — 7–9/75 (separate-`sqld`
  + pure-Rust remote client), 41 (untrusted storage / no at-rest crypto),
  54–66 (`Store` trait: `fsync_barrier`, `health`, `StoreHealth`), 91 (listener
  self-check), 165/237–238/254 (Profile B), 169 (FS-S22), 210 (control
  unreachable), 312 (C-waiver CVE watch), 327 (OI-SM-8 replication).
- `/home/drdave/Desktop/env-ctl/docs/THREAT-MODEL.md` — 13/26 (A4), 27 (A5),
  34 (A12), 38–45 (REQ-SEC-1/5/6/8), 56 (FS-S5), 62–63 (FS-S11/12).
- `/home/drdave/Desktop/env-ctl/docs/DESIGN-NOTES.md` — 14 (1-of-2 framing),
  42 (HF-1 DEK rotation), 44 (HF-3 keyslot_aad), 45 (HF-4 mlock), 56 (HF-14
  durable audit), 75 (KDF profile), 112 (OI-9 hmac_key), 121 (OI-18).
- `/home/drdave/Desktop/env-ctl/docs/ROADMAP.md` — 5 (phasing/NEW-3), 19–20
  (Phase 1 vault core + DEK rotation acceptance), 43 (Phase 7 merge/SystemdUnit).
- `/home/drdave/Desktop/env-ctl/docs/db/schema.sql` — full canonical schema
  (meta 24–28, hmac_key 30–39, keyslots 45–63, dek_generation 70–75,
  secret_versions 94–104, relay_bearers 128–151, audit_log 159–169,
  ca_key 174–186, certs 188–209).
- `/home/drdave/Desktop/env-ctl/docs/SCAFFOLD-SPEC.md` — engine method
  signatures (206–216), `EngineError` (330–337), crate layout.
- `/home/drdave/Desktop/env-ctl/docs/research/03-libsql-server.md` — 9 (embedded
  modes bundle C SQLite), 37–46 (embedded replicas), 95/99 (versions: libsql
  0.9, libsql-ffi 0.9.30; pure-Rust `remote` feature).
- `/home/drdave/Desktop/env-ctl/docs/research/13-tamper-evident-audit.md` —
  hash chaining + Ed25519 head signing + RFC 8785 canonicalization.

**External (cited; mark [UNVERIFIED] until re-fetched at build time):**
- SQLite `VACUUM INTO`: <https://www.sqlite.org/lang_vacuum.html#vacuuminto>
- SQLite WAL mode: <https://www.sqlite.org/wal.html>
- RFC 9106 — Argon2: <https://datatracker.ietf.org/doc/html/rfc9106>
- RFC 5869 — HKDF: <https://www.rfc-editor.org/rfc/rfc5869>
- CFRG XChaCha20-Poly1305 draft: <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03>
- RFC 8785 — JSON Canonicalization Scheme: <https://www.rfc-editor.org/rfc/rfc8785>
- RustCrypto NCC audit (2019): <https://www.nccgroup.com/us/research-blog/public-report-rustcrypto-aes-gcm-and-chacha20poly1305-implementation-review/>
- systemd.timer: <https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html>
- systemd.exec (LimitCORE/LimitMEMLOCK): <https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html>
- Turso embedded replicas: <https://docs.turso.tech/features/embedded-replicas/introduction>
- libSQL replication internals: <https://blog.canoozie.net/libsql-replication/>
