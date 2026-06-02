# env-ctl ops — USB key ceremony, keyslot enrollment, recovery

> Status: ops/deploy design for **Profile A (on-box, dual-RTX-5090 dev box)**, the default and only shippable
> posture today. Targets the real subsystem `crates/secrets-engine/src/keyslot.rs` (LUKS-style dual-KEK wrap)
> plus `secretd` lifecycle and the `envctl secret|vault|relay|ca|run` CLI surface that this codebase merges into.
> Cross-refs: `../ARCHITECTURE.md`, `../THREAT-MODEL.md`, `../SERVER-MODE.md`, `../DESIGN-NOTES.md`, `../ROADMAP.md`.
> Scope: this doc covers the **operator ceremony, keyslot lifecycle, and recovery path** only. It is READ-ONLY
> design — no code exists yet for these verbs (Phase 2 per `../ROADMAP.md`); Phase 0 ships `todo!()` guard bodies.
> Items not yet decided or not yet in the design docs are flagged **UNVERIFIED** or **PROPOSED** inline.

---

## 0. TL;DR — the recommended ceremony for THIS box

1. `envctl install secretd` → user service under `$XDG_RUNTIME_DIR`; the daemon **refuses to start on-box with no
   enabled USB keyslot** (FS-S22, `../SERVER-MODE.md` §5.2). So you enroll the USB *before/at* first unlock.
2. **Enroll the USB keyslot** from a blank, **GPT-partitioned** stick:
   `envctl vault keyslot enroll --usb /dev/disk/by-partuuid/<PARTUUID> --generate-keyfile --apply`
   → daemon generates a 64-byte CSPRNG keyfile onto the partition, derives `KEK_usb = HKDF-SHA256(keyfile, salt32,
   info="env-ctl/v1/kek/usb")`, wraps the one DEK under it (XChaCha20-Poly1305), and records the slot durably.
3. **Enroll a passphrase keyslot** as the explicit fallback (entropy-enforced):
   `envctl vault keyslot enroll --passphrase --apply` → `KEK_pp = argon2id(m=1 GiB, t=4, p=4)`.
4. **(PROPOSED)** enroll a recovery factor for the "USB lost AND passphrase forgotten" case (see §4 — this is a
   *design proposal*, not yet in the canonical docs; flagged UNVERIFIED).
5. Eject and physically secure the USB. Pull-the-USB is the panic stop: auto-relock zeroizes the DEK + in-RAM CA
   Issuer after a drain grace (default-ON, OI-4).

**One honest sentence:** the **keyfile content is the secret**; the PARTUUID is only a fast pre-filter to avoid
auto-unlocking off the *wrong* stick (CF-4 / `../THREAT-MODEL.md` design note). Physical possession of the USB is
the at-rest security boundary on vfat/exfat where `0400` is advisory (A11/A18).

---

## 1. Threat model the ceremony has to satisfy

Pulled directly from `../THREAT-MODEL.md` and `../DESIGN-NOTES.md` so the ceremony's choices are traceable:

| ID | Adversary / state | Why it shapes the ceremony |
|----|-------------------|----------------------------|
| **A4** | Stolen disk / backup | Vault rows are app-layer XChaCha20-Poly1305; the DEK is wrapped under USB-KEK/passphrase-KEK keyslots; the unwrap key is never on disk. The ceremony must never write the DEK or a KEK to disk in clear. |
| **A5** | Stolen USB key | USB is **one** keyslot; the keyfile *content* is the secret, not the UUID. Ceremony must let the operator revoke the USB slot + rekey. |
| **A11/A18** | Local read of the mounted keyfile / vfat ignores mode bits | Mount read-only, read keyfile into `Zeroizing`, never copy to a temp file; warn when the FS ignores `0400`. |
| **A12 / CF-3 / FS-S13** | Attacker-forced passphrase-fallback downgrade | The two factors are an **OR (1-of-2)**, not 2FA — strength == the **weaker** factor (passphrase argon2id work vs an offline attacker with `vault.db`). Enroll-time entropy enforcement + optional **require-both** keyslot. |
| **CF-4 / FS-S22** | UUID spoofing / gate backs nothing | `UsbPresent` PROVES keyfile possession (must unwrap the slot or match a vault-resident keyed MAC). On-box daemon refuses to serve USB-gated egress with no enabled `usb_keyfile` slot. |
| **HF-3 / OI-8** | Silently-added / param-downgraded keyslot | `keyslot_aad` binds all KDF-determining fields; a DEK-authenticated **vault header MAC** covers the whole slot set; unlock refuses on drift. |
| **OI-17 / FS-S9** | Slot-existence oracle / unreadable identifier | Single generic `UnlockFailed`; try every enabled slot; `UsbPresent` **refuses** (never panics) when the identifier is unreadable. |

Design invariants the ceremony inherits (`../ARCHITECTURE.md`):

- **`apply`/`confirm` are the safe-by-default wire defaults.** Every destructive RPC carries proto3 `bool apply`
  (default `false` == dry-run) plus `bool confirm` for RootOfTrust ops. An all-zero/omitted request is dry-run.
  Enroll/rotate/revoke are dry-run unless `--apply`; root-of-trust destruction also needs `--confirm`.
- **Resolve-once `UnlockContext` (REQ-SEC-2):** USB possession + peer uid resolve ONCE per op; guards never
  re-resolve mid-op (no TOCTOU).
- **All key material** (`Dek`, `Kek`, passphrase, keyfile, CA `Issuer`) lives in `Zeroizing`/`ZeroizeOnDrop`,
  is never `Serialize`, and the daemon runs with `mlockall` + `RLIMIT_CORE=0` + `MADV_DONTDUMP` (refuse to start
  if `mlockall` fails — FS-S4).

---

## 2. The keyslot crypto (canonical, from `../DESIGN-NOTES.md` §"Key handling")

This is the contract the ceremony must produce. Reproduced verbatim from the design docs so ops snippets below
are demonstrably aligned, not invented.

```
USB slot KEK:        KEK_usb = HKDF-SHA256(ikm = keyfile_64B, salt = salt32, info = b"env-ctl/v1/kek/usb")
                     (the keyfile is already 64-B CSPRNG — argon2 on auto-unlock would be wrong)
Passphrase slot KEK: KEK_pp  = argon2id(passphrase, salt, params)
                     built as Argon2::new(Algorithm::Argon2id, Version::V0x13, params)  -- NEVER Argon2::default()
                     default + enforced floor: m = 1 GiB, t = 4, p = 4

Keyslot wrap (LUKS-style, one DEK, EITHER factor opens it):
  wrapped_dek = XChaCha20-Poly1305(KEK).seal(DEK, nonce24, aad = keyslot_aad)
  -- the AEAD tag IS the correctness oracle (wrong factor => tag mismatch => no plaintext, no separate verifier)

keyslot_aad (binds ALL KDF-determining + identity fields; HF-3):
  b"env-ctl/v1/keyslot"
    || u8(factor) || u8(kdf_id)
    || u32be(m_kib) || u32be(t_cost) || u32be(p_lanes)
    || len32(salt) || salt
    || len32(uuid) || uuid
    || u64be(dek_generation) || u64be(slot_id)

Per-record envelope (recomputed at decrypt from trusted columns, NEVER read from a stored column):
  AAD = b"env-ctl/v1" || u8(table_tag) || u64be(secret_id) || u64be(version) || u64be(dek_generation)

Vault header MAC: DEK-authenticated MAC over all slots' {factor, kdf_id, params, salt, count} + issuance floor.
  Recomputed on unlock; unlock REFUSES on drift (detects a silently-added/downgraded slot, swapped UUID,
  rewound floor).
```

KDF / AEAD / RNG facts and pinned crate roles (from `../ARCHITECTURE.md` deps row; versions are the *families*
this repo pins — confirm exact pins in `Cargo.toml` at implementation, UNVERIFIED here):

| Primitive | Standard / source | Crate (role) |
|-----------|-------------------|--------------|
| HKDF-SHA256 | RFC 5869 — <https://datatracker.ietf.org/doc/html/rfc5869> | `hkdf` + `sha2` |
| Argon2id v1.3 (`0x13`) | RFC 9106 — <https://datatracker.ietf.org/doc/html/rfc9106>; PHC reference <https://github.com/P-H-C/phc-winner-argon2> | `argon2` (explicit `Argon2::new`, never `default()`) |
| XChaCha20-Poly1305 (24-B nonce AEAD) | RFC 8439 (ChaCha20-Poly1305) — <https://datatracker.ietf.org/doc/html/rfc8439>; XChaCha draft <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03> | `chacha20poly1305` |
| Keyed BLAKE3 (possession MAC, audit chain) | <https://github.com/BLAKE3-team/BLAKE3>; `keyed_hash` <https://docs.rs/blake3> | `blake3` |
| CSPRNG (all nonces/keyfiles/salts) | `OsRng`; OI-16 mandates `OsRng` for ALL seal-path nonces, forbids seeded RNG behind non-test cfg | `rand` + `getrandom` |
| Memory hygiene | zero-on-drop, no `Serialize` | `zeroize`, `subtle` |

> NOTE on the earlier internal finding that cited "RFC 7539": RFC 7539 was **obsoleted by RFC 8439**. Cite **RFC
> 8439** for ChaCha20-Poly1305; XChaCha20's 24-byte nonce is specified by the CFRG XChaCha draft above. Corrected here.

---

## 3. USB identifier resolution — pin GPT PARTUUID, reject everything else (OI-5)

**Decision (OI-5, `../DESIGN-NOTES.md`):** pin the **GPT PARTUUID**, NOT the filesystem UUID.

- PARTUUID is a per-partition 128-bit GUID from the GPT partition entry, stable across reformat of the filesystem
  on that partition. GUID Partition Table spec: <https://uefi.org/specifications> (UEFI spec, GPT section);
  overview <https://en.wikipedia.org/wiki/GUID_Partition_Table>.
- Filesystem UUID (`blkid -U`) changes on reformat and is the wrong selector — reject it.
- **Reject the MBR pseudo-PARTUUID** form (`SSSSSSSS-NN`, a 32-bit disk signature + partition index). A valid GPT
  PARTUUID is a 36-char canonical GUID (`8-4-4-4-12`). Enroll must validate the format and refuse non-GPT.

Resolution methods (authoritative = poll; udev is an optional nudge only):

```bash
# Authoritative read of a partition's GPT PARTUUID (util-linux blkid; -s selects field, -o value prints bare):
#   man: https://man7.org/linux/man-pages/man8/blkid.8.html
blkid -o value -s PARTUUID /dev/sdXN

# The kernel/udev-maintained stable symlink the daemon polls (fail-closed if absent):
#   man: https://man7.org/linux/man-pages/man7/udev.7.html
ls -l /dev/disk/by-partuuid/
#   /dev/disk/by-partuuid/<PARTUUID> -> ../../sdXN
```

- **R8 (`../DESIGN-NOTES.md`):** the PARTUUID **poll is authoritative and fail-closed**. `udev` is **OFF by
  default** and may only *nudge* the poller — making libudev (C) mandatory would violate the pure-Rust posture.
  Pure-Rust `udev` bindings exist (the `udev` crate) but are not required; the poller is the source of truth.
- **`UsbPresent` is a pre-filter + cryptographic possession proof** (CF-4): match PARTUUID → then prove the
  keyfile unwraps the USB slot (or matches the vault-resident keyed MAC). A forged-UUID stick with the wrong
  keyfile does NOT pass (Phase 2 acceptance, `../ROADMAP.md`).
- The enrolled UUID is **never emitted on the wire** (`StatusResp.usb_partuuid` removed — it leaked the gate
  selector).

> **Version note (UNVERIFIED, low risk):** `blkid -s PARTUUID` is present in modern util-linux; `/dev/disk/by-partuuid/`
> symlinks are maintained by systemd-udev (>= v183 era for by-partuuid). Assume any util-linux >= 2.36 / systemd
> >= 250 on this Ubuntu 26.04 box is fine; confirm with `blkid --version` / `udevadm --version` at deploy. The
> Arch wiki "Persistent block device naming" page documents the same selectors but served an anti-bot challenge
> when fetched — claims corroborated against man7.org and the UEFI/Wikipedia GPT references above.

---

## 4. The ceremony, step by step (concrete verbs + I/O)

> CLI namespace: this subsystem **merges into `envctl`** (`../ARCHITECTURE.md`: "CLI verbs fold under
> `envctl secret|vault|relay|ca|run`"). Keyslot ops live under `envctl vault keyslot …`. The earlier internal
> finding wrote `env-ctl …`; the binary is **`envctl`**. Corrected throughout.

### 4.0 Pre-flight

```bash
envctl install secretd        # manifest SystemdUnit; user service under $XDG_RUNTIME_DIR (../SERVER-MODE.md §5.2)
lsblk -o NAME,SIZE,TYPE,PARTUUID,FSTYPE,MOUNTPOINT   # confirm the blank GPT stick + its PARTUUID
```

The daemon **refuses to start on-box** until a USB keyslot is enrolled (FS-S22). First-run flow either enrolls in
a setup mode or the operator enrolls against an unlocked-with-bootstrap-passphrase vault; either way the USB slot
is created before the box serves USB-gated egress. (**OPEN — see §7:** exact first-unlock bootstrap is not pinned
in the docs.)

### 4.1 Enroll the USB keyslot

```bash
# Dry-run is the DEFAULT (no --apply): prints exactly what would happen, mutates nothing.
envctl vault keyslot enroll \
    --usb /dev/disk/by-partuuid/c0ffee0c-a11e-4ded-babe-cafe00000001 \
    --generate-keyfile
```

```
DRY-RUN (no --apply)
  Slot:            usb (next free slot_id = 1)
  PARTUUID:        c0ffee0c-a11e-4ded-babe-cafe00000001   [GPT GUID, validated]
  Keyfile:         <USB>/env-ctl/keyfile   (64-byte CSPRNG, mode 0400 [advisory on vfat/exfat])
  KEK derivation:  HKDF-SHA256(keyfile, salt32, info="env-ctl/v1/kek/usb")
  DEK wrap:        XChaCha20-Poly1305(KEK_usb).seal(DEK, nonce24, aad=keyslot_aad)
  Header MAC:      will be recomputed over the new slot set
  Re-run with --apply to write.
```

```bash
envctl vault keyslot enroll \
    --usb /dev/disk/by-partuuid/c0ffee0c-a11e-4ded-babe-cafe00000001 \
    --generate-keyfile --apply
```

```
APPLIED
  + keyfile written to <USB>/env-ctl/keyfile (64 bytes, 0400)
  + slot_id=1 (usb) wrapped_dek committed durably to vault.db (fsync barrier before success)
  + header MAC updated
  WARNING: the keyfile CONTENT is the secret. On vfat/exfat 0400 is advisory — any same-session
           process can copy it while mounted (A11/A18). Physical possession IS the boundary.
  Event: KeyslotEnrolled{ factor="usb", slot_id=1 }   (PARTUUID is NOT echoed to the wire)
```

Daemon-side obligations (mirrors `keyslot.rs` contract, OI-7/OI-16):

- Generate keyfile with `OsRng`; mount the partition **read-only**, write keyfile, never to a temp file; read it
  back into `Zeroizing`.
- Derive `KEK_usb` per §2; consume the `Kek` **by value** in `wrap_dek` so it is short-lived; zeroize the argon2
  arena / hkdf scratch (OI-7).
- Persist the slot + recompute the header MAC, then `fsync` **before** returning success (durable-before-ack).
- Emit `KeyslotEnrolled` (best-effort event); write the **durable** `audit_log` row. Never log keyfile/KEK/DEK.

### 4.2 Enroll the passphrase keyslot (the explicit, entropy-enforced fallback)

```bash
envctl vault keyslot enroll --passphrase           # dry-run: shows KDF params + entropy estimate only
envctl vault keyslot enroll --passphrase --apply   # prompts twice; zeroized after use
```

```
APPLIED
  + slot_id=2 (passphrase) committed durably
  KDF:        argon2id(m=1 GiB, t=4, p=4)   [explicit Argon2::new(Argon2id, V0x13, params); params bound in keyslot_aad]
  Salt:       32-byte CSPRNG (per-slot)
  Entropy:    estimated >= floor (low-entropy passphrase REJECTED at enroll — Phase 2 acceptance)
  Event: KeyslotEnrolled{ factor="passphrase", slot_id=2 }
```

- **A12 stated plainly:** with both slots enabled, vault strength against an offline `vault.db` attacker == the
  **passphrase argon2id work factor** (the weaker factor). The attacker can *force* the downgrade by inducing
  USB-absent. This is why entropy is enforced at enroll and why **require-both** exists.

### 4.3 (Optional) require-both keyslot — defeat the forced downgrade

```bash
envctl vault keyslot enroll --require-both --usb /dev/disk/by-partuuid/<UUID> --apply
# KEK = KDF(usb_keyfile || passphrase) -> single slot needs BOTH factors; no 1-of-2 downgrade path.
```

This is the structural 2FA: a single slot whose KEK derives from **both** the keyfile and the passphrase, so
yanking the USB does not open a weaker path (CF-3 mitigation). Trade-off: lose either factor and that slot is
dead — pair it with a separate recovery slot (§4.4) or you can brick yourself. (Design-listed as **optional** in
`../ROADMAP.md` Phase 2.)

### 4.4 (PROPOSED — UNVERIFIED) Recovery keyslot

> **Flagged:** a dedicated "recovery" factor (a daemon-generated high-entropy secret, printed once for offline
> storage) is **not** in the canonical design docs. The docs' recovery story today is: **the passphrase keyslot
> IS the recovery factor**, plus `keyslot revoke --usb` + DEK rekey to drop a lost stick. The internal finding
> proposed a third "recovery" slot encoded as "3-of-39 BIP39 words." That **3-of-39** encoding is *non-standard*
> (BIP-39 word counts are 12/15/18/21/24; spec <https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki>).
> If a recovery slot is adopted, prefer either a **standard 24-word BIP-39 mnemonic** (256-bit entropy) or a plain
> **base32/hex 32-byte code** — do not invent a "3-of-39" scheme. Recommendation: treat §4.4 as a Phase 2/3
> design decision, not a shipped feature. The rest of this doc does not depend on it.

If adopted, the shape would mirror §4.1 (HKDF over a 64-B CSPRNG recovery secret, wrapped into its own slot,
printed once with a visual boundary, never logged/transmitted, destroyed from RAM after the operator confirms).

### 4.5 Verify and lock

```bash
envctl vault keyslot list        # metadata-only, NO unlock side-effect
```

```
SLOT  FACTOR       ENABLED  KDF        CREATED
1     usb          true     hkdf-sha256 2026-06-02T14:30:45Z
2     passphrase   true     argon2id    2026-06-02T14:32:10Z
```

```bash
envctl vault unlock                       # USB present -> auto-unlock, no prompt
envctl vault lock                          # zeroize DEK + in-RAM CA Issuer (the true panic stop)
envctl vault unlock --passphrase           # USB absent -> passphrase path
envctl audit query --action 'unlock|keyslot'   # durable rows; NO plaintext factor ever logged
```

---

## 5. Keyslot lifecycle: rotate, revoke, rekey

From `../ARCHITECTURE.md` / `../ROADMAP.md` Phase 2. **Two rotations, very different costs:**

```bash
# Cheap: passphrase rotation = single keyslot rewrite (re-wrap the SAME DEK under a new passphrase-KEK).
envctl vault keyslot rotate-passphrase --apply

# Drop a lost/stolen USB: disable+rekey leaves the vault passphrase-openable (Phase 2 acceptance).
envctl vault keyslot revoke --usb --apply           # refuses if it would leave zero enabled slots
envctl vault rekey --apply --confirm                # full DEK re-encryption (see below)

# Expensive: DEK rotation = FULL re-encryption (NOT a keyslot-only rewrite).
envctl vault rekey --apply --confirm
```

`vault rekey` semantics (`../ARCHITECTURE.md`): under one atomic txn with a resumable `rotation_in_progress` meta
flag, **every** ciphertext row (`secret_versions`, `ca_key`, `certs`) is decrypted with the OLD DEK and re-sealed
with the NEW DEK + fresh nonce + AAD bound to `new_generation`; then `keyslots.wrapped_dek` is rewritten for every
enabled slot, `meta.active_dek_generation` advances, the old generation is tombstoned, and only THEN is the old DEK
dropped. Cost is O(all secrets). `hmac_key` is a separate sealed row stable across DEK rotation, so **DEK rotation
does not invalidate live relay bearers** (OI-9).

Guard rules:
- All three are **dry-run unless `--apply`**; `rekey` is RootOfTrust → also needs `--confirm`.
- `revoke` **refuses to disable the last enabled slot** (fail-closed; you cannot brick the vault by accident).
- Every keyslot mutation re-verifies + rewrites the header MAC and writes a durable audit row (OI-8/OI-11).
- No `--force` bypasses any guard (`../ARCHITECTURE.md`).

---

## 6. USB-pull, auto-relock, and the grace window (OI-4)

**Default-ON auto-relock (review fix — was default-off).** Pulling the enrolled USB zeroizes the DEK *and* the
in-RAM CA `Issuer` after a short **drain grace**. `lock` / idle-timeout zeroize on demand. `relay revoke --all`
(durable, count-reporting) + `lock` are the containment actions (`../ARCHITECTURE.md`).

**Plane-specific grace (`../SERVER-MODE.md` §"Profile A" / OI-4):**

| Plane | Grace | Why |
|-------|-------|-----|
| Local same-box (control + `envctl run` children) | ~5 min (PROPOSED, **OPEN OI-4**) | A UX cushion for a "brief USB jiggle mid-command"; tune in Phase 2/3. |
| Remote relay edge (Telegram cloud agent, phone, laptop) | **short or zero** | A **security** parameter, not UX: on USB-absent, deny NEW remote egress immediately; re-run `decide()` mid-stream so an in-flight remote stream aborts within grace (extends FS-S5). |

`decide()` treats an **`Unproven`** presence factor **exactly like `AbsentSince(now)`** — immediate deny, no grace
(`../SERVER-MODE.md`). There is no second gate bolted beside `decide()`.

Operationally: **pull the stick → remote egress stops within the (short/zero) remote grace; local children get the
UX grace; the DEK is gone from RAM after the drain.** Re-insert + the keyfile must still *prove possession* to
resume — a clone with the wrong keyfile does not resume the gate.

---

## 7. Systemd unit + on-box deploy (Profile A)

`secretd` ships as a manifest `SystemdUnit` component: `envctl install secretd` stands it up, `envctl reset secretd`
unwinds it via the same guarded Wiring revert (`../ARCHITECTURE.md`). It runs as a **user service** under
`$XDG_RUNTIME_DIR` (`../SERVER-MODE.md` §5.2). Control is local-only over a UDS with `SO_PEERCRED` == owner;
**only the relay HTTPS edge is network-exposed**; the embedded `sqld`/vault is loopback-only.

> The exact unit text below is **PROPOSED/illustrative** to satisfy "concrete unit snippet" — it is not checked
> into the repo and the manifest `SystemdUnit` component is the source of truth. Flagged UNVERIFIED.

```ini
# ~/.config/systemd/user/secretd.service   (PROPOSED — illustrative; manifest SystemdUnit is canonical)
[Unit]
Description=env-ctl secretd (secrets vault + credential broker)
Documentation=https://example.invalid/env-ctl/docs/ARCHITECTURE.md
After=default.target

[Service]
Type=notify
# Loopback-only embedded sqld + pure-Rust libSQL `remote` client (C core isolated in a separate process):
ExecStartPre=/usr/bin/sqld --http-listen-addr 127.0.0.1:8081 --db-path %h/.local/share/env-ctl/vault.db
ExecStart=/usr/local/bin/secretd --store-profile embedded --no-tcp-control
# Startup self-check: refuse to start unless exactly one non-loopback listener (the relay edge) exists,
# control is a UDS under XDG_RUNTIME_DIR, and an enabled usb_keyfile slot exists (FS-S8/FS-S22).
Restart=on-failure
RestartSec=2

# --- Memory hygiene the daemon ALSO asserts in-process (mlockall etc.); these are defense-in-depth ---
LimitCORE=0                      # RLIMIT_CORE=0 (no coredump leak)
MemoryDenyWriteExecute=true
LockPersonality=true
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%h/.local/share/env-ctl %t/env-ctl     # %t = $XDG_RUNTIME_DIR (control.sock dir, 0700)
PrivateTmp=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6       # AF_UNIX (control) + INET (relay edge) only
SystemCallFilter=@system-service
# CAP_IPC_LOCK so mlockall succeeds without raising RLIMIT_MEMLOCK; daemon refuses to start if mlockall fails (FS-S4)
AmbientCapabilities=CAP_IPC_LOCK
CapabilityBoundingSet=CAP_IPC_LOCK

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now secretd.service
journalctl --user -u secretd -f        # operational logs (NEVER contains keyfile/KEK/DEK/passphrase)
```

Control-plane reachability check (deploy smoke test, `../SERVER-MODE.md` §3): every control verb must be
**undialable off-box** (UDS only, no TCP control bind anywhere); a valid DPoP-bound relay swap succeeds; USB-pull
stops remote egress within grace.

VPS (**Profile B**) is **non-shippable** until the operator-authorizer protocol (OI-SM-2) and trusted-time
(OI-SM-3) are designed — out of scope for this ceremony doc. With no USB present the keyslot model collapses to
the passphrase argon2id work factor and the DEK lives in untrusted VPS RAM (`../SERVER-MODE.md` §"VPS"). Profile A
is the default for this box for exactly this reason.

---

## 8. Disaster-recovery runbook

```bash
# Case 1: USB lost, passphrase known.
envctl vault unlock --passphrase
envctl vault keyslot revoke --usb --apply           # drop the lost stick's slot
envctl vault keyslot enroll --usb /dev/disk/by-partuuid/<NEW_UUID> --generate-keyfile --apply
envctl vault rekey --apply --confirm                # rekey so the lost keyfile cannot ever unwrap a future DEK

# Case 2: stick suspected cloned/stolen (A5) — same as Case 1, do it NOW; rekey is the point.
envctl vault lock                                   # panic stop first (zeroize DEK + CA Issuer in RAM)
envctl relay revoke --all --apply                   # durable, count-reporting; kills outstanding bearers
#   ... then Case 1 revoke + enroll + rekey ...

# Case 3: USB lost AND passphrase forgotten.
#   With ONLY {usb, passphrase} slots: the vault is UNRECOVERABLE by design (A4 — no backdoor).
#   This is why §4.2 (passphrase) is mandatory and §4.4 (recovery slot) is the proposed extra net.
#   If a recovery slot (§4.4) was enrolled:  envctl vault unlock --recovery   (then re-enroll USB + rekey).
```

Audit after any recovery: `envctl audit query --action 'keyslot|rekey|relay'` — confirm the durable rows; no
plaintext factor is ever present.

---

## 9. Open questions (load-bearing for ops)

| Ref | Question | Impact / status |
|-----|----------|-----------------|
| **OI-4** | Local grace-window length (proposed ~5 min) and its interaction with long-running `envctl run` egress. | Operational tuning. Remote grace is separately short/zero (§6). Tune in Phase 2/3. |
| **First-unlock bootstrap** | Exact flow that gets the *first* USB slot enrolled given "daemon refuses to start with no USB slot" (FS-S22). Setup mode vs bootstrap passphrase? | **OPEN** — not pinned in the docs; blocks a clean first-run ceremony script. Needs a design decision. |
| **§4.4 recovery slot** | Adopt a dedicated recovery keyslot? If so, encoding = standard 24-word BIP-39 or base32/hex (NOT the non-standard "3-of-39"). | **PROPOSED/UNVERIFIED.** Today the passphrase slot is the recovery factor. Decide in Phase 2/3. |
| **OI-18 / A18** | TPM-sealed or per-install salt so a *bare keyfile copy* is insufficient (clone resistance beyond physical possession). | Stretch goal. Would materially strengthen A5/A11. Phase 3+. |
| **OI-6** | Clock-rollback hardening (`CLOCK_BOOTTIME`/audit high-water) interacts with USB-absent timestamps driving the drain. | Phase 3. Owner-writable floor → effective vs accident + external attacker, not owner-session malware. |
| **Crate pins** | Exact pinned versions of `argon2`/`hkdf`/`chacha20poly1305`/`blake3`/`zeroize`/`rand` in `Cargo.toml`. | **UNVERIFIED here** (no code yet, Phase 0/1). Confirm at implementation; the *families/standards* in §2 are fixed. |
| **util-linux / udev versions** | Exact minimum `blkid`/`udev` versions on Ubuntu 26.04 for `by-partuuid` + `-s PARTUUID`. | **UNVERIFIED.** Assume modern (>= util-linux 2.36 / systemd 250). Confirm with `blkid --version` at deploy. |
| **OI-SM-2 / OI-SM-3** | VPS (Profile B) operator-authorizer protocol + trusted-time. | **Non-shippable** until designed; out of scope here. Profile A is the only supported posture for this box. |

---

## 10. Sources

- RFC 5869 (HKDF) — <https://datatracker.ietf.org/doc/html/rfc5869>
- RFC 9106 (Argon2) — <https://datatracker.ietf.org/doc/html/rfc9106>
- RFC 8439 (ChaCha20-Poly1305; obsoletes RFC 7539) — <https://datatracker.ietf.org/doc/html/rfc8439>
- CFRG XChaCha draft (24-byte nonce) — <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03>
- Argon2 PHC reference — <https://github.com/P-H-C/phc-winner-argon2>
- BLAKE3 — <https://github.com/BLAKE3-team/BLAKE3>; `keyed_hash` API — <https://docs.rs/blake3>
- BIP-39 (mnemonic; note the standard word counts) — <https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki>
- `blkid(8)` — <https://man7.org/linux/man-pages/man8/blkid.8.html>
- `udev(7)` — <https://man7.org/linux/man-pages/man7/udev.7.html>
- GUID Partition Table — UEFI spec <https://uefi.org/specifications>; overview <https://en.wikipedia.org/wiki/GUID_Partition_Table>
- Internal: `../ARCHITECTURE.md`, `../THREAT-MODEL.md` (A4/A5/A11/A12/A18, REQ-SEC-*, FS-S*), `../SERVER-MODE.md`
  (Profiles A/B, plane-specific grace, FS-S20..S25, OI-SM-2/3), `../DESIGN-NOTES.md` (CF-3/CF-4, HF-3, R8,
  OI-4/5/7/8/9/16/17/18), `../ROADMAP.md` (Phase 0/1/2/3 scope + acceptance).
- VMScape (cited in `../SERVER-MODE.md` for VPS RAM exposure) — CVE-2025-40300. **UNVERIFIED** against an upstream
  advisory from this doc; carried as-cited from the design docs.
