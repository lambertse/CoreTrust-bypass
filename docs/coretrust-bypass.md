# How the CoreTrust bypass works

This is a step-by-step walkthrough of what `ct_bypass::CoreTrustBypass` does and
why. It re-signs an already ad-hoc-signed Mach-O **in place** so that iOS's
CoreTrust accepts it without a real Apple signature. It implements the
**CVE-2023-41991** technique popularised by TrollStore.

> Educational / authorised-research note: this documents a public code-signing
> technique on binaries you own. It does not defeat FairPlay encryption — the
> input must already be a decrypted, ad-hoc-signed Mach-O.

## Background: what CoreTrust checks

A Mach-O's signature lives in a **SuperBlob** pointed at by `LC_CODE_SIGNATURE`.
The SuperBlob is a small index of **blobs**, each in a numbered *slot*:

| Slot | Contents |
|------|----------|
| `0` (`kCodeDirectory`) | the primary **CodeDirectory** |
| `5` / `7` | entitlements (XML and DER) |
| `0x1000` (`kAlternateCodeDirectories`) | an alternate CodeDirectory (e.g. a SHA-256 one next to a SHA-1 one) |
| `0x10000` (`kSignature`) | the CMS signature over the CodeDirectory's hash |

A **CodeDirectory** hashes every page of the binary (code slots) plus the other
blobs (special slots), and carries the identity strings. Its own hash is the
**cdhash**, and that is what the CMS signature signs.

**CVE-2023-41991** was a flaw in how CoreTrust validated a CMS signature that
carries more than one signer, which let a mix-and-match signature pass
validation. For the exact validation flaw, see the CVE write-ups and the
TrollStore documentation; what matters here is the structure this code builds,
which exploits it.

The signature is a CMS whose signed content is the **slot-0** CodeDirectory's
hash. The bypass presents:

- **slot 0:** a genuine, Apple-signed App Store CodeDirectory (SHA-1), taken
  verbatim from a real App Store binary. Apple's own signer in the template CMS
  already vouches for this CodeDirectory, so that signer stays **byte-for-byte**
  unchanged and still verifies against Apple's chain.
- **slot 0x1000:** *our* CodeDirectory (SHA-256) describing the real code,
  carrying the **same Team ID** as the App Store one and with its flags cleared.

A **second** signer (the TrollStore CA) is then added to the same CMS. Its signed
attributes list the cdhashes of both CodeDirectories, so the CMS vouches for our
real code while Apple's untouched signer keeps the signature acceptable. Both
CodeDirectories must agree on the Team ID, which is why step 5 copies it across.

## The steps (mapping to `CoreTrustBypassImpl::bypass()`)

1. **Load the Mach-O** — `MachO::load`. A thin 64-bit Mach-O is required.

2. **Reject unsupported inputs** — `detail::check_supported_macho`. Encrypted
   binaries (`kErrMachoEncrypted`) and object/dSYM files (`kErrMachoFiletype`)
   can't be signed this way.

3. **Decode the existing signature** — `detail::load_code_signature` reads the
   `LC_CODE_SIGNATURE` range and parses it into a `SuperBlob`. The binary must
   already be at least ad-hoc signed (`kErrNoCodeSignature` / `kErrDecodeSuperBlob`).

4. **Swap in the App Store CodeDirectory** — `detail::swap_in_app_store_cd`:
   - Pick the **real** CodeDirectory to keep: the SHA-256 alternate if the
     binary already has one, otherwise the main one. It must be SHA-256
     (`kErrCodeDirNotSha256`).
   - Remove both CodeDirectory slots, then re-add the real one at slot `0x1000`.
   - Insert the bundled App Store CodeDirectory at slot `0`, and read its
     **Team ID**.
   - Drop any existing signature blob.

5. **Adopt the App Store Team ID** — `detail::adopt_app_store_team_id` rewrites
   the real (slot `0x1000`) CodeDirectory so its Team ID matches the App Store
   one and clears its flags (notably the `adhoc` flag). Both CodeDirectories
   must agree on the Team ID for CoreTrust to accept them.

6. **Sign in two passes** — `detail::sign_superblob`. Signing changes the size of
   the SuperBlob, which changes the load commands, which changes page 0 — and
   page 0's hash is one of the code slots, so the cdhash would shift under us.
   To keep everything consistent:
   1. Build the signature once just to learn the final size.
   2. `resize_code_signature` to reserve exactly that many bytes (this edits the
      load commands).
   3. Re-hash the code slots over the now-final first page
      (`update_code_slots`) and write the updated CodeDirectory back.
   4. Build the signature again for real; assert the encoded SuperBlob is exactly
      the reserved size (`kErrSuperBlobSizeMismatch`).

7. **Write it back** — `write_code_signature` splices the new SuperBlob into the
   reserved region and `save` flushes the file to disk.

## The signature itself (`update_signature_blob`)

1. `compute_cdhashes` — SHA-1 of the slot-0 (App Store) CodeDirectory and
   SHA-256 of the slot-`0x1000` (real) one.
2. Load Apple's **template CMS** from `app_store_signature_blob()`; its original
   signer must stay byte-identical.
3. `CMS_add1_signer(..., CMS_PARTIAL | CMS_REUSE_DIGEST | CMS_NOSMIMECAP)` adds
   the TrollStore CA signer, reusing Apple's `messageDigest` (the content is
   detached).
4. Attach the two cdhash signed attributes the loader expects:
   - OID `1.2.840.113635.100.9.1` — an XML plist `{"cdhashes": [sha1, sha256]}`
     (the SHA-256 value truncated to 20 bytes).
   - OID `1.2.840.113635.100.9.2` — a DER structure with the full SHA-1 and
     SHA-256 cdhashes.
5. `CMS_SignerInfo_sign`, encode to DER, and wrap it in a `kBlobWrapper` blob in
   slot `0x10000`.

## Why the blob order matters

`SuperBlob::serialize()` emits the index in **ascending slot order**
(`0`, `5`/`7`, `0x1000`, `0x10000`). CoreTrust selects a CodeDirectory by slot
number rather than by position, but emitting the slots sorted reproduces exactly
what `codesign` writes and matches the reference implementation.

## Error codes

Each stage returns a specific `ReturnCode` (see `include/exploit/return_code.h`)
instead of a generic failure, so a caller can tell *which* step failed — e.g.
`kErrCodeDirNotSha256`, `kErrSetTeamId`, `kErrUpdateCodeSlots`,
`kErrSuperBlobSizeMismatch`. `succeeded()` / `failed()` test the result.
