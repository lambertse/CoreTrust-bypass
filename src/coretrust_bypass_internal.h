#ifndef CT_BYPASS_CORETRUST_BYPASS_INTERNAL_H
#define CT_BYPASS_CORETRUST_BYPASS_INTERNAL_H

// Internal interface of the CoreTrust bypass, exposed only so the unit tests
// can drive each stage in isolation. It is not shipped in include/ and is not
// part of the public API; use exploit/coretrust_bypass.h for that.

#include <cstddef>
#include <string>

#include "exploit/return_code.h"
#include "macho/cs_blob.h"
#include "macho/macho.h"
#include "macho/utils.h"

namespace ct_bypass::detail {

using macho::Bytes;
using macho::MachO;
using macho::SuperBlob;

// Replaces a universal `macho` with the thin slice to re-sign: the one the
// host would run or, on macOS, the best arm64 slice. A thin 64-bit Mach-O is
// kept as is. kErrMachoNoUsableSlice if there is no such slice.
ReturnCode select_slice(MachO::Ptr& macho);

// Rejects inputs the bypass cannot handle: kErrMachoNoUsableSlice unless it is
// a thin 64-bit Mach-O, kErrMachoEncrypted for an encrypted binary,
// kErrMachoFiletype for an object or dSYM file.
ReturnCode check_supported_macho(const MachO& macho);

// Decodes the embedded code signature into `superblob` and reports its file
// offset in `code_signature_offset`.
ReturnCode load_code_signature(const MachO& macho, SuperBlob& superblob,
                               size_t& code_signature_offset);

// SHA-1 of the App Store CodeDirectory (slot 0) and SHA-256 of the real one
// (slot 0x1000); these are the cdhashes the new signer vouches for.
ReturnCode compute_cdhashes(const SuperBlob& superblob, Bytes& sha1_cdhash,
                            Bytes& sha256_cdhash);

// Moves the real (SHA-256) CodeDirectory to the alternate slot, puts the App
// Store CodeDirectory in slot 0 and drops the old signature. Reports the App
// Store Team ID in `app_store_team_id`.
ReturnCode swap_in_app_store_cd(SuperBlob& superblob,
                                std::string& app_store_team_id);

// Gives the real CodeDirectory the App Store Team ID (both must match) and
// clears its flags, writing the result back into `superblob`.
ReturnCode adopt_app_store_team_id(SuperBlob& superblob,
                                   const std::string& app_store_team_id);

// Two-pass signing: size the SuperBlob, resize the load commands, rehash the
// pages that moved and sign. Reports the final encoded SuperBlob, the same
// size as the first-pass one the range was sized for, in `signed_superblob`.
ReturnCode sign_superblob(MachO& macho, SuperBlob& superblob,
                          size_t code_signature_offset,
                          Bytes& signed_superblob);

}  // namespace ct_bypass::detail

#endif  // CT_BYPASS_CORETRUST_BYPASS_INTERNAL_H
