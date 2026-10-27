#ifndef CT_BYPASS_CS_BLOB_H
#define CT_BYPASS_CS_BLOB_H

// Reading and editing the embedded code signature of a Mach-O.
//
// LC_CODE_SIGNATURE points at a SuperBlob: a small index followed by the blobs
// it lists. Each index entry says what a blob is for (its slot) and where it
// starts. Every blob begins with its own magic and length.
//
//   SuperBlob
//   +--------------------------+
//   | magic  0xfade0cc0        |
//   | length (whole SuperBlob) |
//   | count                    |
//   | {slot, offset} x count   |
//   +--------------------------+
//   | blob | blob | ...        |
//   +--------------------------+
//
// The CodeDirectory is the blob the kernel actually verifies. It holds a hash
// of every page of the binary (code slots), hashes of the other blobs such as
// the entitlements (special slots), and the identity strings. Its cdhash, the
// hash of the CodeDirectory itself, is what the CMS signature signs.
//
//   CodeDirectory
//   +---------------------------------+  0
//   | fixed header                    |  grows with `version`, see
//   |   magic, length, version, flags |  CodeDirectory::Version
//   |   hashOffset, identOffset, ...  |
//   +---------------------------------+  header size
//   | identifier "com.example.app\0"  |  <- identOffset
//   | team ID    "ABCDE12345\0"       |  <- teamOffset (0 if none)
//   +---------------------------------+
//   | special slots, stored backwards |  slot -1 (Info.plist) sits right
//   |   ..., slot -2, slot -1         |  before hashOffset
//   +---------------------------------+  <- hashOffset
//   | code slots: page 0, page 1, ... |  hash of each page of the binary
//   +---------------------------------+
//
// All integers are big-endian. cs_blob.cpp draws the CodeDirectory header
// byte by byte. Constants come from xnu's osfmk/kern/cs_blobs.h, which has no
// userland header.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "digest.h"
#include "exploit/return_code.h"
#include "utils.h"

namespace ct_bypass::macho {

// Every blob, the SuperBlob included, starts with magic + length
inline constexpr size_t kBlobHeaderSize = 8;
inline constexpr size_t kSha1Len = 20;
inline constexpr size_t kSha256Len = 32;
inline constexpr size_t kCDHashLen = 20;
inline constexpr size_t kMaxHashLen = 48;

enum class BlobMagic : uint32_t {
  kCodeDirectory = 0xfade0c02,
  kEmbeddedSignature = 0xfade0cc0,  // the SuperBlob
  kBlobWrapper = 0xfade0b01,        // CMS signature
};

// What a blob in the SuperBlob is for (CSSLOT_* in xnu)
enum class SlotType : uint32_t {
  kCodeDirectory = 0,
  kEntitlements = 5,
  kDerEntitlements = 7,
  kAlternateCodeDirectories = 0x1000,  // e.g. a SHA-256 CD next to a SHA-1 one
  kSignature = 0x10000,                // CMS signature over the cdhash
};

struct Blob {
  SlotType slot;
  Bytes data;  // the whole blob, its magic and length included
};

class CodeDirectory {
 public:
  // CodeDirectory layout revisions. Each one appends fields to the header.
  enum class Version : uint32_t {
    kBase = 0x20001,
    kScatter = 0x20100,      // + scatterOffset
    kTeamId = 0x20200,       // + teamOffset
    kCodeLimit64 = 0x20300,  // + 64-bit codeLimit
    kExecSegment = 0x20400,  // + execSeg base/limit/flags
    kRuntime = 0x20500,      // + runtime, preEncryptOffset
    kLinkage = 0x20600,      // + linkage hash and offset
  };

  static std::optional<CodeDirectory> deserialize(Bytes data);

  const Bytes& data() const { return data_; }
  uint32_t version() const;
  bool has(Version version) const;
  uint32_t flags() const;
  HashType hash_type() const;
  std::string identifier() const;
  std::string team_id() const;

  void set_flags(uint32_t flags);
  ReturnCode set_team_id(std::string_view team_id);
  ReturnCode update_code_slots(const uint8_t* code, size_t code_size);

 private:
  explicit CodeDirectory(Bytes data) : data_(std::move(data)) {}

  bool is_valid() const;

  uint32_t field(size_t offset) const;
  void set_field(size_t offset, uint32_t value);

  uint32_t hash_offset() const;
  uint32_t ident_offset() const;
  uint32_t team_offset() const;
  uint8_t hash_size() const;
  uint64_t code_limit() const;
  // Where the special slots start; the hash table is [hashes_begin, hashes_end)
  uint64_t hashes_begin() const;
  uint64_t hashes_end() const;

  Bytes data_;
};

class SuperBlob {
 public:
  static std::optional<SuperBlob> deserialize(const Bytes& data);
  Bytes serialize() const;

  std::optional<Blob> find_blob(SlotType slot) const; 
  ReturnCode remove_blob(SlotType slot);
  ReturnCode add_blob(const Blob& blob);

 private:
  SuperBlob() = default;

  std::vector<Blob> blobs_;
};

}  // namespace ct_bypass::macho

#endif  // CT_BYPASS_CS_BLOB_H
