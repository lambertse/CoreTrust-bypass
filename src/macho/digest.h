#ifndef CT_BYPASS_MACHO_DIGEST_H
#define CT_BYPASS_MACHO_DIGEST_H

#include <cstddef>
#include <cstdint>
#include <optional>

#include "utils.h"

namespace ct_bypass::macho {

// Hash algorithm of a CodeDirectory (CS_HASHTYPE_* in xnu's cs_blobs.h)
enum class HashType : uint8_t {
  kSha1 = 1,
  kSha256 = 2,
  kSha256Truncated = 3,  // SHA-256 cut to its first 20 bytes
  kSha384 = 4,
};

// Digest length in bytes, or 0 for an unknown hash type
constexpr size_t digest_size(HashType type) {
  switch (type) {
    case HashType::kSha1:
      return 20;
    case HashType::kSha256:
      return 32;
    case HashType::kSha256Truncated:
      return 20;
    case HashType::kSha384:
      return 48;
  }
  return 0;
}

// Digest of [data, data + size); nullopt for an unknown hash type or if
// libcrypto fails
std::optional<Bytes> compute_digest(HashType type, const uint8_t* data,
                                    size_t size);

}  // namespace ct_bypass::macho

#endif  // CT_BYPASS_MACHO_DIGEST_H
