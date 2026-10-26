#include "digest.h"

#include <openssl/evp.h>

namespace ct_bypass::macho {

std::optional<Bytes> compute_digest(HashType type, const uint8_t* data,
                                    size_t size) {
  const EVP_MD* md = nullptr;
  switch (type) {
    case HashType::kSha1:
      md = EVP_sha1();
      break;
    case HashType::kSha256:
    case HashType::kSha256Truncated:
      md = EVP_sha256();
      break;
    case HashType::kSha384:
      md = EVP_sha384();
      break;
  }
  if (md == nullptr) {
    return std::nullopt;
  }

  Bytes digest(EVP_MAX_MD_SIZE);
  unsigned int length = 0;
  if (!EVP_Digest(data, size, digest.data(), &length, md, nullptr)) {
    return std::nullopt;
  }
  digest.resize(digest_size(type));
  return digest;
}

}  // namespace ct_bypass::macho
