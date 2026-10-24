#ifndef CT_BYPASS_TEMPLATE_H
#define CT_BYPASS_TEMPLATE_H

#include <cstddef>
#include <cstdint>

namespace ct_bypass::templates {

// Non-owning view of a static byte blob.
struct ByteView {
  const uint8_t* data;
  size_t size;
};

// Layout of cd_hashes_der(): a DER sequence holding the SHA-1 and SHA-256
// CDHashes, with zeroed placeholders at the offsets below.
inline constexpr size_t kCdHashesDerSize = 78;
inline constexpr size_t kCdHashesDerSha1Offset = 11;
inline constexpr size_t kCdHashesDerSha1Size = 20;
inline constexpr size_t kCdHashesDerSha256Offset = 46;
inline constexpr size_t kCdHashesDerSha256Size = 32;

// Code directory and CMS signature blob taken from an App Store binary.
ByteView app_store_code_directory();
ByteView app_store_signature_blob();

// PEM-encoded CA certificate and private key.
ByteView ca_certificate();
ByteView ca_private_key();

// DER template for the CDHashes attribute; see kCdHashesDer* for its layout.
ByteView cd_hashes_der();

}  // namespace ct_bypass::templates

#endif  // CT_BYPASS_TEMPLATE_H
