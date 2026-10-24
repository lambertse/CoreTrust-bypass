#include "template.h"

#include "detail/app_store_details.h"
#include "detail/ca_details.h"
#include "detail/der_template.h"

namespace ct_bypass::templates {
namespace {

// The *_len constants are generated alongside the arrays; make sure they agree.
static_assert(sizeof(detail::app_store_cd) == detail::app_store_cd_len);
static_assert(sizeof(detail::app_store_signature_blob) ==
              detail::app_store_signature_blob_len);
static_assert(sizeof(detail::CA_cert) == detail::CA_cert_len);
static_assert(sizeof(detail::CA_key) == detail::CA_key_len);

static_assert(sizeof(detail::cd_hashes_DER_template) == kCdHashesDerSize);
static_assert(kCdHashesDerSha1Offset + kCdHashesDerSha1Size <=
              kCdHashesDerSha256Offset);
static_assert(kCdHashesDerSha256Offset + kCdHashesDerSha256Size ==
              kCdHashesDerSize);
// Each placeholder is preceded by its OCTET STRING tag and length.
static_assert(detail::cd_hashes_DER_template[kCdHashesDerSha1Offset - 2] ==
                  0x04 &&
              detail::cd_hashes_DER_template[kCdHashesDerSha1Offset - 1] ==
                  kCdHashesDerSha1Size);
static_assert(detail::cd_hashes_DER_template[kCdHashesDerSha256Offset - 2] ==
                  0x04 &&
              detail::cd_hashes_DER_template[kCdHashesDerSha256Offset - 1] ==
                  kCdHashesDerSha256Size);

template <size_t N>
constexpr ByteView view(const uint8_t (&bytes)[N]) {
  return ByteView{bytes, N};
}

}  // namespace

ByteView app_store_code_directory() { return view(detail::app_store_cd); }
ByteView app_store_signature_blob() {
  return view(detail::app_store_signature_blob);
}

ByteView ca_certificate() { return view(detail::CA_cert); }
ByteView ca_private_key() { return view(detail::CA_key); }

ByteView cd_hashes_der() { return view(detail::cd_hashes_DER_template); }

}  // namespace ct_bypass::templates
