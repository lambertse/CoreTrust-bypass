#include "template/template.h"

#include <gtest/gtest.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <algorithm>
#include <memory>
#include <ostream>
#include <string>

#include "macho/cs_blob.h"

namespace ct_bypass {

// Prints ReturnCode as its value instead of raw bytes in assertion failures.
void PrintTo(ReturnCode code, std::ostream* os) {
  *os << static_cast<int>(code);
}

namespace templates {
namespace {

using macho::Bytes;
using macho::CodeDirectory;
using macho::read_be32;

// Facts about app_store_code_directory(), decoded from its header
constexpr uint32_t kAppStoreCdSize = 32469;
constexpr uint32_t kAppStoreCdVersion = 0x20500;
constexpr uint32_t kAppStoreTeamOffset = 118;
constexpr uint32_t kAppStorePreEncryptOffset = 129;
constexpr uint32_t kAppStoreHashesBegin = 16229;  // first special slot

// CodeDirectory header offsets read directly by these tests
constexpr size_t kCdHashOffset = 16;
constexpr size_t kCdTeamOffset = 48;
constexpr size_t kCdPreEncryptOffset = 92;

Bytes to_bytes(ByteView view) {
  return Bytes(view.data, view.data + view.size);
}

struct BioDeleter {
  void operator()(BIO* bio) const { BIO_free(bio); }
};
struct X509Deleter {
  void operator()(X509* cert) const { X509_free(cert); }
};
struct PKeyDeleter {
  void operator()(EVP_PKEY* key) const { EVP_PKEY_free(key); }
};

std::unique_ptr<BIO, BioDeleter> memory_bio(ByteView view) {
  return std::unique_ptr<BIO, BioDeleter>(
      BIO_new_mem_buf(view.data, static_cast<int>(view.size)));
}

TEST(AppStoreCodeDirectory, DeserializesWithExpectedIdentity) {
  ByteView view = app_store_code_directory();
  ASSERT_EQ(view.size, kAppStoreCdSize);

  auto cd = CodeDirectory::deserialize(to_bytes(view));
  ASSERT_TRUE(cd);
  EXPECT_EQ(cd->version(), kAppStoreCdVersion);
  EXPECT_EQ(cd->hash_type(), macho::HashType::kSha1);
  EXPECT_EQ(cd->identifier(), "com.icraze.gtatracker");
  EXPECT_EQ(cd->team_id(), "T8ALTGMVXN");
}

TEST(AppStoreCodeDirectory, SetTeamIdShiftsPreEncryptHashes) {
  // The pre-encrypt hashes start right after the Team ID, so a longer Team ID
  // must move them and update preEncryptOffset
  Bytes original = to_bytes(app_store_code_directory());
  ASSERT_EQ(read_be32(original.data() + kCdPreEncryptOffset),
            kAppStorePreEncryptOffset);
  auto cd = CodeDirectory::deserialize(original);
  ASSERT_TRUE(cd);

  const std::string team_id = "ABCDEFGHIJKL";
  const uint32_t shift = 2;  // 12 characters replace 10
  ASSERT_EQ(cd->set_team_id(team_id), ReturnCode::kOk);

  const Bytes& edited = cd->data();
  EXPECT_EQ(cd->team_id(), team_id);
  EXPECT_EQ(cd->identifier(), "com.icraze.gtatracker");
  EXPECT_EQ(edited.size(), original.size() + shift);
  EXPECT_EQ(read_be32(edited.data() + kCdTeamOffset), kAppStoreTeamOffset);
  EXPECT_EQ(read_be32(edited.data() + kCdPreEncryptOffset),
            kAppStorePreEncryptOffset + shift);
  EXPECT_EQ(read_be32(edited.data() + kCdHashOffset),
            read_be32(original.data() + kCdHashOffset) + shift);

  // Pre-encrypt hashes, special slots and code slots, all moved intact
  EXPECT_TRUE(std::equal(original.begin() + kAppStorePreEncryptOffset,
                         original.end(),
                         edited.begin() + kAppStorePreEncryptOffset + shift,
                         edited.end()));
  EXPECT_TRUE(CodeDirectory::deserialize(edited));
}

TEST(AppStoreCodeDirectory, SetTeamIdRoundTripsToOriginalBytes) {
  Bytes original = to_bytes(app_store_code_directory());
  auto cd = CodeDirectory::deserialize(original);
  ASSERT_TRUE(cd);

  ASSERT_EQ(cd->set_team_id("A"), ReturnCode::kOk);
  ASSERT_EQ(cd->set_team_id("T8ALTGMVXN"), ReturnCode::kOk);
  EXPECT_EQ(cd->data(), original);
}

TEST(AppStoreSignatureBlob, IsBlobWrapperWithMatchingLength) {
  ByteView view = app_store_signature_blob();
  ASSERT_GE(view.size, macho::kBlobHeaderSize);
  EXPECT_EQ(read_be32(view.data),
            static_cast<uint32_t>(macho::BlobMagic::kBlobWrapper));
  EXPECT_EQ(read_be32(view.data + 4), view.size);
}

TEST(CaCertificate, ParsesAsPemCertificate) {
  auto bio = memory_bio(ca_certificate());
  ASSERT_TRUE(bio);
  std::unique_ptr<X509, X509Deleter> cert(
      PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
  EXPECT_TRUE(cert);
}

TEST(CaPrivateKey, ParsesAndMatchesCertificate) {
  auto cert_bio = memory_bio(ca_certificate());
  auto key_bio = memory_bio(ca_private_key());
  ASSERT_TRUE(cert_bio);
  ASSERT_TRUE(key_bio);
  std::unique_ptr<X509, X509Deleter> cert(
      PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr));
  std::unique_ptr<EVP_PKEY, PKeyDeleter> key(
      PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr));
  ASSERT_TRUE(cert);
  ASSERT_TRUE(key);
  EXPECT_EQ(X509_check_private_key(cert.get(), key.get()), 1);
}

TEST(CdHashesDer, HasSha1AndSha256AlgorithmIdentifiers) {
  ByteView view = cd_hashes_der();
  ASSERT_EQ(view.size, kCdHashesDerSize);
  Bytes der = to_bytes(view);

  // OBJECT IDENTIFIER 1.3.14.3.2.26 (sha1)
  const Bytes sha1_oid = {0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a};
  EXPECT_EQ(Bytes(der.begin() + 2, der.begin() + 9), sha1_oid);
  // OBJECT IDENTIFIER 2.16.840.1.101.3.4.2.1 (sha256)
  const Bytes sha256_oid = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                            0x65, 0x03, 0x04, 0x02, 0x01};
  EXPECT_EQ(Bytes(der.begin() + 33, der.begin() + 44), sha256_oid);
}

TEST(CdHashesDer, PlaceholdersAreZeroed) {
  ByteView view = cd_hashes_der();
  for (size_t i = 0; i < kCdHashesDerSha1Size; i++) {
    EXPECT_EQ(view.data[kCdHashesDerSha1Offset + i], 0) << "byte " << i;
  }
  for (size_t i = 0; i < kCdHashesDerSha256Size; i++) {
    EXPECT_EQ(view.data[kCdHashesDerSha256Offset + i], 0) << "byte " << i;
  }
}

}  // namespace
}  // namespace templates
}  // namespace ct_bypass
