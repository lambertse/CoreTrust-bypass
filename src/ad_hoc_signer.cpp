#include "exploit/ad_hoc_signer.h"

#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "cf_ptr.h"
#include "security_spi.h"
#include "utils.h"

namespace ct_bypass {
namespace {

struct SignerFunctions {
  SecCodeSignerCreateFn create = nullptr;
  SecCodeSignerAddSignatureWithErrorsFn add_signature_with_errors = nullptr;

  bool available() const { return create && add_signature_with_errors; }
};

// Resolved at runtime because the symbols are SPI, and iOS 14 doesn't have
// them at all.
const SignerFunctions& signer_functions() {
  static const SignerFunctions fns = [] {
    SignerFunctions f;
    f.create = reinterpret_cast<SecCodeSignerCreateFn>(
        dlsym(RTLD_DEFAULT, "SecCodeSignerCreate"));
    f.add_signature_with_errors =
        reinterpret_cast<SecCodeSignerAddSignatureWithErrorsFn>(
            dlsym(RTLD_DEFAULT, "SecCodeSignerAddSignatureWithErrors"));
    return f;
  }();
  return fns;
}

CFPtr<CFNumberRef> create_preserve_metadata_flags(bool preserve_entitlements) {
  int64_t flags = spi::kSecCSPreserveIdentifier |
                  spi::kSecCSPreserveRequirements |
                  spi::kSecCSPreserveResourceRules;
  if (preserve_entitlements) flags |= spi::kSecCSPreserveEntitlements;
  return CFPtr<CFNumberRef>(
      CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &flags));
}

// Wraps the entitlements plist in an embedded entitlements blob
// (magic + big-endian total length + XML). Returns null on failure.
CFPtr<CFDataRef> create_entitlements_blob(CFDictionaryRef entitlements) {
  CFErrorRef error_raw = nullptr;
  CFPtr<CFDataRef> xml_data(
      CFPropertyListCreateData(kCFAllocatorDefault, entitlements,
                               kCFPropertyListXMLFormat_v1_0, 0, &error_raw));
  CFPtr<CFErrorRef> error(error_raw);
  if (!xml_data) {
    fprintf(stderr, "Failed to encode entitlements: %s\n",
            utils::cf_description(error.get()).c_str());
    return nullptr;
  }

  // SecCodeSigner expects the full blob, not the raw XML; it crashes without
  // this header.
  constexpr size_t kHeaderSize = 2 * sizeof(uint32_t);
  const CFIndex xml_length = CFDataGetLength(xml_data.get());
  const uint32_t header[2] = {
      CFSwapInt32HostToBig(spi::kEntitlementsBlobMagic),
      CFSwapInt32HostToBig(static_cast<uint32_t>(kHeaderSize + xml_length)),
  };
  std::vector<UInt8> blob(kHeaderSize + xml_length);
  memcpy(blob.data(), header, kHeaderSize);
  CFDataGetBytes(xml_data.get(), CFRangeMake(0, xml_length),
                 blob.data() + kHeaderSize);
  return CFPtr<CFDataRef>(CFDataCreate(kCFAllocatorDefault, blob.data(),
                                       static_cast<CFIndex>(blob.size())));
}

// Builds the SecCodeSignerCreate parameters. Returns null on failure.
CFPtr<CFMutableDictionaryRef> create_signer_parameters(
    bool preserve_metadata, CFDictionaryRef custom_entitlements) {
  CFPtr<CFMutableDictionaryRef> parameters(CFDictionaryCreateMutable(
      kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
      &kCFTypeDictionaryValueCallBacks));
  if (!parameters) return nullptr;

  // A null identity requests ad-hoc signing (equivalent to `codesign -s -`).
  CFDictionarySetValue(parameters.get(), spi::kSecCodeSignerIdentity, kCFNull);

  if (preserve_metadata) {
    CFPtr<CFNumberRef> flags =
        create_preserve_metadata_flags(!custom_entitlements);
    CFDictionarySetValue(parameters.get(), spi::kSecCodeSignerPreserveMetadata,
                         flags.get());
  }

  if (custom_entitlements) {
    CFPtr<CFDataRef> blob = create_entitlements_blob(custom_entitlements);
    if (!blob) return nullptr;
    CFDictionarySetValue(parameters.get(), spi::kSecCodeSignerEntitlements,
                         blob.get());
  }

  return parameters;
}

CFPtr<SecStaticCodeRef> create_static_code(const std::string& path) {
  CFPtr<CFURLRef> file_url = utils::create_file_url(path.c_str());
  if (!file_url) return nullptr;

  CFPtr<CFDictionaryRef> attributes(CFDictionaryCreate(
      kCFAllocatorDefault, nullptr, nullptr, 0, &kCFTypeDictionaryKeyCallBacks,
      &kCFTypeDictionaryValueCallBacks));
  SecStaticCodeRef code = nullptr;
  if (SecStaticCodeCreateWithPathAndAttributes(
          file_url.get(), kSecCSDefaultFlags, attributes.get(), &code) !=
      errSecSuccess) {
    return nullptr;
  }
  return CFPtr<SecStaticCodeRef>(code);
}

OSStatus add_signature(SecCodeSignerRef signer, SecStaticCodeRef code) {
  CFErrorRef errors_raw = nullptr;
  OSStatus status = signer_functions().add_signature_with_errors(
      signer, code, kSecCSDefaultFlags, &errors_raw);
  CFPtr<CFErrorRef> errors(errors_raw);
  if (status != errSecSuccess) {
    fprintf(stderr, "Error while signing: %s\n",
            utils::cf_description(errors.get()).c_str());
  }
  return status;
}

// Re-reads the signing information to confirm the new signature parses.
OSStatus check_signing_information(SecStaticCodeRef code) {
  // Difference from codesign: added kSecCSSigningInformation,
  // kSecCSRequirementInformation, kSecCSInternalInformation
  const SecCSFlags flags = kSecCSDefaultFlags | kSecCSSigningInformation |
                           kSecCSRequirementInformation |
                           kSecCSInternalInformation;
  CFDictionaryRef info_raw = nullptr;
  OSStatus status = SecCodeCopySigningInformation(code, flags, &info_raw);
  CFPtr<CFDictionaryRef> info(info_raw);
  return status;
}

}  // namespace

class AdHocSignerImpl {
 public:
  AdHocSignerImpl(const std::string& path, bool preserve_metadata,
                  CFDictionaryRef custom_entitlements)
      : path_(path),
        preserve_metadata_(preserve_metadata),
        custom_entitlements_(cf_retain(custom_entitlements)) {}

  ReturnCode sign() const;

 private:
  const std::string path_;
  const bool preserve_metadata_;
  const CFPtr<CFDictionaryRef> custom_entitlements_;
};

ReturnCode AdHocSignerImpl::sign() const {
  const SignerFunctions& fns = signer_functions();
  if (!fns.available()) return ReturnCode::kErrSignerUnavailable;

  CFPtr<CFMutableDictionaryRef> parameters =
      create_signer_parameters(preserve_metadata_, custom_entitlements_.get());
  if (!parameters) return ReturnCode::kErrCreateSignerParameters;

  SecCodeSignerRef signer_raw = nullptr;
  if (fns.create(parameters.get(), kSecCSDefaultFlags, &signer_raw) !=
      errSecSuccess) {
    return ReturnCode::kErrSignerCreate;
  }
  CFPtr<SecCodeSignerRef> signer(signer_raw);

  CFPtr<SecStaticCodeRef> code = create_static_code(path_);
  if (!code) return ReturnCode::kErrCreateStaticCode;

  if (add_signature(signer.get(), code.get()) != errSecSuccess) {
    return ReturnCode::kErrAddSignature;
  }
  if (check_signing_information(code.get()) != errSecSuccess) {
    return ReturnCode::kErrCheckSigningInformation;
  }
  return ReturnCode::kOk;
}

AdHocSigner::AdHocSigner(const std::string& path, bool preserve_metadata,
                         CFDictionaryRef custom_entitlements)
    : impl_(std::make_unique<AdHocSignerImpl>(path, preserve_metadata,
                                              custom_entitlements)) {}

AdHocSigner::~AdHocSigner() = default;

AdHocSigner::Ptr AdHocSigner::create(const std::string& path,
                                     bool preserve_metadata,
                                     CFDictionaryRef custom_entitlements) {
  return Ptr(new AdHocSigner(path, preserve_metadata, custom_entitlements));
}

ReturnCode AdHocSigner::sign() { return impl_->sign(); }

}  // namespace ct_bypass
