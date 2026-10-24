#ifndef CT_BYPASS_SECURITY_SPI_H
#define CT_BYPASS_SECURITY_SPI_H

// Private Security.framework interfaces (from Apple's Security sources,
// SecCodeSigner.h). These are not in the public SDK headers.

#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecCode.h>
#include <Security/SecStaticCode.h>

// clang-format off
extern "C" {
typedef struct __SecCodeSigner* SecCodeSignerRef SPI_AVAILABLE(macos(10.5), ios(15.0), macCatalyst(13.0));
typedef OSStatus (*SecCodeSignerCreateFn)(CFDictionaryRef parameters, SecCSFlags flags, SecCodeSignerRef* signerRef);
typedef OSStatus (*SecCodeSignerAddSignatureWithErrorsFn)(SecCodeSignerRef signerRef, SecStaticCodeRef codeRef, SecCSFlags flags, CFErrorRef* errors);
}  // extern "C"
// clang-format on

namespace ct_bypass::spi {

// SecCodeSignerCreate parameter keys.
inline const CFStringRef kSecCodeSignerEntitlements = CFSTR("entitlements");
inline const CFStringRef kSecCodeSignerIdentity = CFSTR("signer");
inline const CFStringRef kSecCodeSignerPreserveMetadata =
    CFSTR("preserve-metadata");

// Values for kSecCodeSignerPreserveMetadata.
typedef CF_OPTIONS(uint32_t, SecPreserveFlags) {
  kSecCSPreserveIdentifier = 1 << 0,
  kSecCSPreserveRequirements = 1 << 1,
  kSecCSPreserveEntitlements = 1 << 2,
  kSecCSPreserveResourceRules = 1 << 3,
  kSecCSPreserveFlags = 1 << 4,
  kSecCSPreserveTeamIdentifier = 1 << 5,
  kSecCSPreserveDigestAlgorithm = 1 << 6,
  kSecCSPreservePreEncryptHashes = 1 << 7,
  kSecCSPreserveRuntime = 1 << 8,
};

// Magic of an embedded entitlements blob (CSMAGIC_EMBEDDED_ENTITLEMENTS).
inline constexpr uint32_t kEntitlementsBlobMagic = 0xFADE7171;

}  // namespace ct_bypass::spi

#endif  // CT_BYPASS_SECURITY_SPI_H
