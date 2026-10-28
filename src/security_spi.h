#ifndef CT_BYPASS_SECURITY_SPI_H
#define CT_BYPASS_SECURITY_SPI_H

// Security.framework interfaces missing from the SDK headers: the private
// SecCodeSigner SPI (from Apple's Security sources, SecCodeSigner.h) and, on
// iOS, whose SDK ships no code-signing headers, the public static-code API.

#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecBase.h>
#include <TargetConditionals.h>

#ifndef SPI_AVAILABLE
#define SPI_AVAILABLE(...)
#endif

// clang-format off
#if TARGET_OS_OSX
#include <Security/SecCode.h>
#include <Security/SecStaticCode.h>
#else
extern "C" {
// CSCommon.h
typedef struct CF_BRIDGED_TYPE(id) __SecCode const* SecStaticCodeRef;
typedef CF_OPTIONS(uint32_t, SecCSFlags) {
  kSecCSDefaultFlags = 0,
};

// SecCode.h
CF_ENUM(uint32_t) {
  kSecCSInternalInformation = 1 << 0,
  kSecCSSigningInformation = 1 << 1,
  kSecCSRequirementInformation = 1 << 2,
};
OSStatus SecCodeCopySigningInformation(SecStaticCodeRef code, SecCSFlags flags, CFDictionaryRef* CF_RETURNS_RETAINED information);

// SecStaticCode.h
OSStatus SecStaticCodeCreateWithPathAndAttributes(CFURLRef path, SecCSFlags flags, CFDictionaryRef attributes, SecStaticCodeRef* CF_RETURNS_RETAINED staticCode);
}  // extern "C"
#endif  // TARGET_OS_OSX

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
