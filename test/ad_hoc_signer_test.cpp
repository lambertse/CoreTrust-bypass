#include "exploit/ad_hoc_signer.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <gtest/gtest.h>
#include <stdlib.h>

#include <filesystem>
#include <ostream>
#include <string>
#include <system_error>
#include <vector>

#include "cf_ptr.h"

namespace ct_bypass {

// Prints ReturnCode as its value instead of raw bytes in assertion failures.
void PrintTo(ReturnCode code, std::ostream* os) {
  *os << static_cast<int>(code);
}

namespace {

constexpr char kGetTaskAllow[] = "com.apple.security.get-task-allow";
// Set by the build when it ad-hoc signs ad_hoc_signer_fixture
constexpr char kFixtureIdentifier[] = "com.ct-bypass.ad-hoc-signer-fixture";

CFPtr<SecStaticCodeRef> create_static_code(const std::string& path) {
  CFPtr<CFURLRef> url(CFURLCreateFromFileSystemRepresentation(
      kCFAllocatorDefault, reinterpret_cast<const UInt8*>(path.c_str()),
      static_cast<CFIndex>(path.size()), false));
  SecStaticCodeRef code = nullptr;
  if (!url || SecStaticCodeCreateWithPath(url.get(), kSecCSDefaultFlags,
                                          &code) != errSecSuccess) {
    return nullptr;
  }
  return CFPtr<SecStaticCodeRef>(code);
}

CFPtr<CFDictionaryRef> signing_information(const std::string& path) {
  CFPtr<SecStaticCodeRef> code = create_static_code(path);
  CFDictionaryRef info = nullptr;
  if (!code ||
      SecCodeCopySigningInformation(
          code.get(), kSecCSSigningInformation | kSecCSRequirementInformation,
          &info) != errSecSuccess) {
    return nullptr;
  }
  return CFPtr<CFDictionaryRef>(info);
}

std::string to_string(CFStringRef string) {
  if (!string) return {};
  CFIndex size = CFStringGetMaximumSizeForEncoding(CFStringGetLength(string),
                                                   kCFStringEncodingUTF8) +
                 1;
  std::vector<char> buffer(size);
  if (!CFStringGetCString(string, buffer.data(), size,
                          kCFStringEncodingUTF8)) {
    return {};
  }
  return buffer.data();
}

std::string identifier_of(const std::string& path) {
  CFPtr<CFDictionaryRef> info = signing_information(path);
  if (!info) return {};
  return to_string(static_cast<CFStringRef>(
      CFDictionaryGetValue(info.get(), kSecCodeInfoIdentifier)));
}

class AdHocSignerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    std::string dir = (std::filesystem::temp_directory_path() /
                       "ad_hoc_signer_test.XXXXXX")
                          .string();
    ASSERT_NE(mkdtemp(dir.data()), nullptr);
    dir_ = dir;

    // sign() rewrites the file in place, so always work on a copy. Not
    // test/macho_sample: its slot 0 holds a transplanted App Store
    // CodeDirectory that doesn't match the file, which SecCodeSigner rejects.
    binary_ = (dir_ / "binary").string();
    std::filesystem::copy_file(AD_HOC_SIGNER_FIXTURE_PATH, binary_);
    std::filesystem::permissions(binary_, std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::add);
  }

  void TearDown() override {
    if (!dir_.empty()) {
      std::error_code ec;
      std::filesystem::remove_all(dir_, ec);
    }
  }

  // Signs `path`, skipping the test where the signing SPI doesn't exist
  ReturnCode sign(const std::string& path, bool preserve_metadata,
                  CFDictionaryRef entitlements = nullptr) {
    ReturnCode ret =
        AdHocSigner::create(path, preserve_metadata, entitlements)->sign();
    if (ret == ReturnCode::kErrSignerUnavailable) {
      skipped_ = true;
    }
    return ret;
  }

  std::filesystem::path dir_;
  std::string binary_;
  bool skipped_ = false;
};

TEST_F(AdHocSignerTest, ProducesValidAdHocSignature) {
  ReturnCode ret = sign(binary_, false);
  if (skipped_) GTEST_SKIP() << "SecCodeSigner SPI unavailable";
  ASSERT_EQ(ret, ReturnCode::kOk);

  CFPtr<SecStaticCodeRef> code = create_static_code(binary_);
  ASSERT_TRUE(code);
  EXPECT_EQ(SecStaticCodeCheckValidity(code.get(), kSecCSDefaultFlags, nullptr),
            errSecSuccess);

  CFPtr<CFDictionaryRef> info = signing_information(binary_);
  ASSERT_TRUE(info);
  auto flags_number = static_cast<CFNumberRef>(
      CFDictionaryGetValue(info.get(), kSecCodeInfoFlags));
  ASSERT_NE(flags_number, nullptr);
  uint32_t flags = 0;
  ASSERT_TRUE(CFNumberGetValue(flags_number, kCFNumberSInt32Type, &flags));
  EXPECT_NE(flags & kSecCodeSignatureAdhoc, 0u);
}

TEST_F(AdHocSignerTest, PreserveMetadataKeepsIdentifier) {
  ASSERT_EQ(identifier_of(binary_), kFixtureIdentifier);

  ReturnCode ret = sign(binary_, true);
  if (skipped_) GTEST_SKIP() << "SecCodeSigner SPI unavailable";
  ASSERT_EQ(ret, ReturnCode::kOk);

  EXPECT_EQ(identifier_of(binary_), kFixtureIdentifier);
}

TEST_F(AdHocSignerTest, EmbedsCustomEntitlements) {
  CFPtr<CFStringRef> key(CFStringCreateWithCString(
      kCFAllocatorDefault, kGetTaskAllow, kCFStringEncodingUTF8));
  const void* keys[] = {key.get()};
  const void* values[] = {kCFBooleanTrue};
  CFPtr<CFDictionaryRef> entitlements(CFDictionaryCreate(
      kCFAllocatorDefault, keys, values, 1, &kCFTypeDictionaryKeyCallBacks,
      &kCFTypeDictionaryValueCallBacks));

  ReturnCode ret = sign(binary_, true, entitlements.get());
  if (skipped_) GTEST_SKIP() << "SecCodeSigner SPI unavailable";
  ASSERT_EQ(ret, ReturnCode::kOk);

  CFPtr<CFDictionaryRef> info = signing_information(binary_);
  ASSERT_TRUE(info);
  auto embedded = static_cast<CFDictionaryRef>(
      CFDictionaryGetValue(info.get(), kSecCodeInfoEntitlementsDict));
  ASSERT_NE(embedded, nullptr);
  EXPECT_EQ(CFDictionaryGetValue(embedded, key.get()), kCFBooleanTrue);
}

TEST_F(AdHocSignerTest, FailsForMissingFile) {
  ReturnCode ret = sign((dir_ / "missing").string(), false);
  if (skipped_) GTEST_SKIP() << "SecCodeSigner SPI unavailable";
  EXPECT_EQ(ret, ReturnCode::kErrCreateStaticCode);
}

}  // namespace
}  // namespace ct_bypass
