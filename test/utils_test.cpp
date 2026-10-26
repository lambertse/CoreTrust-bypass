#include "utils.h"

#include <CoreFoundation/CoreFoundation.h>
#include <gtest/gtest.h>
#include <sys/param.h>

#include <filesystem>
#include <string>

#include "cf_ptr.h"

namespace ct_bypass::utils {
namespace {

CFPtr<CFStringRef> create_string(const char* utf8) {
  return CFPtr<CFStringRef>(CFStringCreateWithCString(
      kCFAllocatorDefault, utf8, kCFStringEncodingUTF8));
}

std::string file_system_path(CFURLRef url) {
  char path[MAXPATHLEN];
  if (!CFURLGetFileSystemRepresentation(url, true,
                                        reinterpret_cast<UInt8*>(path),
                                        sizeof(path))) {
    return {};
  }
  return path;
}

TEST(CfDescription, ReturnsNullMarkerForNull) {
  EXPECT_EQ(cf_description(nullptr), "(null)");
}

TEST(CfDescription, ContainsStringContents) {
  CFPtr<CFStringRef> string = create_string("ct-bypass description test");
  ASSERT_TRUE(string);
  EXPECT_NE(cf_description(string.get()).find("ct-bypass description test"),
            std::string::npos);
}

TEST(CfDescription, KeepsNonAsciiCharacters) {
  // UTF-8 needs more bytes than characters; the buffer must account for it
  CFPtr<CFStringRef> string = create_string("Thế giới ✓");
  ASSERT_TRUE(string);
  EXPECT_NE(cf_description(string.get()).find("Thế giới ✓"),
            std::string::npos);
}

TEST(CreateFileUrl, KeepsAbsolutePath) {
  CFPtr<CFURLRef> url = create_file_url("/tmp/ct_bypass/some file.bin");
  ASSERT_TRUE(url);
  EXPECT_EQ(file_system_path(url.get()), "/tmp/ct_bypass/some file.bin");
  EXPECT_FALSE(CFURLHasDirectoryPath(url.get()));
}

TEST(CreateFileUrl, ResolvesRelativePathAgainstWorkingDirectory) {
  CFPtr<CFURLRef> url = create_file_url("relative/binary");
  ASSERT_TRUE(url);
  EXPECT_EQ(file_system_path(url.get()),
            (std::filesystem::current_path() / "relative/binary").string());
}

}  // namespace
}  // namespace ct_bypass::utils
