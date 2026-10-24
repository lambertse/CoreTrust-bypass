#include "utils.h"

#include <unistd.h>

#include <filesystem>
#include <vector>

namespace mocha::utils {

std::string cf_description(CFTypeRef obj) {
  if (!obj) return "(null)";
  CFPtr<CFStringRef> desc(CFCopyDescription(obj));
  if (!desc) return "(null)";

  const CFIndex size =
      CFStringGetMaximumSizeForEncoding(CFStringGetLength(desc.get()),
                                        kCFStringEncodingUTF8) +
      1;
  std::vector<char> buf(size);
  if (!CFStringGetCString(desc.get(), buf.data(), size,
                          kCFStringEncodingUTF8)) {
    return "(null)";
  }
  return std::string(buf.data());
}

CFPtr<CFURLRef> create_file_url(const std::string& path) {
  const auto abs = std::filesystem::absolute(path).string();

  return CFPtr<CFURLRef>(CFURLCreateFromFileSystemRepresentation(
      kCFAllocatorDefault, reinterpret_cast<const UInt8*>(abs.c_str()),
      static_cast<CFIndex>(abs.size()), false));
}

}  // namespace mocha::utils
