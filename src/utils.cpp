#include "utils.h"

#include <filesystem>
#include <system_error>
#include <vector>

namespace ct_bypass::utils {

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
  // Without a working directory the path is used as given
  std::error_code ec;
  std::string abs = std::filesystem::absolute(path, ec).string();
  if (ec) abs = path;

  return CFPtr<CFURLRef>(CFURLCreateFromFileSystemRepresentation(
      kCFAllocatorDefault, reinterpret_cast<const UInt8*>(abs.c_str()),
      static_cast<CFIndex>(abs.size()), false));
}

}  // namespace ct_bypass::utils
