#include "utils.h"

#include <unistd.h>

#include <climits>
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

CFPtr<CFURLRef> create_file_url(const char* path) {
  std::string full_path(path ? path : "");
  if (full_path.empty() || full_path[0] != '/') {
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)))
      full_path = std::string(cwd) + "/" + full_path;
  }
  return CFPtr<CFURLRef>(CFURLCreateFromFileSystemRepresentation(
      kCFAllocatorDefault, reinterpret_cast<const UInt8*>(full_path.c_str()),
      static_cast<CFIndex>(full_path.size()), false));
}

}  // namespace mocha::utils
