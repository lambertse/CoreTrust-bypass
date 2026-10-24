#ifndef CT_BYPASS_UTILS_H
#define CT_BYPASS_UTILS_H

#include <CoreFoundation/CoreFoundation.h>

#include <string>

#include "cf_ptr.h"

namespace ct_bypass::utils {

// Returns CFCopyDescription() of `obj` as UTF-8, or "(null)".
std::string cf_description(CFTypeRef obj);

// Creates a file URL for `path`, resolving relative paths against the
// current working directory.
CFPtr<CFURLRef> create_file_url(const std::string& path);

}  // namespace ct_bypass::utils

#endif  // CT_BYPASS_UTILS_H
