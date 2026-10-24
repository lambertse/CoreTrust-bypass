#ifndef CT_BYPASS_CF_PTR_H
#define CT_BYPASS_CF_PTR_H

#include <CoreFoundation/CoreFoundation.h>

#include <memory>
#include <type_traits>

namespace ct_bypass {

// Releases a CoreFoundation object when the owning CFPtr goes out of scope.
struct CFDeleter {
  void operator()(CFTypeRef ref) const { CFRelease(ref); }
};

// Owning smart pointer for CoreFoundation "Create"/"Copy" results,
// e.g. CFPtr<CFStringRef>.
template <typename Ref>
using CFPtr = std::unique_ptr<std::remove_pointer_t<Ref>, CFDeleter>;

// Takes a +1 reference to a borrowed object. Returns an empty CFPtr for null.
template <typename Ref>
CFPtr<Ref> cf_retain(Ref ref) {
  if (!ref) return nullptr;
  return CFPtr<Ref>(static_cast<Ref>(const_cast<void*>(CFRetain(ref))));
}

}  // namespace ct_bypass

#endif  // CT_BYPASS_CF_PTR_H
