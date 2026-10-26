#include "cf_ptr.h"

#include <CoreFoundation/CoreFoundation.h>
#include <gtest/gtest.h>

namespace ct_bypass {
namespace {

// A heap-allocated object, so retain counts are real. CFSTR constants and
// small CFNumbers are immortal or tagged pointers.
CFMutableArrayRef create_array() {
  return CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
}

TEST(CFPtr, ReleasesOnScopeExit) {
  CFMutableArrayRef array = create_array();
  CFRetain(array);  // keeps the array alive after the CFPtr releases it
  ASSERT_EQ(CFGetRetainCount(array), 2);

  { CFPtr<CFMutableArrayRef> owner(array); }

  EXPECT_EQ(CFGetRetainCount(array), 1);
  CFRelease(array);
}

TEST(CFPtr, ReleasesOnReset) {
  CFMutableArrayRef array = create_array();
  CFRetain(array);
  CFPtr<CFMutableArrayRef> owner(array);

  owner.reset();

  EXPECT_FALSE(owner);
  EXPECT_EQ(CFGetRetainCount(array), 1);
  CFRelease(array);
}

TEST(CFPtr, EmptyPointerIsNotReleased) {
  // CFRelease(NULL) crashes, so an empty CFPtr must never call it
  CFPtr<CFArrayRef> empty;
  EXPECT_FALSE(empty);
}

TEST(CfRetain, AddsAReference) {
  CFPtr<CFMutableArrayRef> owner(create_array());
  ASSERT_EQ(CFGetRetainCount(owner.get()), 1);

  {
    CFPtr<CFMutableArrayRef> second = cf_retain(owner.get());
    EXPECT_EQ(second.get(), owner.get());
    EXPECT_EQ(CFGetRetainCount(owner.get()), 2);
  }

  EXPECT_EQ(CFGetRetainCount(owner.get()), 1);
}

TEST(CfRetain, ReturnsEmptyForNull) {
  EXPECT_FALSE(cf_retain(static_cast<CFArrayRef>(nullptr)));
}

}  // namespace
}  // namespace ct_bypass
