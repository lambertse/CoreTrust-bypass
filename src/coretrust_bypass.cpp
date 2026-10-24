#include "exploit/coretrust_bypass.h"

#include <string>

namespace mocha {

class CoreTrustBypassImpl {
 public:
  CoreTrustBypassImpl(const std::string& path) : path_(path) {}

  ReturnCode bypass() const;

 public:
  const std::string path_;
};

ReturnCode CoreTrustBypassImpl::bypass() const { return ReturnCode::kOk; }

CoreTrustBypass::CoreTrustBypass(const std::string& path)
    : impl_(std::make_unique<CoreTrustBypassImpl>(path)) {}

CoreTrustBypass::~CoreTrustBypass() = default;

CoreTrustBypass::Ptr CoreTrustBypass::create(const std::string& path) {
  return Ptr(new CoreTrustBypass(path));
}

ReturnCode CoreTrustBypass::bypass() { return impl_->bypass(); }

}  // namespace mocha
