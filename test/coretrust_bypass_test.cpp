#include "coretrust_bypass_internal.h"

#include <gtest/gtest.h>

#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <unistd.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include "exploit/coretrust_bypass.h"
#include "exploit/return_code.h"
#include "macho/cd_builders.h"
#include "macho/cs_blob.h"
#include "macho/digest.h"
#include "macho/macho.h"
#include "template/template.h"

namespace ct_bypass {

// Prints ReturnCode as its value instead of raw bytes in assertion failures.
void PrintTo(ReturnCode code, std::ostream* os) {
  *os << static_cast<int>(code);
}

namespace {

using namespace macho;
using macho::test::CdSpec;
using macho::test::make_blob;
using macho::test::make_cd;
using macho::test::make_superblob;

// Deserializes a SuperBlob from the given slot/body pairs; fails the test if
// the bytes don't parse.
SuperBlob build_superblob(
    const std::vector<std::pair<SlotType, Bytes>>& entries) {
  std::optional<SuperBlob> sb = SuperBlob::deserialize(make_superblob(entries));
  EXPECT_TRUE(sb.has_value());
  return sb.value_or(SuperBlob{});
}

uint32_t read_le32(const Bytes& data, size_t offset) {
  uint32_t value = 0;
  EXPECT_LE(offset + sizeof(value), data.size());
  if (offset + sizeof(value) <= data.size()) {
    memcpy(&value, data.data() + offset, sizeof(value));
  }
  return value;
}

Bytes read_file(const std::string& path) {
  std::ifstream file(path, std::ios::binary);
  EXPECT_TRUE(file) << "failed to open " << path;
  return Bytes((std::istreambuf_iterator<char>(file)),
               std::istreambuf_iterator<char>());
}

// Header-only thin 64-bit Mach-O.
Bytes make_header64(cpu_type_t cputype, cpu_subtype_t cpusubtype) {
  mach_header_64 header{};
  header.magic = MH_MAGIC_64;
  header.cputype = cputype;
  header.cpusubtype = cpusubtype;
  header.filetype = MH_EXECUTE;
  const auto* bytes = reinterpret_cast<const uint8_t*>(&header);
  return Bytes(bytes, bytes + sizeof(header));
}

// Universal binary holding `slices`, each aligned to 16 KiB.
Bytes make_fat(const std::vector<Bytes>& slices) {
  constexpr size_t kAlign = 0x4000;
  Bytes data(kAlign, 0);
  write_be32(data.data(), FAT_MAGIC);
  write_be32(data.data() + 4, static_cast<uint32_t>(slices.size()));
  for (size_t i = 0; i < slices.size(); i++) {
    const Bytes& slice = slices[i];
    size_t offset = data.size();
    uint8_t* entry = data.data() + sizeof(fat_header) + i * sizeof(fat_arch);
    // cputype and cpusubtype sit at offsets 4 and 8 of the slice's header
    write_be32(entry, read_le32(slice, 4));
    write_be32(entry + 4, read_le32(slice, 8));
    write_be32(entry + 8, static_cast<uint32_t>(offset));
    write_be32(entry + 12, static_cast<uint32_t>(slice.size()));
    write_be32(entry + 16, 14);  // log2 of the alignment
    data.insert(data.end(), slice.begin(), slice.end());
    data.resize((data.size() + kAlign - 1) / kAlign * kAlign, 0);
  }
  return data;
}

// Team ID baked into the bundled App Store CodeDirectory template.
std::string app_store_team_id() {
  Blob blob = Blob::blob_from_generic(
      SlotType::kCodeDirectory, templates::app_store_code_directory().data);
  std::optional<CodeDirectory> cd = CodeDirectory::deserialize(blob.data);
  EXPECT_TRUE(cd.has_value());
  return cd ? cd->team_id() : std::string();
}

//
// swap_in_app_store_cd
//

TEST(SwapInAppStoreCd, Sha256MainBecomesAlternate) {
  Bytes main_cd = make_cd({});  // SHA-256 by default
  SuperBlob sb = build_superblob({{SlotType::kCodeDirectory, main_cd}});

  std::string team;
  ASSERT_EQ(detail::swap_in_app_store_cd(sb, team), ReturnCode::kOk);
  EXPECT_FALSE(team.empty());

  // Slot 0 now holds the App Store CodeDirectory (SHA-1), not the original one
  std::optional<Blob> slot0 = sb.find_blob(SlotType::kCodeDirectory);
  ASSERT_TRUE(slot0);
  std::optional<CodeDirectory> cd0 = CodeDirectory::deserialize(slot0->data);
  ASSERT_TRUE(cd0);
  EXPECT_EQ(cd0->hash_type(), HashType::kSha1);
  EXPECT_EQ(cd0->team_id(), team);

  // The original SHA-256 CodeDirectory moved, unchanged, to slot 0x1000
  std::optional<Blob> alt = sb.find_blob(SlotType::kAlternateCodeDirectories);
  ASSERT_TRUE(alt);
  EXPECT_EQ(alt->data, main_cd);
}

TEST(SwapInAppStoreCd, PrefersAlternateCodeDirectory) {
  CdSpec sha1;
  sha1.hash_type = HashType::kSha1;
  sha1.hash_size = 20;
  Bytes main_cd = make_cd(sha1);
  Bytes alt_cd = make_cd({});  // SHA-256
  SuperBlob sb =
      build_superblob({{SlotType::kCodeDirectory, main_cd},
                       {SlotType::kAlternateCodeDirectories, alt_cd}});

  std::string team;
  ASSERT_EQ(detail::swap_in_app_store_cd(sb, team), ReturnCode::kOk);

  // The SHA-256 alternate is carried over, the SHA-1 main is dropped
  std::optional<Blob> alt = sb.find_blob(SlotType::kAlternateCodeDirectories);
  ASSERT_TRUE(alt);
  EXPECT_EQ(alt->data, alt_cd);
  std::optional<Blob> slot0 = sb.find_blob(SlotType::kCodeDirectory);
  ASSERT_TRUE(slot0);
  EXPECT_EQ(CodeDirectory::deserialize(slot0->data)->hash_type(),
            HashType::kSha1);
}

TEST(SwapInAppStoreCd, RejectsSha1OnlyCodeDirectory) {
  CdSpec sha1;
  sha1.hash_type = HashType::kSha1;
  sha1.hash_size = 20;
  SuperBlob sb = build_superblob({{SlotType::kCodeDirectory, make_cd(sha1)}});

  std::string team;
  EXPECT_EQ(detail::swap_in_app_store_cd(sb, team),
            ReturnCode::kErrCodeDirNotSha256);
}

TEST(SwapInAppStoreCd, RejectsMalformedCodeDirectory) {
  Bytes cd = make_cd({});
  write_be32(cd.data(), 0);  // wipe the magic; the blob length stays valid
  SuperBlob sb = build_superblob({{SlotType::kCodeDirectory, cd}});

  std::string team;
  EXPECT_EQ(detail::swap_in_app_store_cd(sb, team),
            ReturnCode::kErrCodeDirMalformed);
}

TEST(SwapInAppStoreCd, RejectsMissingCodeDirectory) {
  Bytes entitlements =
      make_blob(0xfade7171, 32, 0xaa);  // CSMAGIC_EMBEDDED_ENTITLEMENTS
  SuperBlob sb = build_superblob({{SlotType::kEntitlements, entitlements}});

  std::string team;
  EXPECT_EQ(detail::swap_in_app_store_cd(sb, team),
            ReturnCode::kErrCodeDirMissing);
}

//
// adopt_app_store_team_id  (catches the write-back bug: mutations landed on a
// throwaway copy and never reached the SuperBlob)
//

TEST(AdoptAppStoreTeamId, WritesTeamIdAndClearsFlagsBack) {
  CdSpec spec;
  spec.flags = 0x2;  // adhoc flag set
  spec.team_id = std::string("ORIGINAL12");
  SuperBlob sb = build_superblob(
      {{SlotType::kAlternateCodeDirectories, make_cd(spec)}});

  ASSERT_EQ(detail::adopt_app_store_team_id(sb, "APPSTORE99"),
            ReturnCode::kOk);

  std::optional<Blob> alt = sb.find_blob(SlotType::kAlternateCodeDirectories);
  ASSERT_TRUE(alt);
  std::optional<CodeDirectory> cd = CodeDirectory::deserialize(alt->data);
  ASSERT_TRUE(cd);
  EXPECT_EQ(cd->team_id(), "APPSTORE99");
  EXPECT_EQ(cd->flags(), 0u);
}

TEST(AdoptAppStoreTeamId, FailsWithoutAlternateCodeDirectory) {
  SuperBlob sb = build_superblob({{SlotType::kCodeDirectory, make_cd({})}});
  EXPECT_EQ(detail::adopt_app_store_team_id(sb, "APPSTORE99"),
            ReturnCode::kErrCodeDirMissing);
}

//
// compute_cdhashes
//

TEST(ComputeCdhashes, HashesBothCodeDirectories) {
  Bytes cd0 = make_cd({});
  CdSpec alt_spec;
  alt_spec.identifier = "com.example.alt";
  Bytes cd1 = make_cd(alt_spec);
  SuperBlob sb =
      build_superblob({{SlotType::kCodeDirectory, cd0},
                       {SlotType::kAlternateCodeDirectories, cd1}});

  Bytes sha1;
  Bytes sha256;
  ASSERT_EQ(detail::compute_cdhashes(sb, sha1, sha256), ReturnCode::kOk);
  EXPECT_EQ(sha1, compute_digest(HashType::kSha1, cd0.data(), cd0.size()));
  EXPECT_EQ(sha256, compute_digest(HashType::kSha256, cd1.data(), cd1.size()));
}

TEST(ComputeCdhashes, FailsWithoutAlternateCodeDirectory) {
  SuperBlob sb = build_superblob({{SlotType::kCodeDirectory, make_cd({})}});
  Bytes sha1;
  Bytes sha256;
  EXPECT_EQ(detail::compute_cdhashes(sb, sha1, sha256),
            ReturnCode::kErrCodeDirMissing);
}

//
// check_supported_macho / load_code_signature against the real fixture
//

TEST(CheckSupportedMacho, AcceptsExecutableFixture) {
  MachO::Ptr macho;
  ASSERT_EQ(MachO::load(AD_HOC_SIGNER_FIXTURE_PATH, macho), ReturnCode::kOk);
  EXPECT_EQ(detail::check_supported_macho(*macho), ReturnCode::kOk);
}

TEST(LoadCodeSignature, DecodesFixtureSignature) {
  MachO::Ptr macho;
  ASSERT_EQ(MachO::load(AD_HOC_SIGNER_FIXTURE_PATH, macho), ReturnCode::kOk);

  // A valid signature must decode to kOk (catches the inverted success test
  // that rejected good signatures and dereferenced an empty optional).
  SuperBlob superblob;
  size_t offset = 0;
  ASSERT_EQ(detail::load_code_signature(*macho, superblob, offset),
            ReturnCode::kOk);
  EXPECT_TRUE(superblob.find_blob(SlotType::kCodeDirectory).has_value());
}

TEST(CheckSupportedMacho, RejectsUniversalBinary) {
  MachO::Ptr macho;
  ASSERT_EQ(MachO::from_bytes(make_fat({read_file(MACHO_SAMPLE_PATH)}), macho),
            ReturnCode::kOk);
  EXPECT_EQ(detail::check_supported_macho(*macho),
            ReturnCode::kErrMachoNoUsableSlice);
}

//
// select_slice
//

TEST(SelectSlice, KeepsThinMachO) {
  MachO::Ptr macho;
  ASSERT_EQ(MachO::load(MACHO_SAMPLE_PATH, macho), ReturnCode::kOk);
  const MachO* thin = macho.get();

  ASSERT_EQ(detail::select_slice(macho), ReturnCode::kOk);
  EXPECT_EQ(macho.get(), thin);
}

TEST(SelectSlice, ExtractsArm64SliceFromUniversalBinary) {
  // macho_sample is plain arm64, which every arm64 host and macOS can pick
  Bytes sample = read_file(MACHO_SAMPLE_PATH);
  MachO::Ptr macho;
  ASSERT_EQ(MachO::from_bytes(
                make_fat({make_header64(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL),
                          sample}),
                macho),
            ReturnCode::kOk);

  ASSERT_EQ(detail::select_slice(macho), ReturnCode::kOk);
  EXPECT_TRUE(macho->is_thin_64());
  EXPECT_TRUE(macho->data() == sample);
  EXPECT_EQ(detail::check_supported_macho(*macho), ReturnCode::kOk);
}

TEST(SelectSlice, FailsWithoutArm64Slice) {
  MachO::Ptr macho;
  ASSERT_EQ(MachO::from_bytes(
                make_fat({make_header64(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL)}),
                macho),
            ReturnCode::kOk);
  EXPECT_EQ(detail::select_slice(macho), ReturnCode::kErrMachoNoUsableSlice);
}

//
// End-to-end bypass on a freshly ad-hoc-signed fixture. macho_sample can't be
// used here: its slot 0 is already a transplanted App Store CD, which would
// mask the swap and write-back bugs. The fixture has a non-App-Store slot 0, a
// different Team ID, the adhoc flag set and a signature whose size changes, so
// the invariants below actually exercise the fix.
//

class CoreTrustBypassE2E : public ::testing::Test {
 protected:
  void SetUp() override {
    namespace fs = std::filesystem;
    std::string tmpl = (fs::temp_directory_path() / "ct_bypass_XXXXXX").string();
    std::vector<char> buffer(tmpl.begin(), tmpl.end());
    buffer.push_back('\0');
    ASSERT_NE(mkdtemp(buffer.data()), nullptr);
    dir_ = buffer.data();
    out_ = (fs::path(dir_) / "fixture").string();
    fs::copy_file(AD_HOC_SIGNER_FIXTURE_PATH, out_,
                  fs::copy_options::overwrite_existing);
  }

  void TearDown() override {
    if (!dir_.empty()) {
      std::error_code ec;
      std::filesystem::remove_all(dir_, ec);
    }
  }

  std::string dir_;
  std::string out_;
};

TEST_F(CoreTrustBypassE2E, ProducesAConsistentSignature) {
  CoreTrustBypass::Ptr bypass = CoreTrustBypass::create(out_);
  ReturnCode rc = bypass->bypass();
  if (rc == ReturnCode::kErrCodeDirNotSha256) {
    GTEST_SKIP() << "fixture isn't SHA-256 signed on this host";
  }
  ASSERT_EQ(rc, ReturnCode::kOk);

  MachO::Ptr macho;
  ASSERT_EQ(MachO::load(out_, macho), ReturnCode::kOk);
  size_t offset = 0;
  size_t size = 0;
  ASSERT_EQ(macho->get_signature_range(offset, size), ReturnCode::kOk);
  Bytes file = macho->data();
  Bytes signature(file.begin() + offset, file.begin() + offset + size);
  std::optional<SuperBlob> sb = SuperBlob::deserialize(signature);
  ASSERT_TRUE(sb);

  std::optional<Blob> slot0 = sb->find_blob(SlotType::kCodeDirectory);
  std::optional<Blob> alt = sb->find_blob(SlotType::kAlternateCodeDirectories);
  std::optional<Blob> cms = sb->find_blob(SlotType::kSignature);
  ASSERT_TRUE(slot0);
  ASSERT_TRUE(alt);
  ASSERT_TRUE(cms);

  std::optional<CodeDirectory> cd0 = CodeDirectory::deserialize(slot0->data);
  std::optional<CodeDirectory> cd_alt = CodeDirectory::deserialize(alt->data);
  ASSERT_TRUE(cd0);
  ASSERT_TRUE(cd_alt);

  // Bug E: slot 0 must be the bundled App Store CodeDirectory verbatim, not the
  // original one. Comparing the bytes catches it even on a host whose fixture
  // already has a SHA-1 slot 0.
  Blob expected_app_store = Blob::blob_from_generic(
      SlotType::kCodeDirectory, templates::app_store_code_directory().data);
  EXPECT_EQ(slot0->data, expected_app_store.data);
  EXPECT_EQ(cd0->hash_type(), HashType::kSha1);
  EXPECT_EQ(cd_alt->hash_type(), HashType::kSha256);

  // Bug B: the real CD adopted the App Store Team ID and cleared its flags
  std::string team = app_store_team_id();
  EXPECT_FALSE(team.empty());
  EXPECT_EQ(cd0->team_id(), team);
  EXPECT_EQ(cd_alt->team_id(), team);
  EXPECT_EQ(cd_alt->flags(), 0u);

  // Bug A: the real CD's page hashes match the final file. Recomputing them is
  // a no-op only if they were written back after the load commands were
  // resized; stale hashes would differ.
  std::optional<CodeDirectory> recomputed =
      CodeDirectory::deserialize(alt->data);
  ASSERT_TRUE(recomputed);
  ASSERT_EQ(recomputed->update_code_slots(file.data(), offset),
            ReturnCode::kOk);
  EXPECT_EQ(recomputed->data(), cd_alt->data());

  // The CMS must actually vouch for the final CodeDirectories: the DER cdhash
  // attribute embeds the raw SHA-1 (slot 0) and SHA-256 (slot 0x1000) hashes.
  // This catches a signer that signed stale cdhashes, or swapped SHA-1/SHA-256.
  std::optional<Bytes> sha1 =
      compute_digest(HashType::kSha1, slot0->data.data(), slot0->data.size());
  std::optional<Bytes> sha256 =
      compute_digest(HashType::kSha256, alt->data.data(), alt->data.size());
  ASSERT_TRUE(sha1);
  ASSERT_TRUE(sha256);
  EXPECT_NE(std::search(cms->data.begin(), cms->data.end(), sha1->begin(),
                        sha1->end()),
            cms->data.end());
  EXPECT_NE(std::search(cms->data.begin(), cms->data.end(), sha256->begin(),
                        sha256->end()),
            cms->data.end());
}

// A universal input is replaced by its re-signed arm64 slice
TEST_F(CoreTrustBypassE2E, ThinsUniversalBinary) {
  std::string universal = (std::filesystem::path(dir_) / "universal").string();
  {
    Bytes fat = make_fat({make_header64(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL),
                          read_file(MACHO_SAMPLE_PATH)});
    std::ofstream file(universal, std::ios::binary | std::ios::trunc);
    file.write(reinterpret_cast<const char*>(fat.data()),
               static_cast<std::streamsize>(fat.size()));
    ASSERT_TRUE(file);
  }

  ASSERT_EQ(CoreTrustBypass::create(universal)->bypass(), ReturnCode::kOk);

  MachO::Ptr macho;
  ASSERT_EQ(MachO::load(universal, macho), ReturnCode::kOk);
  ASSERT_TRUE(macho->is_thin_64());
  EXPECT_EQ(macho->get_slices()[0].cputype, CPU_TYPE_ARM64);

  SuperBlob superblob;
  size_t offset = 0;
  ASSERT_EQ(detail::load_code_signature(*macho, superblob, offset),
            ReturnCode::kOk);
  std::optional<Blob> alt =
      superblob.find_blob(SlotType::kAlternateCodeDirectories);
  std::optional<Blob> cms = superblob.find_blob(SlotType::kSignature);
  ASSERT_TRUE(alt);
  ASSERT_TRUE(cms);

  // The thinned slice was actually re-signed: the CMS vouches for the real
  // CodeDirectory, i.e. its SHA-256 appears in the signature. macho_sample's
  // slot 0 is already the App Store CD, so comparing slot 0 would prove
  // nothing.
  std::optional<Bytes> sha256 =
      compute_digest(HashType::kSha256, alt->data.data(), alt->data.size());
  ASSERT_TRUE(sha256);
  EXPECT_NE(std::search(cms->data.begin(), cms->data.end(), sha256->begin(),
                        sha256->end()),
            cms->data.end());
}

}  // namespace
}  // namespace ct_bypass
