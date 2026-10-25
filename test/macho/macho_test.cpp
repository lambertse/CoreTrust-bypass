#include "macho/macho.h"

#include <gtest/gtest.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <ostream>
#include <string>
#include <system_error>
#include <vector>

namespace ct_bypass {

// Prints ReturnCode as its value instead of raw bytes in assertion failures.
void PrintTo(ReturnCode code, std::ostream* os) {
  *os << static_cast<int>(code);
}

namespace macho {
namespace {

// Big-endian magic of an embedded signature SuperBlob.
constexpr uint32_t kEmbeddedSignatureMagic = 0xfade0cc0;

// Layout of the thin 64-bit Mach-O built by make_signed_macho().
constexpr size_t kLinkeditCommandOffset = sizeof(mach_header_64);
constexpr size_t kCodeSignatureCommandOffset =
    kLinkeditCommandOffset + sizeof(segment_command_64);
constexpr size_t kCommandsEnd =
    kCodeSignatureCommandOffset + sizeof(linkedit_data_command);
constexpr uint64_t kLinkeditOffset = 0x4000;
constexpr uint64_t kLinkeditVmAddr = 0x100004000;
constexpr uint32_t kSignatureOffset = 0x4100;
constexpr uint64_t kPageSize = 0x4000;

// Filler bytes so tests can tell zeroed bytes from untouched ones.
constexpr Byte kLinkeditFill = 0x5a;
constexpr Byte kSignatureFill = 0xab;
constexpr Byte kTrailingFill = 0xc3;
constexpr Byte kBlobFill = 0xcd;

// Fat slice i is placed at kFatSliceStride * (i + 1); every slice built here
// fits in one stride.
constexpr uint64_t kFatSliceStride = 0x10000;

// LC_CODE_SIGNATURE of test/macho_sample.
constexpr size_t kSampleSignatureOffset = 0xe8a50;
constexpr size_t kSampleSignatureSize = 0xb904;

template <typename T>
void put(Bytes& data, size_t offset, const T& value) {
  ASSERT_LE(offset + sizeof(T), data.size());
  memcpy(data.data() + offset, &value, sizeof(T));
}

template <typename T>
T get(const Bytes& data, size_t offset) {
  T value{};
  EXPECT_LE(offset + sizeof(T), data.size());
  if (offset + sizeof(T) <= data.size()) {
    memcpy(&value, data.data() + offset, sizeof(T));
  }
  return value;
}

void put_be32(Bytes& data, size_t offset, uint32_t value) {
  ASSERT_LE(offset + 4, data.size());
  for (size_t i = 0; i < 4; i++) {
    data[offset + i] = static_cast<Byte>(value >> (24 - 8 * i));
  }
}

void put_be64(Bytes& data, size_t offset, uint64_t value) {
  put_be32(data, offset, static_cast<uint32_t>(value >> 32));
  put_be32(data, offset + 4, static_cast<uint32_t>(value));
}

uint32_t get_be32(const Bytes& data, size_t offset) {
  EXPECT_LE(offset + 4, data.size());
  if (offset + 4 > data.size()) return 0;
  return (uint32_t)data[offset] << 24 | (uint32_t)data[offset + 1] << 16 |
         (uint32_t)data[offset + 2] << 8 | (uint32_t)data[offset + 3];
}

::testing::AssertionResult range_filled_with(const Bytes& data, size_t begin,
                                             size_t end, Byte value) {
  if (begin > end || end > data.size()) {
    return ::testing::AssertionFailure()
           << "range [" << begin << ", " << end << ") outside " << data.size()
           << " bytes";
  }
  for (size_t i = begin; i < end; i++) {
    if (data[i] != value) {
      return ::testing::AssertionFailure()
             << "byte at 0x" << std::hex << i << " is 0x" << int(data[i])
             << ", expected 0x" << int(value);
    }
  }
  return ::testing::AssertionSuccess();
}

::testing::AssertionResult range_equals(const Bytes& data, size_t offset,
                                        const Bytes& expected) {
  if (offset > data.size() || expected.size() > data.size() - offset) {
    return ::testing::AssertionFailure()
           << expected.size() << " bytes at " << offset << " outside "
           << data.size() << " bytes";
  }
  auto mismatch =
      std::mismatch(expected.begin(), expected.end(), data.begin() + offset);
  if (mismatch.first != expected.end()) {
    return ::testing::AssertionFailure()
           << "byte at 0x" << std::hex
           << offset + (mismatch.first - expected.begin()) << " is 0x"
           << int(*mismatch.second) << ", expected 0x" << int(*mismatch.first);
  }
  return ::testing::AssertionSuccess();
}

// Header-only thin 64-bit Mach-O with no load commands.
Bytes make_header64(cpu_type_t cputype, cpu_subtype_t cpusubtype,
                    uint32_t filetype = MH_EXECUTE) {
  Bytes data(sizeof(mach_header_64));
  mach_header_64 header{};
  header.magic = MH_MAGIC_64;
  header.cputype = cputype;
  header.cpusubtype = cpusubtype;
  header.filetype = filetype;
  put(data, 0, header);
  return data;
}

// Header-only thin 32-bit Mach-O with no load commands.
Bytes make_header32(cpu_type_t cputype, cpu_subtype_t cpusubtype,
                    uint32_t filetype = MH_EXECUTE) {
  Bytes data(sizeof(mach_header));
  mach_header header{};
  header.magic = MH_MAGIC;
  header.cputype = cputype;
  header.cpusubtype = cpusubtype;
  header.filetype = filetype;
  put(data, 0, header);
  return data;
}

// Signed thin 64-bit arm64 executable whose LC_CODE_SIGNATURE covers
// `datasize` bytes holding a SuperBlob of `blob_length`, followed by
// `trailing` bytes outside the range:
//   [0, kCommandsEnd)                    header, __LINKEDIT, LC_CODE_SIGNATURE
//   [kLinkeditOffset, kSignatureOffset)  __LINKEDIT data (kLinkeditFill)
//   [kSignatureOffset, +datasize)        SuperBlob header, then kSignatureFill
//   [.., +trailing)                      kTrailingFill
// __LINKEDIT runs to the end of the file.
Bytes make_signed_macho(uint32_t datasize = 0x200, uint32_t blob_length = 0x180,
                        uint32_t trailing = 0) {
  size_t signature_end = kSignatureOffset + datasize;
  size_t file_size = signature_end + trailing;
  Bytes data(file_size, 0);
  std::fill(data.begin() + kLinkeditOffset, data.begin() + kSignatureOffset,
            kLinkeditFill);
  std::fill(data.begin() + kSignatureOffset, data.begin() + signature_end,
            kSignatureFill);
  std::fill(data.begin() + signature_end, data.end(), kTrailingFill);

  mach_header_64 header{};
  header.magic = MH_MAGIC_64;
  header.cputype = CPU_TYPE_ARM64;
  header.cpusubtype = CPU_SUBTYPE_ARM64_ALL;
  header.filetype = MH_EXECUTE;
  header.ncmds = 2;
  header.sizeofcmds = kCommandsEnd - sizeof(mach_header_64);
  put(data, 0, header);

  segment_command_64 linkedit{};
  linkedit.cmd = LC_SEGMENT_64;
  linkedit.cmdsize = sizeof(segment_command_64);
  memcpy(linkedit.segname, SEG_LINKEDIT, sizeof(SEG_LINKEDIT));
  linkedit.vmaddr = kLinkeditVmAddr;
  linkedit.fileoff = kLinkeditOffset;
  linkedit.filesize = file_size - kLinkeditOffset;
  linkedit.vmsize = (linkedit.filesize + kPageSize - 1) & ~(kPageSize - 1);
  linkedit.maxprot = VM_PROT_READ;
  linkedit.initprot = VM_PROT_READ;
  put(data, kLinkeditCommandOffset, linkedit);

  linkedit_data_command cs{};
  cs.cmd = LC_CODE_SIGNATURE;
  cs.cmdsize = sizeof(linkedit_data_command);
  cs.dataoff = kSignatureOffset;
  cs.datasize = datasize;
  put(data, kCodeSignatureCommandOffset, cs);

  if (datasize >= 8) {
    put_be32(data, kSignatureOffset, kEmbeddedSignatureMagic);
    put_be32(data, kSignatureOffset + 4, blob_length);
  }
  return data;
}

uint64_t fat_slice_offset(size_t index) {
  return kFatSliceStride * (index + 1);
}

size_t fat_entry_offset(size_t index, bool is64) {
  return sizeof(fat_header) +
         index * (is64 ? sizeof(fat_arch_64) : sizeof(fat_arch));
}

// Universal binary holding `slices`, each placed at fat_slice_offset(i).
Bytes make_fat(const std::vector<Bytes>& slices, bool is64 = false) {
  size_t file_size = sizeof(fat_header);
  if (!slices.empty()) {
    file_size = fat_slice_offset(slices.size() - 1) + slices.back().size();
  }
  Bytes data(file_size, 0);
  put_be32(data, 0, is64 ? FAT_MAGIC_64 : FAT_MAGIC);
  put_be32(data, 4, static_cast<uint32_t>(slices.size()));
  for (size_t i = 0; i < slices.size(); i++) {
    const Bytes& slice = slices[i];
    EXPECT_LE(slice.size(), kFatSliceStride) << "slice " << i;
    if (slice.size() > kFatSliceStride) return {};
    uint64_t offset = fat_slice_offset(i);
    size_t entry = fat_entry_offset(i, is64);
    // cputype and cpusubtype sit at the same offsets in both header widths.
    put_be32(data, entry, get<uint32_t>(slice, 4));
    put_be32(data, entry + 4, get<uint32_t>(slice, 8));
    if (is64) {
      put_be64(data, entry + 8, offset);
      put_be64(data, entry + 16, slice.size());
      put_be32(data, entry + 24, 12);
    } else {
      put_be32(data, entry + 8, static_cast<uint32_t>(offset));
      put_be32(data, entry + 12, static_cast<uint32_t>(slice.size()));
      put_be32(data, entry + 16, 12);
    }
    std::copy(slice.begin(), slice.end(), data.begin() + offset);
  }
  return data;
}

bool host_cpu_type(cpu_type_t& out_cputype, cpu_subtype_t& out_cpusubtype) {
  size_t len = sizeof(out_cputype);
  if (sysctlbyname("hw.cputype", &out_cputype, &len, nullptr, 0) != 0) {
    return false;
  }
  len = sizeof(out_cpusubtype);
  return sysctlbyname("hw.cpusubtype", &out_cpusubtype, &len, nullptr, 0) == 0;
}

bool host_is_arm64e() {
  cpu_type_t cputype;
  cpu_subtype_t cpusubtype;
  return host_cpu_type(cputype, cpusubtype) && cputype == CPU_TYPE_ARM64 &&
         (static_cast<uint32_t>(cpusubtype) & ~CPU_SUBTYPE_MASK) ==
             static_cast<uint32_t>(CPU_SUBTYPE_ARM64E);
}

// Darwin 20 (macOS 11 / iOS 14) moved arm64e to the new ABI.
bool host_uses_arm64e_abi_v2() {
  struct utsname name;
  return uname(&name) == 0 && atoi(name.release) >= 20;
}

constexpr cpu_subtype_t kArm64eAbiV2 =
    static_cast<cpu_subtype_t>(CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_ARM64E_ABI_V2);

class MachOTest : public ::testing::Test {
 protected:
  void SetUp() override {
    std::string dir =
        (std::filesystem::temp_directory_path() / "macho_test.XXXXXX").string();
    ASSERT_NE(mkdtemp(dir.data()), nullptr);
    dir_ = dir;
  }

  void TearDown() override {
    if (!dir_.empty()) {
      std::error_code ec;
      std::filesystem::remove_all(dir_, ec);
    }
  }

  std::string path(const std::string& name) const {
    return (dir_ / name).string();
  }

  std::string write_file(const Bytes& data,
                         const std::string& name = "input") const {
    std::string filepath = path(name);
    std::ofstream file(filepath, std::ios::binary | std::ios::trunc);
    file.write(reinterpret_cast<const char*>(data.data()),
               static_cast<std::streamsize>(data.size()));
    EXPECT_TRUE(file) << "failed to write " << filepath;
    return filepath;
  }

  static Bytes read_file(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    EXPECT_TRUE(file) << "failed to open " << filepath;
    return Bytes((std::istreambuf_iterator<char>(file)),
                 std::istreambuf_iterator<char>());
  }

  // Loads `data` through a temporary file.
  ReturnCode load(const Bytes& data, MachO::Ptr& out_macho) const {
    return MachO::load(write_file(data), out_macho);
  }

  // Returns the bytes MachO::save writes for `macho`.
  Bytes saved(const MachO::Ptr& macho) const {
    std::string filepath = path("output");
    EXPECT_EQ(MachO::save(filepath, macho), ReturnCode::kOk);
    return read_file(filepath);
  }

  std::filesystem::path dir_;
};

using MachOLoadTest = MachOTest;
using MachOLoadCommandsTest = MachOTest;
using MachOFindSliceTest = MachOTest;
using MachOFindPreferredSliceTest = MachOTest;
using MachOGetSignatureRangeTest = MachOTest;
using MachOResizeCodeSignatureTest = MachOTest;
using MachOUpdateCodeSignatureTest = MachOTest;
using MachOSaveTest = MachOTest;
using MachOSampleTest = MachOTest;

// load: thin files

TEST_F(MachOLoadTest, FailsForMissingFile) {
  MachO::Ptr macho;
  EXPECT_EQ(MachO::load(path("missing"), macho), ReturnCode::kErrCommon);
  EXPECT_EQ(macho, nullptr);
}

TEST_F(MachOLoadTest, FailsForEmptyFile) {
  MachO::Ptr macho;
  EXPECT_EQ(load({}, macho), ReturnCode::kErrCommon);
  EXPECT_EQ(macho, nullptr);
}

TEST_F(MachOLoadTest, FailsForFileSmallerThanFatHeader) {
  Bytes data = make_header64(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
  data.resize(sizeof(fat_header) - 1);
  MachO::Ptr macho;
  EXPECT_EQ(load(data, macho), ReturnCode::kErrCommon);
}

TEST_F(MachOLoadTest, FailsForTruncatedHeader) {
  Bytes data = make_header64(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
  data.resize(sizeof(mach_header_64) - 1);
  MachO::Ptr macho;
  EXPECT_EQ(load(data, macho), ReturnCode::kErrCommon);
}

TEST_F(MachOLoadTest, FailsForNonMachO) {
  std::string text = "#!/bin/sh\necho 'definitely not a Mach-O'\n";
  MachO::Ptr macho;
  EXPECT_EQ(load(Bytes(text.begin(), text.end()), macho),
            ReturnCode::kErrCommon);
}

TEST_F(MachOLoadTest, FailsForByteSwappedMachO) {
  Bytes data = make_header64(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
  put<uint32_t>(data, 0, MH_CIGAM_64);
  MachO::Ptr macho;
  EXPECT_EQ(load(data, macho), ReturnCode::kErrCommon);
}

TEST_F(MachOLoadTest, LeavesOutputUntouchedOnFailure) {
  MachO::Ptr macho;
  ASSERT_EQ(load(make_signed_macho(), macho), ReturnCode::kOk);
  const MachO* previous = macho.get();

  EXPECT_EQ(MachO::load(path("missing"), macho), ReturnCode::kErrCommon);
  EXPECT_EQ(macho.get(), previous);
}

TEST_F(MachOLoadTest, LoadsThin64) {
  Bytes data = make_signed_macho();
  MachO::Ptr macho;
  ASSERT_EQ(load(data, macho), ReturnCode::kOk);
  ASSERT_NE(macho, nullptr);

  const MachOSliceList& slices = macho->get_slices();
  ASSERT_EQ(slices.size(), 1u);
  EXPECT_EQ(slices[0].cputype, CPU_TYPE_ARM64);
  EXPECT_EQ(slices[0].cpusubtype, CPU_SUBTYPE_ARM64_ALL);
  EXPECT_EQ(slices[0].filetype, static_cast<uint32_t>(MH_EXECUTE));
  EXPECT_EQ(slices[0].offset, 0u);
  EXPECT_EQ(slices[0].size, data.size());
}

TEST_F(MachOLoadTest, LoadsThin64WithoutLoadCommands) {
  MachO::Ptr macho;
  ASSERT_EQ(
      load(make_header64(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, MH_DYLIB),
           macho),
      ReturnCode::kOk);

  const MachOSliceList& slices = macho->get_slices();
  ASSERT_EQ(slices.size(), 1u);
  EXPECT_EQ(slices[0].cputype, CPU_TYPE_X86_64);
  EXPECT_EQ(slices[0].filetype, static_cast<uint32_t>(MH_DYLIB));
  EXPECT_EQ(slices[0].size, sizeof(mach_header_64));
}

TEST_F(MachOLoadTest, LoadsThin32) {
  Bytes data = make_header32(CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7, MH_DYLIB);
  MachO::Ptr macho;
  ASSERT_EQ(load(data, macho), ReturnCode::kOk);

  const MachOSliceList& slices = macho->get_slices();
  ASSERT_EQ(slices.size(), 1u);
  EXPECT_EQ(slices[0].cputype, CPU_TYPE_ARM);
  EXPECT_EQ(slices[0].cpusubtype, CPU_SUBTYPE_ARM_V7);
  EXPECT_EQ(slices[0].filetype, static_cast<uint32_t>(MH_DYLIB));
  EXPECT_EQ(slices[0].offset, 0u);
  EXPECT_EQ(slices[0].size, data.size());
}

// load: universal files

class MachOLoadFatTest : public MachOTest,
                         public ::testing::WithParamInterface<bool> {};

TEST_P(MachOLoadFatTest, LoadsAllSlices) {
  bool is64 = GetParam();
  std::vector<Bytes> slices = {
      make_signed_macho(),
      make_header64(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, MH_DYLIB),
      make_header32(CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7, MH_BUNDLE),
  };
  MachO::Ptr macho;
  ASSERT_EQ(load(make_fat(slices, is64), macho), ReturnCode::kOk);

  const MachOSliceList& loaded = macho->get_slices();
  ASSERT_EQ(loaded.size(), 3u);
  EXPECT_EQ(loaded[0].cputype, CPU_TYPE_ARM64);
  EXPECT_EQ(loaded[0].cpusubtype, CPU_SUBTYPE_ARM64_ALL);
  EXPECT_EQ(loaded[0].filetype, static_cast<uint32_t>(MH_EXECUTE));
  EXPECT_EQ(loaded[1].cputype, CPU_TYPE_X86_64);
  EXPECT_EQ(loaded[1].cpusubtype, CPU_SUBTYPE_X86_64_ALL);
  EXPECT_EQ(loaded[1].filetype, static_cast<uint32_t>(MH_DYLIB));
  EXPECT_EQ(loaded[2].cputype, CPU_TYPE_ARM);
  EXPECT_EQ(loaded[2].cpusubtype, CPU_SUBTYPE_ARM_V7);
  EXPECT_EQ(loaded[2].filetype, static_cast<uint32_t>(MH_BUNDLE));
  for (size_t i = 0; i < slices.size(); i++) {
    EXPECT_EQ(loaded[i].offset, fat_slice_offset(i)) << "slice " << i;
    EXPECT_EQ(loaded[i].size, slices[i].size()) << "slice " << i;
  }
}

TEST_P(MachOLoadFatTest, SkipsInvalidSlices) {
  bool is64 = GetParam();
  Bytes arm64 = make_header64(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
  Bytes data = make_fat({arm64, arm64, arm64, arm64}, is64);
  // fat_arch fields: offset at +8, size at +12 (+16 in fat_arch_64).
  size_t offset_field = 8;
  size_t size_field = is64 ? 16 : 12;
  auto put_field = [&](size_t index, size_t field, uint64_t value) {
    size_t at = fat_entry_offset(index, is64) + field;
    if (is64) {
      put_be64(data, at, value);
    } else {
      put_be32(data, at, static_cast<uint32_t>(value));
    }
  };
  // Slice 0 starts past the end of the file.
  put_field(0, offset_field, data.size() + 1);
  // Slice 1 runs past the end of the file.
  put_field(1, size_field, data.size());
  // Slice 2 isn't a Mach-O.
  put<uint32_t>(data, fat_slice_offset(2), 0xdeadbeef);

  MachO::Ptr macho;
  ASSERT_EQ(load(data, macho), ReturnCode::kOk);
  const MachOSliceList& slices = macho->get_slices();
  ASSERT_EQ(slices.size(), 1u);
  EXPECT_EQ(slices[0].offset, fat_slice_offset(3));
}

TEST_P(MachOLoadFatTest, FailsWhenNoSliceIsValid) {
  bool is64 = GetParam();
  Bytes arm64 = make_header64(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
  Bytes data = make_fat({arm64, arm64}, is64);
  put<uint32_t>(data, fat_slice_offset(0), 0xdeadbeef);
  put<uint32_t>(data, fat_slice_offset(1), MH_CIGAM_64);

  MachO::Ptr macho;
  EXPECT_EQ(load(data, macho), ReturnCode::kErrCommon);
  EXPECT_EQ(macho, nullptr);
}

TEST_P(MachOLoadFatTest, FailsWithoutSlices) {
  MachO::Ptr macho;
  EXPECT_EQ(load(make_fat({}, GetParam()), macho), ReturnCode::kErrCommon);
}

TEST_P(MachOLoadFatTest, FailsWhenArchCountOverrunsFile) {
  bool is64 = GetParam();
  Bytes data =
      make_fat({make_header64(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL)}, is64);
  put_be32(data, 4, 0x10000);

  MachO::Ptr macho;
  EXPECT_EQ(load(data, macho), ReturnCode::kErrCommon);
}

INSTANTIATE_TEST_SUITE_P(FatHeaders, MachOLoadFatTest, ::testing::Bool(),
                         [](const ::testing::TestParamInfo<bool>& info) {
                           return info.param ? "Fat64" : "Fat32";
                         });

// load: load commands of a thin 64-bit Mach-O

TEST_F(MachOLoadCommandsTest, FailsWhenCommandsRunPastFileEnd) {
  Bytes data = make_signed_macho();
  mach_header_64 header = get<mach_header_64>(data, 0);
  header.sizeofcmds = static_cast<uint32_t>(data.size());
  put(data, 0, header);

  MachO::Ptr macho;
  EXPECT_EQ(load(data, macho), ReturnCode::kErrCommon);
}

TEST_F(MachOLoadCommandsTest, FailsWhenCommandCountOverrunsCommands) {
  Bytes data = make_signed_macho();
  mach_header_64 header = get<mach_header_64>(data, 0);
  header.ncmds = 3;
  put(data, 0, header);

  MachO::Ptr macho;
  EXPECT_EQ(load(data, macho), ReturnCode::kErrCommon);
}

TEST_F(MachOLoadCommandsTest, FailsForCommandSmallerThanLoadCommand) {
  for (uint32_t cmdsize : {0u, 4u}) {
    Bytes data = make_signed_macho();
    load_command cmd = get<load_command>(data, kLinkeditCommandOffset);
    cmd.cmdsize = cmdsize;
    put(data, kLinkeditCommandOffset, cmd);

    MachO::Ptr macho;
    EXPECT_EQ(load(data, macho), ReturnCode::kErrCommon)
        << "cmdsize " << cmdsize;
  }
}

TEST_F(MachOLoadCommandsTest, FailsForCommandRunningPastCommands) {
  Bytes data = make_signed_macho();
  load_command cmd = get<load_command>(data, kCodeSignatureCommandOffset);
  cmd.cmdsize = sizeof(linkedit_data_command) + 8;
  put(data, kCodeSignatureCommandOffset, cmd);

  MachO::Ptr macho;
  EXPECT_EQ(load(data, macho), ReturnCode::kErrCommon);
}

TEST_F(MachOLoadCommandsTest, IgnoresUndersizedCodeSignatureCommand) {
  Bytes data = make_signed_macho();
  load_command cmd = get<load_command>(data, kCodeSignatureCommandOffset);
  cmd.cmdsize = sizeof(load_command);
  put(data, kCodeSignatureCommandOffset, cmd);

  MachO::Ptr macho;
  ASSERT_EQ(load(data, macho), ReturnCode::kOk);
  size_t offset, size;
  EXPECT_EQ(macho->get_signature_range(offset, size), ReturnCode::kErrCommon);
}

TEST_F(MachOLoadCommandsTest, IgnoresUndersizedLinkeditCommand) {
  Bytes data = make_signed_macho();
  mach_header_64 header = get<mach_header_64>(data, 0);
  // Shrink __LINKEDIT to a bare load_command; LC_CODE_SIGNATURE follows it.
  linkedit_data_command cs =
      get<linkedit_data_command>(data, kCodeSignatureCommandOffset);
  load_command linkedit = get<load_command>(data, kLinkeditCommandOffset);
  linkedit.cmdsize = sizeof(load_command);
  put(data, kLinkeditCommandOffset, linkedit);
  put(data, kLinkeditCommandOffset + sizeof(load_command), cs);
  header.sizeofcmds = sizeof(load_command) + sizeof(linkedit_data_command);
  put(data, 0, header);

  MachO::Ptr macho;
  ASSERT_EQ(load(data, macho), ReturnCode::kOk);
  size_t offset, size;
  EXPECT_EQ(macho->get_signature_range(offset, size), ReturnCode::kOk);
  // Without __LINKEDIT the signature can't be resized.
  EXPECT_EQ(macho->resize_code_signature(0x100), ReturnCode::kErrCommon);
}

// find_slice

class MachOFindSliceFatTest : public MachOTest {
 protected:
  void SetUp() override {
    MachOTest::SetUp();
    ASSERT_EQ(
        load(make_fat({
                 make_header64(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL),
                 make_header64(CPU_TYPE_ARM64, kArm64eAbiV2),
                 make_header64(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL),
                 make_header64(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_DYLIB),
             }),
             macho_),
        ReturnCode::kOk);
  }

  MachO::Ptr macho_;
};

TEST_F(MachOFindSliceFatTest, FindsMatchingSlice) {
  auto slice = macho_->find_slice(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL);
  ASSERT_TRUE(slice.has_value());
  EXPECT_EQ(slice->cputype, CPU_TYPE_X86_64);
  EXPECT_EQ(slice->offset, fat_slice_offset(2));
}

TEST_F(MachOFindSliceFatTest, ReturnsFirstMatch) {
  auto slice = macho_->find_slice(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
  ASSERT_TRUE(slice.has_value());
  EXPECT_EQ(slice->offset, fat_slice_offset(0));
  EXPECT_EQ(slice->filetype, static_cast<uint32_t>(MH_EXECUTE));
}

TEST_F(MachOFindSliceFatTest, IgnoresSliceCapabilityBits) {
  auto slice = macho_->find_slice(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E);
  ASSERT_TRUE(slice.has_value());
  EXPECT_EQ(slice->offset, fat_slice_offset(1));
  // The returned slice keeps its capability bits.
  EXPECT_EQ(slice->cpusubtype, kArm64eAbiV2);
}

TEST_F(MachOFindSliceFatTest, IgnoresQueryCapabilityBits) {
  auto slice = macho_->find_slice(
      CPU_TYPE_X86_64,
      static_cast<cpu_subtype_t>(CPU_SUBTYPE_X86_64_ALL | CPU_SUBTYPE_LIB64));
  ASSERT_TRUE(slice.has_value());
  EXPECT_EQ(slice->offset, fat_slice_offset(2));
}

TEST_F(MachOFindSliceFatTest, ReturnsNulloptForMissingSubtype) {
  EXPECT_FALSE(
      macho_->find_slice(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_V8).has_value());
  EXPECT_FALSE(
      macho_->find_slice(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_H).has_value());
}

TEST_F(MachOFindSliceFatTest, ReturnsNulloptForMissingCpuType) {
  EXPECT_FALSE(
      macho_->find_slice(CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7).has_value());
  EXPECT_FALSE(
      macho_->find_slice(CPU_TYPE_I386, CPU_SUBTYPE_I386_ALL).has_value());
}

TEST_F(MachOFindSliceTest, FindsSliceOfThinFile) {
  MachO::Ptr macho;
  ASSERT_EQ(load(make_signed_macho(), macho), ReturnCode::kOk);

  auto slice = macho->find_slice(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
  ASSERT_TRUE(slice.has_value());
  EXPECT_EQ(slice->offset, 0u);
  EXPECT_FALSE(
      macho->find_slice(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL).has_value());
}

// find_preferred_slice (results depend on the host CPU)

TEST_F(MachOFindPreferredSliceTest, PicksSliceForHostCpuType) {
  cpu_type_t host_cputype;
  cpu_subtype_t host_cpusubtype;
  ASSERT_TRUE(host_cpu_type(host_cputype, host_cpusubtype));
  if (host_cputype != CPU_TYPE_ARM64 && host_cputype != CPU_TYPE_X86_64) {
    GTEST_SKIP() << "unsupported host cputype " << host_cputype;
  }

  MachO::Ptr macho;
  ASSERT_EQ(
      load(make_fat({make_header64(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL),
                     make_header64(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL)}),
           macho),
      ReturnCode::kOk);

  auto slice = macho->find_preferred_slice();
  ASSERT_TRUE(slice.has_value());
  EXPECT_EQ(slice->cputype, host_cputype);
}

TEST_F(MachOFindPreferredSliceTest, ReturnsNulloptWhenNoSliceRunsOnHost) {
  MachO::Ptr macho;
  ASSERT_EQ(load(make_fat({make_header32(CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7),
                           make_header32(CPU_TYPE_I386, CPU_SUBTYPE_I386_ALL)}),
                 macho),
            ReturnCode::kOk);

  EXPECT_FALSE(macho->find_preferred_slice().has_value());
}

TEST_F(MachOFindPreferredSliceTest, Arm64eHostPicksArm64eSliceWithHostAbi) {
  if (!host_is_arm64e()) {
    GTEST_SKIP() << "host isn't arm64e";
  }

  MachO::Ptr macho;
  ASSERT_EQ(load(make_fat({
                     make_header64(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL),
                     make_header64(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E),
                     make_header64(CPU_TYPE_ARM64, kArm64eAbiV2),
                 }),
                 macho),
            ReturnCode::kOk);

  auto slice = macho->find_preferred_slice();
  ASSERT_TRUE(slice.has_value());
  EXPECT_EQ(slice->offset, fat_slice_offset(host_uses_arm64e_abi_v2() ? 2 : 1));
}

TEST_F(MachOFindPreferredSliceTest, Arm64eHostFallsBackToArm64) {
  if (!host_is_arm64e()) {
    GTEST_SKIP() << "host isn't arm64e";
  }
  // An arm64e slice built for the other ABI doesn't load on this host.
  cpu_subtype_t other_abi =
      host_uses_arm64e_abi_v2() ? CPU_SUBTYPE_ARM64E : kArm64eAbiV2;

  MachO::Ptr macho;
  ASSERT_EQ(
      load(make_fat({make_header64(CPU_TYPE_ARM64, other_abi),
                     make_header64(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL)}),
           macho),
      ReturnCode::kOk);

  auto slice = macho->find_preferred_slice();
  ASSERT_TRUE(slice.has_value());
  EXPECT_EQ(slice->offset, fat_slice_offset(1));
  EXPECT_EQ(slice->cpusubtype, CPU_SUBTYPE_ARM64_ALL);
}

// get_signature_range

TEST_F(MachOGetSignatureRangeTest, ReturnsCodeSignatureRange) {
  MachO::Ptr macho;
  ASSERT_EQ(load(make_signed_macho(0x300), macho), ReturnCode::kOk);

  size_t offset = 0, size = 0;
  ASSERT_EQ(macho->get_signature_range(offset, size), ReturnCode::kOk);
  EXPECT_EQ(offset, kSignatureOffset);
  EXPECT_EQ(size, 0x300u);
}

TEST_F(MachOGetSignatureRangeTest, FailsWithoutCodeSignature) {
  MachO::Ptr macho;
  ASSERT_EQ(load(make_header64(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL), macho),
            ReturnCode::kOk);

  size_t offset, size;
  EXPECT_EQ(macho->get_signature_range(offset, size), ReturnCode::kErrCommon);
}

TEST_F(MachOGetSignatureRangeTest, FailsWhenRangeRunsPastFileEnd) {
  Bytes data = make_signed_macho();
  linkedit_data_command cs =
      get<linkedit_data_command>(data, kCodeSignatureCommandOffset);
  cs.datasize += 1;
  put(data, kCodeSignatureCommandOffset, cs);

  MachO::Ptr macho;
  ASSERT_EQ(load(data, macho), ReturnCode::kOk);
  size_t offset, size;
  EXPECT_EQ(macho->get_signature_range(offset, size), ReturnCode::kErrCommon);
}

TEST_F(MachOGetSignatureRangeTest, FailsWhenRangeStartsPastFileEnd) {
  Bytes data = make_signed_macho();
  linkedit_data_command cs =
      get<linkedit_data_command>(data, kCodeSignatureCommandOffset);
  cs.dataoff = static_cast<uint32_t>(data.size() + 1);
  cs.datasize = 0;
  put(data, kCodeSignatureCommandOffset, cs);

  MachO::Ptr macho;
  ASSERT_EQ(load(data, macho), ReturnCode::kOk);
  size_t offset, size;
  EXPECT_EQ(macho->get_signature_range(offset, size), ReturnCode::kErrCommon);
}

// Signature editing needs a thin 64-bit Mach-O; other files only load for
// slice inspection.
TEST_F(MachOGetSignatureRangeTest, SignatureEditingFailsForFatFile) {
  Bytes data = make_fat({make_signed_macho()});
  MachO::Ptr macho;
  ASSERT_EQ(load(data, macho), ReturnCode::kOk);

  size_t offset, size;
  EXPECT_EQ(macho->get_signature_range(offset, size), ReturnCode::kErrCommon);
  EXPECT_EQ(macho->resize_code_signature(0x100), ReturnCode::kErrCommon);
  EXPECT_EQ(macho->update_code_signature(Bytes(8, kBlobFill)),
            ReturnCode::kErrCommon);
  EXPECT_TRUE(saved(macho) == data);
}

TEST_F(MachOGetSignatureRangeTest, SignatureEditingFailsForThin32) {
  MachO::Ptr macho;
  ASSERT_EQ(load(make_header32(CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7), macho),
            ReturnCode::kOk);

  size_t offset, size;
  EXPECT_EQ(macho->get_signature_range(offset, size), ReturnCode::kErrCommon);
  EXPECT_EQ(macho->resize_code_signature(0x100), ReturnCode::kErrCommon);
  EXPECT_EQ(macho->update_code_signature(Bytes(8, kBlobFill)),
            ReturnCode::kErrCommon);
}

// resize_code_signature

// By default make_signed_macho() leaves the SuperBlob 0x80 bytes shorter than
// LC_CODE_SIGNATURE's range, and resizing keeps that padding.
constexpr size_t kDefaultPadding = 0x200 - 0x180;

TEST_F(MachOResizeCodeSignatureTest, GrowsSignature) {
  Bytes original = make_signed_macho();
  MachO::Ptr macho;
  ASSERT_EQ(load(original, macho), ReturnCode::kOk);

  constexpr size_t kNewSize = 0x1000;
  ASSERT_EQ(macho->resize_code_signature(kNewSize), ReturnCode::kOk);

  constexpr size_t kDataSize = kNewSize + kDefaultPadding;
  constexpr size_t kFileSize = kSignatureOffset + kDataSize;
  size_t offset = 0, size = 0;
  ASSERT_EQ(macho->get_signature_range(offset, size), ReturnCode::kOk);
  EXPECT_EQ(offset, kSignatureOffset);
  EXPECT_EQ(size, kDataSize);
  EXPECT_EQ(macho->get_slices().front().size, kFileSize);

  Bytes out = saved(macho);
  ASSERT_EQ(out.size(), kFileSize);
  linkedit_data_command cs =
      get<linkedit_data_command>(out, kCodeSignatureCommandOffset);
  EXPECT_EQ(cs.dataoff, kSignatureOffset);
  EXPECT_EQ(cs.datasize, kDataSize);
  segment_command_64 linkedit =
      get<segment_command_64>(out, kLinkeditCommandOffset);
  EXPECT_EQ(linkedit.vmaddr, kLinkeditVmAddr);
  EXPECT_EQ(linkedit.fileoff, kLinkeditOffset);
  EXPECT_EQ(linkedit.filesize, kFileSize - kLinkeditOffset);
  EXPECT_EQ(linkedit.vmsize, kPageSize);

  // Only the two load commands and the signature change; the new signature
  // range is zeroed for update_code_signature to fill.
  EXPECT_TRUE(range_equals(
      out, 0,
      Bytes(original.begin(), original.begin() + kLinkeditCommandOffset)));
  EXPECT_TRUE(range_equals(out, kCommandsEnd,
                           Bytes(original.begin() + kCommandsEnd,
                                 original.begin() + kSignatureOffset)));
  EXPECT_TRUE(range_filled_with(out, kSignatureOffset, out.size(), 0));
}

TEST_F(MachOResizeCodeSignatureTest, ShrinksSignature) {
  MachO::Ptr macho;
  ASSERT_EQ(load(make_signed_macho(), macho), ReturnCode::kOk);

  constexpr size_t kNewSize = 0x40;
  ASSERT_EQ(macho->resize_code_signature(kNewSize), ReturnCode::kOk);

  constexpr size_t kDataSize = kNewSize + kDefaultPadding;
  constexpr size_t kFileSize = kSignatureOffset + kDataSize;
  Bytes out = saved(macho);
  ASSERT_EQ(out.size(), kFileSize);
  EXPECT_EQ(macho->get_slices().front().size, kFileSize);
  EXPECT_EQ(
      get<linkedit_data_command>(out, kCodeSignatureCommandOffset).datasize,
      kDataSize);
  segment_command_64 linkedit =
      get<segment_command_64>(out, kLinkeditCommandOffset);
  EXPECT_EQ(linkedit.filesize, kFileSize - kLinkeditOffset);
  EXPECT_EQ(linkedit.vmsize, kPageSize);
  EXPECT_TRUE(
      range_filled_with(out, kLinkeditOffset, kSignatureOffset, kLinkeditFill));
  EXPECT_TRUE(range_filled_with(out, kSignatureOffset, out.size(), 0));
}

TEST_F(MachOResizeCodeSignatureTest, CountsBytesPastRangeAsPadding) {
  // Like test/macho_sample, the file runs past LC_CODE_SIGNATURE's range.
  MachO::Ptr macho;
  ASSERT_EQ(load(make_signed_macho(0x200, 0x180, 0x40), macho),
            ReturnCode::kOk);

  ASSERT_EQ(macho->resize_code_signature(0x100), ReturnCode::kOk);

  size_t offset, size;
  ASSERT_EQ(macho->get_signature_range(offset, size), ReturnCode::kOk);
  EXPECT_EQ(size, 0x100u + 0x80 + 0x40);
  EXPECT_EQ(macho->get_slices().front().size, kSignatureOffset + size);
}

TEST_F(MachOResizeCodeSignatureTest, RoundsLinkeditVmSizeUpToPage) {
  // __LINKEDIT holds 0x100 bytes ahead of the signature plus the padding.
  constexpr size_t kExactPage =
      kPageSize - (kSignatureOffset - kLinkeditOffset) - kDefaultPadding;
  struct {
    size_t new_size;
    uint64_t vmsize;
  } cases[] = {
      {kExactPage - 1, kPageSize},
      {kExactPage, kPageSize},
      {kExactPage + 1, 2 * kPageSize},
  };
  for (const auto& c : cases) {
    MachO::Ptr macho;
    ASSERT_EQ(load(make_signed_macho(), macho), ReturnCode::kOk);
    ASSERT_EQ(macho->resize_code_signature(c.new_size), ReturnCode::kOk);
    segment_command_64 linkedit =
        get<segment_command_64>(saved(macho), kLinkeditCommandOffset);
    EXPECT_EQ(linkedit.vmsize, c.vmsize)
        << "new_size 0x" << std::hex << c.new_size;
  }
}

TEST_F(MachOResizeCodeSignatureTest, FailsWithoutCodeSignature) {
  MachO::Ptr macho;
  ASSERT_EQ(load(make_header64(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL), macho),
            ReturnCode::kOk);
  EXPECT_EQ(macho->resize_code_signature(0x100), ReturnCode::kErrCommon);
}

TEST_F(MachOResizeCodeSignatureTest, FailsWithoutLinkedit) {
  Bytes data = make_signed_macho();
  segment_command_64 segment =
      get<segment_command_64>(data, kLinkeditCommandOffset);
  memset(segment.segname, 0, sizeof(segment.segname));
  memcpy(segment.segname, SEG_DATA, sizeof(SEG_DATA));
  put(data, kLinkeditCommandOffset, segment);

  MachO::Ptr macho;
  ASSERT_EQ(load(data, macho), ReturnCode::kOk);
  EXPECT_EQ(macho->resize_code_signature(0x100), ReturnCode::kErrCommon);
  EXPECT_TRUE(saved(macho) == data);
}

TEST_F(MachOResizeCodeSignatureTest, FailsWhenRangeTooSmallForBlobHeader) {
  Bytes data = make_signed_macho();
  linkedit_data_command cs =
      get<linkedit_data_command>(data, kCodeSignatureCommandOffset);
  cs.datasize = 4;
  put(data, kCodeSignatureCommandOffset, cs);

  MachO::Ptr macho;
  ASSERT_EQ(load(data, macho), ReturnCode::kOk);
  EXPECT_EQ(macho->resize_code_signature(0x100), ReturnCode::kErrCommon);
  EXPECT_TRUE(saved(macho) == data);
}

TEST_F(MachOResizeCodeSignatureTest, FailsWhenLinkeditEndsBeforeFileEnd) {
  Bytes data = make_signed_macho();
  segment_command_64 linkedit =
      get<segment_command_64>(data, kLinkeditCommandOffset);
  linkedit.filesize -= 0x10;
  put(data, kLinkeditCommandOffset, linkedit);

  MachO::Ptr macho;
  ASSERT_EQ(load(data, macho), ReturnCode::kOk);
  EXPECT_EQ(macho->resize_code_signature(0x100), ReturnCode::kErrCommon);
  EXPECT_TRUE(saved(macho) == data);
}

TEST_F(MachOResizeCodeSignatureTest, FailsWhenLinkeditStartsAfterSignature) {
  Bytes data = make_signed_macho();
  segment_command_64 linkedit =
      get<segment_command_64>(data, kLinkeditCommandOffset);
  linkedit.fileoff = kSignatureOffset + 0x10;
  linkedit.filesize = data.size() - linkedit.fileoff;
  put(data, kLinkeditCommandOffset, linkedit);

  MachO::Ptr macho;
  ASSERT_EQ(load(data, macho), ReturnCode::kOk);
  EXPECT_EQ(macho->resize_code_signature(0x100), ReturnCode::kErrCommon);
  EXPECT_TRUE(saved(macho) == data);
}

TEST_F(MachOResizeCodeSignatureTest, FailsWhenBlobLengthRunsPastFileEnd) {
  MachO::Ptr macho;
  Bytes data = make_signed_macho(0x200, 0x201);
  ASSERT_EQ(load(data, macho), ReturnCode::kOk);
  EXPECT_EQ(macho->resize_code_signature(0x100), ReturnCode::kErrCommon);
  EXPECT_TRUE(saved(macho) == data);
}

TEST_F(MachOResizeCodeSignatureTest, FailsWhenSizeExceedsUint32) {
  Bytes data = make_signed_macho();
  MachO::Ptr macho;
  ASSERT_EQ(load(data, macho), ReturnCode::kOk);

  EXPECT_EQ(macho->resize_code_signature(static_cast<size_t>(UINT32_MAX) + 1),
            ReturnCode::kErrCommon);
  // Fits in 32 bits, but not once the padding is added.
  EXPECT_EQ(macho->resize_code_signature(UINT32_MAX - kDefaultPadding + 1),
            ReturnCode::kErrCommon);
  EXPECT_TRUE(saved(macho) == data);
}

// update_code_signature

TEST_F(MachOUpdateCodeSignatureTest, WritesBlobAndZeroesRestOfRange) {
  Bytes original = make_signed_macho(0x200, 0x180, 0x20);
  MachO::Ptr macho;
  ASSERT_EQ(load(original, macho), ReturnCode::kOk);

  Bytes blob(0x40, kBlobFill);
  ASSERT_EQ(macho->update_code_signature(blob), ReturnCode::kOk);

  Bytes out = saved(macho);
  ASSERT_EQ(out.size(), original.size());
  EXPECT_TRUE(range_equals(
      out, 0, Bytes(original.begin(), original.begin() + kSignatureOffset)));
  EXPECT_TRUE(range_equals(out, kSignatureOffset, blob));
  EXPECT_TRUE(range_filled_with(out, kSignatureOffset + blob.size(),
                                kSignatureOffset + 0x200, 0));
  // Bytes past LC_CODE_SIGNATURE's range aren't touched.
  EXPECT_TRUE(range_filled_with(out, kSignatureOffset + 0x200, out.size(),
                                kTrailingFill));
}

TEST_F(MachOUpdateCodeSignatureTest, AcceptsBlobFillingWholeRange) {
  MachO::Ptr macho;
  ASSERT_EQ(load(make_signed_macho(), macho), ReturnCode::kOk);

  Bytes blob(0x200, kBlobFill);
  ASSERT_EQ(macho->update_code_signature(blob), ReturnCode::kOk);
  Bytes out = saved(macho);
  EXPECT_EQ(out.size(), kSignatureOffset + blob.size());
  EXPECT_TRUE(range_equals(out, kSignatureOffset, blob));
}

TEST_F(MachOUpdateCodeSignatureTest, EmptyBlobZeroesRange) {
  MachO::Ptr macho;
  ASSERT_EQ(load(make_signed_macho(), macho), ReturnCode::kOk);

  ASSERT_EQ(macho->update_code_signature({}), ReturnCode::kOk);
  Bytes out = saved(macho);
  EXPECT_TRUE(range_filled_with(out, kSignatureOffset, out.size(), 0));
}

TEST_F(MachOUpdateCodeSignatureTest, RejectsBlobLargerThanRange) {
  Bytes data = make_signed_macho(0x200, 0x180, 0x20);
  MachO::Ptr macho;
  ASSERT_EQ(load(data, macho), ReturnCode::kOk);

  EXPECT_EQ(macho->update_code_signature(Bytes(0x201, kBlobFill)),
            ReturnCode::kErrCommon);
  EXPECT_TRUE(saved(macho) == data);
}

TEST_F(MachOUpdateCodeSignatureTest, FailsWithoutCodeSignature) {
  MachO::Ptr macho;
  ASSERT_EQ(load(make_header64(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL), macho),
            ReturnCode::kOk);
  EXPECT_EQ(macho->update_code_signature(Bytes(8, kBlobFill)),
            ReturnCode::kErrCommon);
}

TEST_F(MachOUpdateCodeSignatureTest, FillsResizedRange) {
  MachO::Ptr macho;
  ASSERT_EQ(load(make_signed_macho(), macho), ReturnCode::kOk);

  Bytes blob(0x1000, kBlobFill);
  ASSERT_EQ(macho->resize_code_signature(blob.size()), ReturnCode::kOk);
  ASSERT_EQ(macho->update_code_signature(blob), ReturnCode::kOk);

  Bytes out = saved(macho);
  ASSERT_EQ(out.size(), kSignatureOffset + blob.size() + kDefaultPadding);
  EXPECT_TRUE(range_equals(out, kSignatureOffset, blob));
  EXPECT_TRUE(
      range_filled_with(out, kSignatureOffset + blob.size(), out.size(), 0));
}

// save

TEST_F(MachOSaveTest, FailsForNullMachO) {
  std::string filepath = path("output");
  EXPECT_EQ(MachO::save(filepath, nullptr), ReturnCode::kErrCommon);
  EXPECT_FALSE(std::filesystem::exists(filepath));
}

TEST_F(MachOSaveTest, FailsForUnwritablePath) {
  MachO::Ptr macho;
  ASSERT_EQ(load(make_signed_macho(), macho), ReturnCode::kOk);
  EXPECT_EQ(MachO::save(path("missing/output"), macho), ReturnCode::kErrCommon);
}

TEST_F(MachOSaveTest, RoundTripsUnchanged) {
  for (const Bytes& data :
       {make_signed_macho(0x200, 0x180, 0x20),
        make_fat({make_signed_macho(),
                  make_header64(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL)}),
        make_header32(CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7)}) {
    MachO::Ptr macho;
    ASSERT_EQ(load(data, macho), ReturnCode::kOk);
    EXPECT_TRUE(saved(macho) == data);
  }
}

TEST_F(MachOSaveTest, TruncatesExistingFile) {
  Bytes data = make_signed_macho();
  MachO::Ptr macho;
  ASSERT_EQ(load(data, macho), ReturnCode::kOk);

  std::string filepath = write_file(Bytes(data.size() * 2, 0xff), "output");
  ASSERT_EQ(MachO::save(filepath, macho), ReturnCode::kOk);
  EXPECT_TRUE(read_file(filepath) == data);
}

// test/macho_sample: a signed thin arm64 executable

TEST_F(MachOSampleTest, LoadsThinArm64Executable) {
  Bytes data = read_file(MACHO_SAMPLE_PATH);
  MachO::Ptr macho;
  ASSERT_EQ(MachO::load(MACHO_SAMPLE_PATH, macho), ReturnCode::kOk);

  const MachOSliceList& slices = macho->get_slices();
  ASSERT_EQ(slices.size(), 1u);
  EXPECT_EQ(slices[0].cputype, CPU_TYPE_ARM64);
  EXPECT_EQ(slices[0].cpusubtype, CPU_SUBTYPE_ARM64_ALL);
  EXPECT_EQ(slices[0].filetype, static_cast<uint32_t>(MH_EXECUTE));
  EXPECT_EQ(slices[0].offset, 0u);
  EXPECT_EQ(slices[0].size, data.size());
  EXPECT_TRUE(
      macho->find_slice(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL).has_value());
}

TEST_F(MachOSampleTest, ReportsEmbeddedSignature) {
  Bytes data = read_file(MACHO_SAMPLE_PATH);
  MachO::Ptr macho;
  ASSERT_EQ(MachO::load(MACHO_SAMPLE_PATH, macho), ReturnCode::kOk);

  size_t offset = 0, size = 0;
  ASSERT_EQ(macho->get_signature_range(offset, size), ReturnCode::kOk);
  EXPECT_EQ(offset, kSampleSignatureOffset);
  EXPECT_EQ(size, kSampleSignatureSize);
  EXPECT_EQ(get_be32(data, offset), kEmbeddedSignatureMagic);
  EXPECT_LE(get_be32(data, offset + 4), size);
}

TEST_F(MachOSampleTest, SaveRoundTripsUnchanged) {
  MachO::Ptr macho;
  ASSERT_EQ(MachO::load(MACHO_SAMPLE_PATH, macho), ReturnCode::kOk);
  EXPECT_TRUE(saved(macho) == read_file(MACHO_SAMPLE_PATH));
}

TEST_F(MachOSampleTest, ReplacesSignature) {
  Bytes original = read_file(MACHO_SAMPLE_PATH);
  ASSERT_GE(original.size(), kSampleSignatureOffset + 8);
  uint32_t blob_length = get_be32(original, kSampleSignatureOffset + 4);
  size_t padding = original.size() - kSampleSignatureOffset - blob_length;

  MachO::Ptr macho;
  ASSERT_EQ(MachO::load(MACHO_SAMPLE_PATH, macho), ReturnCode::kOk);
  Bytes blob(blob_length + 0x1000, kBlobFill);
  put_be32(blob, 0, kEmbeddedSignatureMagic);
  put_be32(blob, 4, static_cast<uint32_t>(blob.size()));
  ASSERT_EQ(macho->resize_code_signature(blob.size()), ReturnCode::kOk);
  ASSERT_EQ(macho->update_code_signature(blob), ReturnCode::kOk);

  // The saved file loads again with the new signature in place.
  std::string resigned = path("resigned");
  ASSERT_EQ(MachO::save(resigned, macho), ReturnCode::kOk);
  MachO::Ptr reloaded;
  ASSERT_EQ(MachO::load(resigned, reloaded), ReturnCode::kOk);
  size_t offset = 0, size = 0;
  ASSERT_EQ(reloaded->get_signature_range(offset, size), ReturnCode::kOk);
  EXPECT_EQ(offset, kSampleSignatureOffset);
  EXPECT_EQ(size, blob.size() + padding);

  Bytes out = read_file(resigned);
  ASSERT_EQ(out.size(), kSampleSignatureOffset + blob.size() + padding);
  EXPECT_EQ(reloaded->get_slices().front().size, out.size());
  EXPECT_TRUE(range_equals(
      out, 0,
      Bytes(original.begin(), original.begin() + kLinkeditCommandOffset)));
  EXPECT_TRUE(range_equals(out, kSampleSignatureOffset, blob));
  EXPECT_TRUE(range_filled_with(out, kSampleSignatureOffset + blob.size(),
                                out.size(), 0));
}

}  // namespace
}  // namespace macho
}  // namespace ct_bypass
