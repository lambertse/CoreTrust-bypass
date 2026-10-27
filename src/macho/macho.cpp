#include "macho.h"
#include "cs_blob.h"
#include "utils.h"

#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <memory>
#include <utility>

#include <mach-o/fat.h>
#include <mach-o/loader.h>

namespace ct_bypass::macho {

namespace {
namespace internal {
bool read_file(const std::string& filepath, Bytes& out_data);
bool write_file(const std::string& filepath, const Bytes& data);
bool read_slice(const Bytes& data, uint64_t offset, uint64_t size,
                MachOSlice& out_slice);
bool host_get_cpu_type(cpu_type_t& out_cputype, cpu_subtype_t& out_cpusubtype);
bool host_supports_arm64e_abi_v2();
uint32_t subtype_base(cpu_subtype_t cpusubtype);
}  // namespace internal

template <typename T>
T read_struct(const Bytes& data, size_t off_set) {
  T out_value{};
  if (off_set > data.size() || sizeof(T) > data.size() - off_set) {
    return out_value;
  }
  memcpy(&out_value, data.data() + off_set, sizeof(T));
  return out_value;
}

template <typename T>
bool write_struct(Bytes& data, size_t off_set, const T& value) {
  if (off_set > data.size() || sizeof(T) > data.size() - off_set) {
    return false;
  }
  memcpy(data.data() + off_set, &value, sizeof(T));
  return true;
}
}  // namespace

MachO::MachO(Bytes&& data) : data_(std::move(data)) {}

ReturnCode MachO::load_slices() {
  slices_.clear();

  if (data_.size() < sizeof(fat_header)) {
    return ReturnCode::kErrCommon;
  }

  uint32_t magic = read_be32(data_.data());
  if (magic != FAT_MAGIC && magic != FAT_MAGIC_64) {
    MachOSlice slice;
    if (!internal::read_slice(data_, 0, data_.size(), slice)) {
      return ReturnCode::kErrCommon;
    }
    slices_.push_back(slice);
    return ReturnCode::kOk;
  }

  bool is64 = magic == FAT_MAGIC_64;
  size_t entrySize = is64 ? sizeof(fat_arch_64) : sizeof(fat_arch);
  uint32_t count = read_be32(data_.data() + 4);
  if (count > (data_.size() - sizeof(fat_header)) / entrySize) {
    return ReturnCode::kErrCommon;
  }

  for (uint32_t i = 0; i < count; i++) {
    // fat_arch: cputype, cpusubtype, offset, size, align (offset/size are 64
    // bits wide in fat_arch_64)
    const uint8_t* entry = data_.data() + sizeof(fat_header) + i * entrySize;
    uint64_t offset = is64 ? read_be64(entry + 8) : read_be32(entry + 8);
    uint64_t size = is64 ? read_be64(entry + 16) : read_be32(entry + 12);
    MachOSlice slice;
    if (internal::read_slice(data_, offset, size, slice)) {
      slices_.push_back(slice);
    }
  }

  if (slices_.empty()) {
    return ReturnCode::kErrCommon;
  }
  return ReturnCode::kOk;
}

ReturnCode MachO::load_load_commands() {
  linkedit_command_.reset();
  code_signature_command_.reset();

  // Only a thin 64-bit Mach-O supports signature editing (see macho.h); other
  // files still load for slice inspection.
  if (slices_.size() != 1 || slices_[0].offset != 0 ||
      slices_[0].size != data_.size() ||
      read_struct<uint32_t>(data_, 0) != MH_MAGIC_64) {
    return ReturnCode::kOk;
  }

  // read_slice already checked the file holds a whole mach_header_64.
  mach_header_64 header = read_struct<mach_header_64>(data_, 0);
  size_t commandsEnd = sizeof(mach_header_64) + header.sizeofcmds;
  if (commandsEnd > data_.size()) {
    return ReturnCode::kErrCommon;
  }
  filetype_ = header.filetype;

  size_t cmdOffset = sizeof(mach_header_64);
  for (uint32_t i = 0; i < header.ncmds; i++) {
    if (sizeof(load_command) > commandsEnd - cmdOffset) {
      return ReturnCode::kErrCommon;
    }
    load_command cmd = read_struct<load_command>(data_, cmdOffset);
    if (cmd.cmdsize < sizeof(load_command) ||
        cmd.cmdsize > commandsEnd - cmdOffset) {
      return ReturnCode::kErrCommon;
    }
    // Commands too small for their struct are skipped so a later write_struct
    // can't spill into the next command.
    if (cmd.cmd == LC_CODE_SIGNATURE &&
        cmd.cmdsize >= sizeof(linkedit_data_command)) {
      code_signature_command_ = cmdOffset;
    } else if (cmd.cmd == LC_SEGMENT_64 &&
               cmd.cmdsize >= sizeof(segment_command_64)) {
      segment_command_64 segment =
          read_struct<segment_command_64>(data_, cmdOffset);
      if (strncmp(segment.segname, SEG_LINKEDIT, sizeof(segment.segname)) ==
          0) {
        linkedit_command_ = cmdOffset;
      }
    } else if (cmd.cmd == LC_ENCRYPTION_INFO ||
               cmd.cmd == LC_ENCRYPTION_INFO_64) {
      if (cmd.cmdsize < sizeof(encryption_info_command)) {
        return ReturnCode::kErrCommon;
      }
      encryption_info_command enc =
          read_struct<encryption_info_command>(data_, cmdOffset);
      encrypted_ = enc.cryptid != 0;
    }
    cmdOffset += cmd.cmdsize;
  }

  return ReturnCode::kOk;
}

ReturnCode MachO::load(const std::string& filepath, MachO::Ptr& out_macho) {
  Bytes data;
  if (!internal::read_file(filepath, data)) {
    return ReturnCode::kErrCommon;
  }
  MachO::Ptr macho(new MachO(std::move(data)));
  ReturnCode ret = ReturnCode::kOk;
  if (failed(ret = macho->load_slices()) ||
      failed(ret = macho->load_load_commands())) {
    return ret;
  }
  out_macho = std::move(macho);
  return ReturnCode::kOk;
}

ReturnCode MachO::save(const std::string& filepath, const MachO::Ptr& macho) {
  if (!macho) {
    return ReturnCode::kErrCommon;
  }
  if (!internal::write_file(filepath, macho->data_)) {
    return ReturnCode::kErrCommon;
  }
  return ReturnCode::kOk;
}

const MachOSliceList& MachO::get_slices() const { return slices_; }

std::optional<MachOSlice> MachO::find_slice(cpu_type_t cputype,
                                            cpu_subtype_t cpusubtype) const {
  // The high byte of cpusubtype holds capability flags (e.g. the arm64e ABI
  // bits), so only the base subtype is compared.
  for (const auto& slice : slices_) {
    if (slice.cputype == cputype && internal::subtype_base(slice.cpusubtype) ==
                                        internal::subtype_base(cpusubtype)) {
      return slice;
    }
  }
  return std::nullopt;
}

std::optional<MachOSlice> MachO::find_preferred_slice() const {
  cpu_type_t host_cputype;
  cpu_subtype_t host_cpusubtype;
  if (!internal::host_get_cpu_type(host_cputype, host_cpusubtype)) {
    return std::nullopt;
  }

  if (host_cputype == CPU_TYPE_ARM64 &&
      internal::subtype_base(host_cpusubtype) ==
          internal::subtype_base(CPU_SUBTYPE_ARM64E)) {
    // An arm64e slice only loads when its ABI matches the host's (Darwin 20 /
    // iOS 14 moved to the new one). Otherwise plain arm64 still runs.
    bool host_abi_v2 = internal::host_supports_arm64e_abi_v2();
    for (const auto& slice : slices_) {
      bool slice_abi_v2 = (static_cast<uint32_t>(slice.cpusubtype) &
                           CPU_SUBTYPE_ARM64E_ABI_V2) != 0;
      if (slice.cputype == CPU_TYPE_ARM64 &&
          internal::subtype_base(slice.cpusubtype) ==
              internal::subtype_base(CPU_SUBTYPE_ARM64E) &&
          slice_abi_v2 == host_abi_v2) {
        return slice;
      }
    }
    return find_slice(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
  }

  if (auto slice = find_slice(host_cputype, host_cpusubtype)) {
    return slice;
  }
  // Hosts can report a specific subtype (arm64 v8, x86_64h) while binaries
  // are built for the generic one.
  switch (host_cputype) {
    case CPU_TYPE_ARM64:
      return find_slice(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
    case CPU_TYPE_X86_64:
      return find_slice(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL);
    default:
      return std::nullopt;
  }
}

ReturnCode MachO::get_signature_range(size_t& out_offset,
                                      size_t& out_size) const {
  if (!code_signature_command_) {
    return ReturnCode::kErrCommon;
  }
  linkedit_data_command cs =
      read_struct<linkedit_data_command>(data_, *code_signature_command_);
  if (cs.dataoff > data_.size() || cs.datasize > data_.size() - cs.dataoff) {
    return ReturnCode::kErrCommon;
  }
  out_offset = cs.dataoff;
  out_size = cs.datasize;
  return ReturnCode::kOk;
}

ReturnCode MachO::resize_code_signature(size_t new_size) {
  size_t dataoff, datasize;
  ReturnCode ret = ReturnCode::kOk;
  if (failed(ret = get_signature_range(dataoff, datasize))) {
    return ret;
  }
  if (!linkedit_command_ || datasize < kBlobHeaderSize) {
    return ReturnCode::kErrCommon;
  }
  linkedit_data_command cs =
      read_struct<linkedit_data_command>(data_, *code_signature_command_);
  segment_command_64 linkedit =
      read_struct<segment_command_64>(data_, *linkedit_command_);

  // The signature must be the last thing in __LINKEDIT and in the file
  if (linkedit.fileoff > dataoff ||
      linkedit.filesize != data_.size() - linkedit.fileoff) {
    return ReturnCode::kErrCommon;
  }

  uint32_t oldLength = read_be32(data_.data() + dataoff + 4);
  if (oldLength > data_.size() - dataoff) {
    return ReturnCode::kErrCommon;
  }
  uint64_t padding = data_.size() - dataoff - oldLength;
  // LC_CODE_SIGNATURE has to cover the padding too, or the file runs past the
  // end of the signature.
  uint64_t newDataSize = (uint64_t)new_size + padding;
  if (new_size > UINT32_MAX || newDataSize > UINT32_MAX) {
    return ReturnCode::kErrCommon;
  }
  uint64_t newFileSize = dataoff + newDataSize;

  cs.datasize = static_cast<uint32_t>(newDataSize);
  linkedit.filesize = newFileSize - linkedit.fileoff;
  linkedit.vmsize = (linkedit.filesize + 0x3fff) & ~(uint64_t)0x3fff;
  write_struct(data_, *code_signature_command_, cs);
  write_struct(data_, *linkedit_command_, linkedit);

  data_.resize(newFileSize);
  memset(data_.data() + dataoff, 0, newFileSize - dataoff);
  slices_[0].size = data_.size();
  return ReturnCode::kOk;
}

ReturnCode MachO::update_code_signature(const Bytes& superblob) {
  size_t dataoff, datasize;
  ReturnCode ret = get_signature_range(dataoff, datasize);
  if (failed(ret) || superblob.size() > datasize) {
    return ReturnCode::kErrCommon;
  }
  // Zero the rest of the old signature so none of it trails the new one
  auto signature = data_.begin() + dataoff;
  auto tail = std::copy(superblob.begin(), superblob.end(), signature);
  std::fill(tail, signature + datasize, 0);
  return ReturnCode::kOk;
}

ReturnCode MachO::write_code_signature(const Bytes& superblob) {
  ReturnCode rc = ReturnCode::kOk;

  size_t dataoff, datasize;
  if (failed(rc = get_signature_range(dataoff, datasize)) ||
      superblob.size() != datasize) {
    return ReturnCode::kErrCommon;
  }
  memcpy(data_.data() + dataoff, superblob.data(), superblob.size());

  return rc;
}

ReturnCode MachO::save(const std::string& filepath) const {
  if (data_.empty()) {
    return ReturnCode::kErrCommon;
  }
  if (!internal::write_file(filepath, data_)) {
    return ReturnCode::kErrCommon;
  }
  return ReturnCode::kOk;
}

namespace {
namespace internal {
bool read_file(const std::string& filepath, Bytes& out_data) {
  std::ifstream file(filepath, std::ios::binary);
  if (!file) return false;
  out_data.assign((std::istreambuf_iterator<char>(file)),
                  std::istreambuf_iterator<char>());
  return !file.bad();
}

bool write_file(const std::string& filepath, const Bytes& data) {
  std::ofstream file(filepath, std::ios::binary | std::ios::trunc);
  if (!file) return false;
  file.write(reinterpret_cast<const char*>(data.data()),
             static_cast<std::streamsize>(data.size()));
  return static_cast<bool>(file);
}

bool read_slice(const Bytes& data, uint64_t offset, uint64_t size,
                MachOSlice& out_slice) {
  if (offset > data.size() || size > data.size() - offset) {
    return false;
  }

  uint32_t magic = read_struct<uint32_t>(data, offset);
  // iOS only ships little-endian slices, so byte-swapped (MH_CIGAM*) ones are
  // rejected along with anything that isn't a Mach-O.
  size_t header_size;
  if (magic == MH_MAGIC_64) {
    header_size = sizeof(mach_header_64);
  } else if (magic == MH_MAGIC) {
    header_size = sizeof(mach_header);
  } else {
    return false;
  }
  if (size < header_size) {
    return false;
  }

  // cputype, cpusubtype and filetype sit at the same offsets in mach_header
  // and mach_header_64.
  mach_header header = read_struct<mach_header>(data, offset);
  out_slice.cputype = header.cputype;
  out_slice.cpusubtype = header.cpusubtype;
  out_slice.filetype = header.filetype;
  out_slice.offset = offset;
  out_slice.size = size;
  return true;
}

bool host_get_cpu_type(cpu_type_t& out_cputype, cpu_subtype_t& out_cpusubtype) {
  size_t len = sizeof(out_cputype);
  if (sysctlbyname("hw.cputype", &out_cputype, &len, NULL, 0) == -1)
    return false;
  len = sizeof(out_cpusubtype);
  if (sysctlbyname("hw.cpusubtype", &out_cpusubtype, &len, NULL, 0) == -1)
    return false;
  return true;
}

bool host_supports_arm64e_abi_v2() {
  struct utsname name;
  if (uname(&name) != 0) return false;
  return atoi(name.release) >= 20;
}

uint32_t subtype_base(cpu_subtype_t cpusubtype) {
  return static_cast<uint32_t>(cpusubtype) & ~CPU_SUBTYPE_MASK;
}

}  // namespace internal
}  // namespace

}  // namespace ct_bypass::macho
