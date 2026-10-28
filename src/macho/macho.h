#ifndef CT_BYPASS_MACHO_H
#define CT_BYPASS_MACHO_H

#include <mach/machine.h>
#include <stddef.h>
#include <stdint.h>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "exploit/return_code.h"
#include "utils.h"

// High bit of cpusubtype: arm64e built with the stable pointer-auth ABI
// (CPU_SUBTYPE_PTRAUTH_ABI in newer SDKs)
#ifndef CPU_SUBTYPE_ARM64E_ABI_V2
#define CPU_SUBTYPE_ARM64E_ABI_V2 0x80000000
#endif

namespace ct_bypass::macho {

// One architecture slice of a file. A thin Mach-O is one slice covering the
// whole file. CPU type, subtype and filetype come from the slice's own header.
struct MachOSlice {
  cpu_type_t cputype;
  cpu_subtype_t cpusubtype;
  uint32_t filetype;
  uint64_t offset;
  uint64_t size;
};
using MachOSliceList = std::vector<MachOSlice>;

// A Mach-O file (thin or universal) held in memory. Every file exposes its
// slices; only a thin 64-bit Mach-O also exposes its load commands and can
// have its code signature edited. Edits stay in memory until save().
class MachO {
 public:
  using Ptr = std::unique_ptr<MachO>;

  static ReturnCode load(const std::string& filepath, MachO::Ptr& out_macho);
  static ReturnCode from_bytes(Bytes data, MachO::Ptr& out_macho);
  ReturnCode save(const std::string& filepath) const;

  const Bytes& data() const { return data_; }

  // Slices
  const MachOSliceList& get_slices() const;
  // First slice of this CPU type whose base subtype matches; capability bits
  // (the high byte of cpusubtype) are ignored on both sides.
  std::optional<MachOSlice> find_slice(cpu_type_t cputype,
                                       cpu_subtype_t cpusubtype) const;
  // The slice the host's kernel would run, or nullopt. Only arm64 hosts have
  // one.
  std::optional<MachOSlice> find_preferred_slice() const;
  // Host-independent pick for tooling that prepares arm64 binaries on another
  // machine: arm64v8, arm64, arm64e (new ABI), then arm64e (old ABI).
  std::optional<MachOSlice> find_arm64_slice() const;
  // Copies `slice` out into a thin MachO of its own.
  ReturnCode extract_slice(const MachOSlice& slice, MachO::Ptr& out) const;

  // Load commands; meaningful only when is_thin_64()
  bool is_thin_64() const;
  std::optional<uint32_t> filetype() const { return filetype_; }
  // An LC_ENCRYPTION_INFO(_64) has cryptid != 0
  bool encrypted() const { return encrypted_; }
  std::optional<size_t> linkedit_command() const { return linkedit_command_; }
  std::optional<size_t> code_signature_command() const {
    return code_signature_command_;
  }

  // Code signature
  // LC_CODE_SIGNATURE's dataoff/datasize, checked to lie inside the file.
  ReturnCode get_signature_range(size_t& out_offset, size_t& out_size) const;
  // Makes room for a SuperBlob of `new_size` bytes. Any padding that followed
  // the old SuperBlob is kept after the new one and stays covered by
  // LC_CODE_SIGNATURE, as codesign lays it out. Rewrites datasize and the
  // __LINKEDIT sizes, resizes the file and zero-fills the signature range.
  ReturnCode resize_code_signature(size_t new_size);
  // Writes `superblob` at the start of the signature range (it must fit) and
  // zero-fills the rest of the range.
  ReturnCode update_code_signature(const Bytes& superblob);

 private:
  explicit MachO(Bytes&& data);

  ReturnCode load_slices();
  ReturnCode load_load_commands();
  // First arm64e slice built for the new (`abi_v2`) or old pointer-auth ABI
  std::optional<MachOSlice> find_arm64e_slice(bool abi_v2) const;

  Bytes data_;
  MachOSliceList slices_;
  // Parsed from the load commands of a thin 64-bit Mach-O; unset or false
  // otherwise. The command offsets are file offsets.
  std::optional<uint32_t> filetype_;
  bool encrypted_ = false;
  std::optional<size_t> linkedit_command_;
  std::optional<size_t> code_signature_command_;
};

}  // namespace ct_bypass::macho

#endif  // CT_BYPASS_MACHO_H
