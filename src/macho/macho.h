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

#ifndef CPU_SUBTYPE_ARM64E_ABI_V2
#define CPU_SUBTYPE_ARM64E_ABI_V2 0x80000000
#endif

namespace ct_bypass::macho {

struct MachOSlice {
  cpu_type_t cputype;
  cpu_subtype_t cpusubtype;
  uint32_t filetype;
  uint64_t offset;
  uint64_t size;
};
using MachOSliceList = std::vector<MachOSlice>;

class MachO {
 public:
  using Ptr = std::unique_ptr<MachO>;

  ~MachO() = default;

  const MachOSliceList& get_slices() const;
  std::optional<MachOSlice> find_slice(cpu_type_t cputype,
                                       cpu_subtype_t cpusubtype) const;
  std::optional<MachOSlice> find_preferred_slice() const;

  ReturnCode get_signature_range(size_t& out_offset, size_t& out_size) const;
  ReturnCode resize_code_signature(size_t new_size);
  ReturnCode update_code_signature(const Bytes& superblob);

  ReturnCode write_code_signature(const Bytes& superblob);
  // Important function, macho after editting has to be call saved to sync into
  // disk
  ReturnCode save(const std::string& filepath) const;

  static ReturnCode load(const std::string& filepath, MachO::Ptr& out_macho);
  static ReturnCode save(const std::string& filepath, const MachO::Ptr& macho);

  // Getter/setter
  const Bytes& data() const { return data_; }
  std::optional<bool> encrypted() const { return encrypted_; }
  std::optional<uint32_t> filetype() const { return filetype_; }
  std::optional<size_t> linkedit_command() const { return linkedit_command_; }
  std::optional<size_t> code_signature_command() const {
    return code_signature_command_;
  }

 private:
  explicit MachO(Bytes&& data);

  ReturnCode load_slices();
  ReturnCode load_load_commands();

 private:
  Bytes data_;
  // File offsets of the __LINKEDIT and LC_CODE_SIGNATURE load commands; unset
  // when absent or the file isn't a thin 64-bit Mach-O.
  std::optional<size_t> linkedit_command_;
  std::optional<size_t> code_signature_command_;
  std::optional<bool> encrypted_;
  std::optional<uint32_t> filetype_;
  MachOSliceList slices_;
};

}  // namespace ct_bypass::macho

#endif  // CT_BYPASS_MACHO_H
