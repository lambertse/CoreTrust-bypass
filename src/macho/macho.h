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

#ifndef CPU_SUBTYPE_ARM64E_ABI_V2
#define CPU_SUBTYPE_ARM64E_ABI_V2 0x80000000
#endif

namespace ct_bypass::macho {

using Byte = uint8_t;
using Bytes = std::vector<Byte>;

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

  static ReturnCode load(const std::string& filepath, MachO::Ptr& out_macho);
  static ReturnCode save(const std::string& filepath, const MachO::Ptr& macho);

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
  MachOSliceList slices_;
};

}  // namespace ct_bypass::macho

#endif  // CT_BYPASS_MACHO_H
