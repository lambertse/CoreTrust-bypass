#ifndef CT_BYPASS_MACHO_UTILS_H
#define CT_BYPASS_MACHO_UTILS_H

#include <cstdint>
#include <vector>

namespace ct_bypass::macho {

using Byte = uint8_t;
using Bytes = std::vector<Byte>;

inline uint32_t read_be32(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) << 24 | static_cast<uint32_t>(p[1]) << 16 |
         static_cast<uint32_t>(p[2]) << 8 | static_cast<uint32_t>(p[3]);
}

inline uint64_t read_be64(const uint8_t* p) {
  return static_cast<uint64_t>(read_be32(p)) << 32 | read_be32(p + 4);
}

inline void write_be32(uint8_t* p, uint32_t value) {
  p[0] = static_cast<uint8_t>(value >> 24);
  p[1] = static_cast<uint8_t>(value >> 16);
  p[2] = static_cast<uint8_t>(value >> 8);
  p[3] = static_cast<uint8_t>(value);
}

}  // namespace ct_bypass::macho

#endif  // CT_BYPASS_MACHO_UTILS_H
