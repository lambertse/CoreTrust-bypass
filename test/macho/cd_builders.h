#ifndef CT_BYPASS_TEST_CD_BUILDERS_H
#define CT_BYPASS_TEST_CD_BUILDERS_H

// Synthetic CodeDirectory / SuperBlob byte builders for the bypass tests, laid
// out the way codesign does it (header, identifier, Team ID, special slots,
// code slots). Kept in a header so several test files can share them.

#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "macho/cs_blob.h"
#include "macho/digest.h"
#include "macho/utils.h"

namespace ct_bypass::macho::test {

// CodeDirectory header offsets (mirror cd_field in cs_blob.cpp)
inline constexpr size_t kCdLength = 4;
inline constexpr size_t kCdVersion = 8;
inline constexpr size_t kCdFlags = 12;
inline constexpr size_t kCdHashOffset = 16;
inline constexpr size_t kCdIdentOffset = 20;
inline constexpr size_t kCdNumSpecialSlots = 24;
inline constexpr size_t kCdNumCodeSlots = 28;
inline constexpr size_t kCdCodeLimit = 32;
inline constexpr size_t kCdHashSize = 36;
inline constexpr size_t kCdHashType = 37;
inline constexpr size_t kCdPageSizeLog2 = 39;
inline constexpr size_t kCdTeamOffset = 48;

inline size_t header_size_of(uint32_t version) {
  if (version >= 0x20600) return 108;
  if (version >= 0x20500) return 96;
  if (version >= 0x20400) return 88;
  if (version >= 0x20300) return 64;
  if (version >= 0x20200) return 52;
  if (version >= 0x20100) return 48;
  return 44;
}

struct CdSpec {
  uint32_t version = 0x20400;  // kExecSegment
  uint32_t flags = 0;
  std::string identifier = "com.example.app";
  std::optional<std::string> team_id = std::string("ABCDE12345");
  uint32_t special_slots = 2;
  uint32_t code_slots = 3;
  HashType hash_type = HashType::kSha256;
  uint8_t hash_size = 32;
  uint8_t page_size_log2 = 12;
  uint32_t code_limit = 3 * 4096;
};

inline Bytes make_cd(const CdSpec& spec) {
  size_t header_size = header_size_of(spec.version);
  size_t ident_offset = header_size;
  size_t team_offset = ident_offset + spec.identifier.size() + 1;
  size_t strings_end =
      spec.team_id ? team_offset + spec.team_id->size() + 1 : team_offset;
  size_t hash_offset = strings_end + spec.special_slots * spec.hash_size;
  size_t size = hash_offset + spec.code_slots * spec.hash_size;

  Bytes cd(size, 0);
  write_be32(cd.data(), static_cast<uint32_t>(BlobMagic::kCodeDirectory));
  write_be32(cd.data() + kCdLength, static_cast<uint32_t>(size));
  write_be32(cd.data() + kCdVersion, spec.version);
  write_be32(cd.data() + kCdFlags, spec.flags);
  write_be32(cd.data() + kCdHashOffset, static_cast<uint32_t>(hash_offset));
  write_be32(cd.data() + kCdIdentOffset, static_cast<uint32_t>(ident_offset));
  write_be32(cd.data() + kCdNumSpecialSlots, spec.special_slots);
  write_be32(cd.data() + kCdNumCodeSlots, spec.code_slots);
  write_be32(cd.data() + kCdCodeLimit, spec.code_limit);
  cd[kCdHashSize] = spec.hash_size;
  cd[kCdHashType] = static_cast<Byte>(spec.hash_type);
  cd[kCdPageSizeLog2] = spec.page_size_log2;
  if (spec.team_id && spec.version >= 0x20200) {
    write_be32(cd.data() + kCdTeamOffset, static_cast<uint32_t>(team_offset));
  }

  std::memcpy(cd.data() + ident_offset, spec.identifier.c_str(),
              spec.identifier.size() + 1);
  if (spec.team_id) {
    std::memcpy(cd.data() + team_offset, spec.team_id->c_str(),
                spec.team_id->size() + 1);
  }
  for (int slot = -static_cast<int>(spec.special_slots);
       slot < static_cast<int>(spec.code_slots); slot++) {
    std::memset(cd.data() + hash_offset + slot * spec.hash_size,
                static_cast<Byte>(0x80 + slot), spec.hash_size);
  }
  return cd;
}

// A generic blob: magic + length header followed by `length - 8` fill bytes.
inline Bytes make_blob(uint32_t magic, uint32_t length, Byte fill) {
  Bytes blob(length, fill);
  write_be32(blob.data(), magic);
  write_be32(blob.data() + 4, length);
  return blob;
}

// A raw SuperBlob buffer (magic, length, count, index, bodies) ready for
// SuperBlob::deserialize.
inline Bytes make_superblob(
    const std::vector<std::pair<SlotType, Bytes>>& entries) {
  constexpr size_t kSuperHeader = 12;
  constexpr size_t kIndexEntry = 8;
  size_t length = kSuperHeader + entries.size() * kIndexEntry;
  for (const auto& entry : entries) length += entry.second.size();

  Bytes data(length, 0);
  write_be32(data.data(), static_cast<uint32_t>(BlobMagic::kEmbeddedSignature));
  write_be32(data.data() + 4, static_cast<uint32_t>(length));
  write_be32(data.data() + 8, static_cast<uint32_t>(entries.size()));

  size_t offset = kSuperHeader + entries.size() * kIndexEntry;
  for (size_t i = 0; i < entries.size(); i++) {
    uint8_t* entry = data.data() + kSuperHeader + i * kIndexEntry;
    write_be32(entry, static_cast<uint32_t>(entries[i].first));
    write_be32(entry + 4, static_cast<uint32_t>(offset));
    std::memcpy(data.data() + offset, entries[i].second.data(),
                entries[i].second.size());
    offset += entries[i].second.size();
  }
  return data;
}

}  // namespace ct_bypass::macho::test

#endif  // CT_BYPASS_TEST_CD_BUILDERS_H
