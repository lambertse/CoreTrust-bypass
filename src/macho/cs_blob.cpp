#include "cs_blob.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace ct_bypass::macho {

namespace {

// CodeDirectory byte layout (struct CS_CodeDirectory in xnu). Offsets count
// from the start of the blob and every integer is big-endian. Each version
// keeps the fields before it and appends its own block, so the fixed header
// ends at a different offset per version. Fields named *Offset point past
// the header, into the variable part below it.
//
//  offset  +0         +1         +2         +3
//        +----------+----------+----------+----------+
//      0 | magic = 0xfade0c02                        |
//      4 | length: size of the whole blob            |
//      8 | version                                   |
//     12 | flags                                     |
//     16 | hashOffset                                |  -> code slot 0
//     20 | identOffset                               |  -> identifier
//     24 | nSpecialSlots                             |
//     28 | nCodeSlots                                |
//     32 | codeLimit: bytes of the binary hashed     |
//        +----------+----------+----------+----------+
//     36 | hashSize | hashType | platform | pageSize |  pageSize = log2
//        +----------+----------+----------+----------+
//     40 | spare2                                    |
//        +===========================================+  44 = end of kBase
//     44 | scatterOffset                             |  kScatter
//        +-------------------------------------------+
//     48 | teamOffset                                |  kTeamId, -> Team ID
//        +-------------------------------------------+
//     52 | spare3                                    |  kCodeLimit64
//     56 | codeLimit64 (8 bytes), overrides          |
//     60 | codeLimit when non-zero                   |
//        +-------------------------------------------+
//     64 | execSegBase   (8 bytes)                   |  kExecSegment
//     72 | execSegLimit  (8 bytes)                   |
//     80 | execSegFlags  (8 bytes)                   |
//        +-------------------------------------------+
//     88 | runtime: hardened runtime version         |  kRuntime
//     92 | preEncryptOffset                          |
//        +----------+----------+---------------------+
//     96 | linkHash | linkApp  | linkAppSubType      |  kLinkage
//        +----------+----------+---------------------+
//    100 | linkageOffset                             |
//    104 | linkageSize                               |
//        +===========================================+  108 = end of kLinkage
//        | identifier  "com.example.app\0"           |  <- identOffset
//        | Team ID     "ABCDE12345\0"                |  <- teamOffset
//        +-------------------------------------------+
//        | special slot -N ... slot -2, slot -1      |  hashSize bytes each
//        +-------------------------------------------+  <- hashOffset
//        | code slot 0, 1, ... nCodeSlots - 1        |  slot i = hash of page i
//        +-------------------------------------------+  <- length
namespace cd_field {
constexpr size_t kMagic = 0;
constexpr size_t kLength = 4;
constexpr size_t kVersion = 8;
constexpr size_t kFlags = 12;
constexpr size_t kHashOffset = 16;
constexpr size_t kIdentOffset = 20;
constexpr size_t kNumSpecialSlots = 24;
constexpr size_t kNumCodeSlots = 28;
constexpr size_t kCodeLimit = 32;
constexpr size_t kHashSize = 36;
constexpr size_t kHashType = 37;
constexpr size_t kPageSizeLog2 = 39;
constexpr size_t kScatterOffset = 44;
constexpr size_t kTeamOffset = 48;
constexpr size_t kCodeLimit64 = 56;
constexpr size_t kPreEncryptOffset = 92;
constexpr size_t kLinkageOffset = 100;
}  // namespace cd_field

using Version = CodeDirectory::Version;

template <typename Enum>
inline constexpr uint32_t to_u32(Enum value) {
  return static_cast<uint32_t>(value);
}

size_t header_size(uint32_t version) {
  struct HeaderSize {
    Version version;
    size_t size;
  };
  constexpr HeaderSize kHeaderSizes[] = {
      {Version::kLinkage, 108},    {Version::kRuntime, 96},
      {Version::kExecSegment, 88}, {Version::kCodeLimit64, 64},
      {Version::kTeamId, 52},      {Version::kScatter, 48},
  };
  for (const auto& entry : kHeaderSizes) {
    if (version >= to_u32(entry.version)) return entry.size;
  }
  return 44;
}

// NUL-terminated string at `offset`; nullopt if it runs off the end of `data`
std::optional<std::string_view> read_string(const Bytes& data,
                                            uint32_t offset) {
  if (offset >= data.size()) return std::nullopt;
  auto begin = data.begin() + offset;
  auto nul = std::find(begin, data.end(), 0);
  if (nul == data.end()) return std::nullopt;
  return std::string_view(reinterpret_cast<const char*>(&*begin),
                          static_cast<size_t>(nul - begin));
}

constexpr size_t kSuperBlobHeaderSize = 12;  // magic, length, count
constexpr size_t kIndexEntrySize = 8;        // slot, offset

}  // namespace

std::optional<CodeDirectory> CodeDirectory::deserialize(Bytes data) {
  CodeDirectory cd(std::move(data));
  if (!cd.is_valid()) {
    return std::nullopt;
  }
  return cd;
}

bool CodeDirectory::is_valid() const {
  // The header must be complete before any accessor below is safe to call
  if (data_.size() < header_size(0) ||
      field(cd_field::kMagic) != to_u32(BlobMagic::kCodeDirectory) ||
      field(cd_field::kLength) != data_.size() ||
      header_size(version()) > data_.size()) {
    return false;
  }

  // Without this a truncated or zero hashSize slips through every slot check
  if (hash_size() == 0 || hash_size() != digest_size(hash_type())) {
    return false;
  }

  uint64_t header_end = header_size(version());
  uint64_t special_slots_size =
      static_cast<uint64_t>(field(cd_field::kNumSpecialSlots)) * hash_size();
  uint64_t code_slots_size =
      static_cast<uint64_t>(field(cd_field::kNumCodeSlots)) * hash_size();
  if (hash_offset() < header_end + special_slots_size ||
      hash_offset() + code_slots_size > data_.size()) {
    return false;
  }

  if (ident_offset() < header_end || !read_string(data_, ident_offset())) {
    return false;
  }
  if (team_offset() != 0 &&
      (team_offset() < header_end || !read_string(data_, team_offset()))) {
    return false;
  }
  return true;
}

uint32_t CodeDirectory::version() const { return field(cd_field::kVersion); }

bool CodeDirectory::has(Version version) const {
  return this->version() >= to_u32(version);
}

uint32_t CodeDirectory::flags() const { return field(cd_field::kFlags); }

HashType CodeDirectory::hash_type() const {
  return static_cast<HashType>(data_[cd_field::kHashType]);
}

std::string CodeDirectory::identifier() const {
  return std::string(*read_string(data_, ident_offset()));
}

std::string CodeDirectory::team_id() const {
  if (team_offset() == 0) {
    return {};
  }
  return std::string(*read_string(data_, team_offset()));
}

void CodeDirectory::set_flags(uint32_t flags) {
  set_field(cd_field::kFlags, flags);
}

ReturnCode CodeDirectory::set_team_id(std::string_view team_id) {
  if (!has(Version::kTeamId) || team_id.find('\0') != team_id.npos) {
    return ReturnCode::kErrCommon;
  }

  // The bytes to replace: the old Team ID, or nothing right after the
  // identifier when there is none yet
  uint64_t start = 0;
  uint64_t end = 0;
  if (team_offset() != 0) {
    start = team_offset();
    end = start + this->team_id().size() + 1;
  } else {
    start = ident_offset() + identifier().size() + 1;
    end = start;
  }

  // Bytes from `end` on move, so nothing the CodeDirectory addresses may sit
  // inside [start, end): not the header, the hash table or another string.
  if (start < header_size(version()) ||
      (end > hashes_begin() && start < hashes_end())) {
    return ReturnCode::kErrCommon;
  }
  uint64_t ident_end = ident_offset() + identifier().size() + 1;
  if (ident_offset() < end && start < ident_end) {
    // The identifier shares bytes with the old Team ID.
    return ReturnCode::kErrCommon;
  }

  std::vector<size_t> offset_fields = {cd_field::kHashOffset,
                                       cd_field::kIdentOffset};
  if (has(Version::kScatter)) offset_fields.push_back(cd_field::kScatterOffset);
  if (has(Version::kRuntime)) {
    offset_fields.push_back(cd_field::kPreEncryptOffset);
  }
  if (has(Version::kLinkage)) offset_fields.push_back(cd_field::kLinkageOffset);
  for (size_t offset_field : offset_fields) {
    uint32_t value = field(offset_field);
    if (value != 0 && start <= value && value < end) {
      return ReturnCode::kErrCommon;
    }
  }

  uint64_t removed = end - start;
  uint64_t inserted = team_id.size() + 1;
  uint64_t new_size = data_.size() - removed + inserted;
  if (new_size > std::numeric_limits<uint32_t>::max()) {
    return ReturnCode::kErrCommon;
  }

  // Build the edited copy so a failure leaves this CodeDirectory untouched
  Bytes edited;
  edited.reserve(new_size);
  edited.insert(edited.end(), data_.begin(), data_.begin() + start);
  edited.insert(edited.end(), team_id.begin(), team_id.end());
  edited.push_back(0);
  edited.insert(edited.end(), data_.begin() + end, data_.end());

  CodeDirectory result(std::move(edited));
  for (size_t offset_field : offset_fields) {
    uint32_t value = result.field(offset_field);
    if (value != 0 && value >= end) {
      result.set_field(offset_field,
                       static_cast<uint32_t>(value - removed + inserted));
    }
  }
  result.set_field(cd_field::kTeamOffset, static_cast<uint32_t>(start));
  result.set_field(cd_field::kLength, static_cast<uint32_t>(new_size));
  if (!result.is_valid()) {
    return ReturnCode::kErrCommon;
  }

  *this = std::move(result);
  return ReturnCode::kOk;
}

ReturnCode CodeDirectory::update_code_slots(const uint8_t* code,
                                            size_t code_size) {
  if (code_limit() != code_size) {
    return ReturnCode::kErrCommon;
  }

  // The header stores log2 of the page size; 0 means one page for everything
  uint8_t page_size_log2 = data_[cd_field::kPageSizeLog2];
  if (page_size_log2 >= 32) {
    return ReturnCode::kErrCommon;
  }
  uint64_t page_size = page_size_log2 ? uint64_t{1} << page_size_log2
                                      : static_cast<uint64_t>(code_size);
  uint64_t page_count = page_size ? (code_size + page_size - 1) / page_size : 0;
  if (field(cd_field::kNumCodeSlots) != page_count) {
    return ReturnCode::kErrCommon;
  }

  // Hash into a copy so a failure leaves this CodeDirectory untouched
  Bytes updated = data_;
  for (uint64_t page = 0; page < page_count; page++) {
    uint64_t page_start = page * page_size;
    uint64_t page_length = std::min(page_size, code_size - page_start);
    std::optional<Bytes> digest =
        compute_digest(hash_type(), code + page_start, page_length);
    if (!digest) {
      return ReturnCode::kErrCommon;
    }
    std::copy(digest->begin(), digest->end(),
              updated.begin() + hash_offset() + page * hash_size());
  }
  // A string stored among the code slots may have lost its NUL
  CodeDirectory result(std::move(updated));
  if (!result.is_valid()) {
    return ReturnCode::kErrCommon;
  }
  *this = std::move(result);
  return ReturnCode::kOk;
}

uint32_t CodeDirectory::field(size_t offset) const {
  return read_be32(data_.data() + offset);
}

void CodeDirectory::set_field(size_t offset, uint32_t value) {
  write_be32(data_.data() + offset, value);
}

uint32_t CodeDirectory::hash_offset() const {
  return field(cd_field::kHashOffset);
}

uint32_t CodeDirectory::ident_offset() const {
  return field(cd_field::kIdentOffset);
}

uint32_t CodeDirectory::team_offset() const {
  return has(Version::kTeamId) ? field(cd_field::kTeamOffset) : 0;
}

uint8_t CodeDirectory::hash_size() const { return data_[cd_field::kHashSize]; }

uint64_t CodeDirectory::code_limit() const {
  // A non-zero 64-bit codeLimit overrides the 32-bit one
  if (has(Version::kCodeLimit64)) {
    uint64_t code_limit_64 = read_be64(data_.data() + cd_field::kCodeLimit64);
    if (code_limit_64 != 0) return code_limit_64;
  }
  return field(cd_field::kCodeLimit);
}

uint64_t CodeDirectory::hashes_begin() const {
  return hash_offset() -
         static_cast<uint64_t>(field(cd_field::kNumSpecialSlots)) * hash_size();
}

uint64_t CodeDirectory::hashes_end() const {
  return hash_offset() +
         static_cast<uint64_t>(field(cd_field::kNumCodeSlots)) * hash_size();
}

std::optional<SuperBlob> SuperBlob::deserialize(const Bytes& data) {
  if (data.size() < kSuperBlobHeaderSize ||
      read_be32(data.data()) != to_u32(BlobMagic::kEmbeddedSignature)) {
    return std::nullopt;
  }
  uint32_t length = read_be32(data.data() + 4);
  uint32_t count = read_be32(data.data() + 8);
  if (length < kSuperBlobHeaderSize || length > data.size() ||
      count > (length - kSuperBlobHeaderSize) / kIndexEntrySize) {
    return std::nullopt;
  }

  SuperBlob superblob;
  for (uint32_t i = 0; i < count; i++) {
    const uint8_t* entry =
        data.data() + kSuperBlobHeaderSize + i * kIndexEntrySize;
    auto slot = static_cast<SlotType>(read_be32(entry));
    uint32_t offset = read_be32(entry + 4);
    if (offset > length - kBlobHeaderSize) {
      return std::nullopt;
    }
    uint32_t blob_length = read_be32(data.data() + offset + 4);
    if (blob_length < kBlobHeaderSize || blob_length > length - offset) {
      return std::nullopt;
    }
    // Keep the blob's own magic and length; its field offsets count from them
    superblob.blobs_.push_back(Blob{
        slot,
        Bytes(data.begin() + offset, data.begin() + offset + blob_length)});
  }
  return superblob;
}

Bytes SuperBlob::serialize() const {
  auto count = static_cast<uint32_t>(blobs_.size());
  size_t length = kSuperBlobHeaderSize + count * kIndexEntrySize;
  for (const Blob& blob : blobs_) {
    length += blob.data.size();
  }

  // Emit the index in ascending slot order. CoreTrust picks the CodeDirectory
  // by slot, not by position, but codesign writes the slots sorted and the
  // bypass relies on it to reproduce the reference layout (slot 0, then the
  // entitlements, the alternate CodeDirectory and the signature).
  std::vector<const Blob*> ordered;
  ordered.reserve(blobs_.size());
  for (const Blob& blob : blobs_) {
    ordered.push_back(&blob);
  }
  std::stable_sort(ordered.begin(), ordered.end(),
                   [](const Blob* a, const Blob* b) {
                     return to_u32(a->slot) < to_u32(b->slot);
                   });

  Bytes data(length);
  write_be32(&data[0], to_u32(BlobMagic::kEmbeddedSignature));
  write_be32(&data[4], static_cast<uint32_t>(length));
  write_be32(&data[8], count);

  size_t offset = kSuperBlobHeaderSize + count * kIndexEntrySize;
  for (uint32_t i = 0; i < count; i++) {
    const Blob& blob = *ordered[i];
    uint8_t* entry = &data[kSuperBlobHeaderSize + i * kIndexEntrySize];
    write_be32(entry, to_u32(blob.slot));
    write_be32(entry + 4, static_cast<uint32_t>(offset));
    std::copy(blob.data.begin(), blob.data.end(), data.begin() + offset);
    offset += blob.data.size();
  }
  return data;
}

std::optional<Blob> SuperBlob::find_blob(SlotType slot) const {
  auto it =
      std::find_if(blobs_.begin(), blobs_.end(),
                   [slot](const Blob& blob) { return blob.slot == slot; });
  if (it == blobs_.end()) {
    return std::nullopt;
  }
  return *it;
}

ReturnCode SuperBlob::remove_blob(SlotType slot) {
  auto it =
      std::find_if(blobs_.begin(), blobs_.end(),
                   [slot](const Blob& blob) { return blob.slot == slot; });
  if (it == blobs_.end()) {
    return ReturnCode::kErrCommon;
  }
  blobs_.erase(it);
  return ReturnCode::kOk;
}

ReturnCode SuperBlob::add_blob(const Blob& blob) {
  if (find_blob(blob.slot).has_value()) {
    return ReturnCode::kErrCommon;
  }
  blobs_.push_back(blob);
  return ReturnCode::kOk;
}

ReturnCode SuperBlob::replace_blob(const Blob& blob) {
  auto it = std::find_if(blobs_.begin(), blobs_.end(),
                         [&blob](const Blob& b) { return b.slot == blob.slot; });
  if (it == blobs_.end()) {
    return ReturnCode::kErrCommon;
  }
  *it = blob;
  return ReturnCode::kOk;
}

}  // namespace ct_bypass::macho
