#include "macho/cs_blob.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>
#include <optional>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

namespace ct_bypass {

// Prints ReturnCode as its value instead of raw bytes in assertion failures.
void PrintTo(ReturnCode code, std::ostream* os) {
  *os << static_cast<int>(code);
}

namespace macho {
namespace {

// CodeDirectory header offsets used to build and corrupt test blobs.
constexpr size_t kCdLength = 4;
constexpr size_t kCdVersion = 8;
constexpr size_t kCdFlags = 12;
constexpr size_t kCdHashOffset = 16;
constexpr size_t kCdIdentOffset = 20;
constexpr size_t kCdNumSpecialSlots = 24;
constexpr size_t kCdNumCodeSlots = 28;
constexpr size_t kCdCodeLimit = 32;
constexpr size_t kCdHashSize = 36;
constexpr size_t kCdHashType = 37;
constexpr size_t kCdPageSizeLog2 = 39;
constexpr size_t kCdScatterOffset = 44;
constexpr size_t kCdTeamOffset = 48;

constexpr uint32_t kVersionExecSegment = 0x20400;
constexpr size_t kHeaderSizeExecSegment = 88;

void put_be32(Bytes& data, size_t offset, uint32_t value) {
  ASSERT_LE(offset + 4, data.size());
  write_be32(data.data() + offset, value);
}

uint32_t get_be32(const Bytes& data, size_t offset) {
  EXPECT_LE(offset + 4, data.size());
  return offset + 4 <= data.size() ? read_be32(data.data() + offset) : 0;
}

Bytes from_hex(const std::string& hex) {
  Bytes bytes;
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    bytes.push_back(
        static_cast<Byte>(std::stoul(hex.substr(i, 2), nullptr, 16)));
  }
  return bytes;
}

// Describes a CodeDirectory laid out the way codesign does it: header,
// identifier, Team ID, special slots, code slots.
struct CdSpec {
  uint32_t version = kVersionExecSegment;
  std::string identifier = "com.example.app";
  std::optional<std::string> team_id = "ABCDE12345";
  uint32_t special_slots = 2;
  uint32_t code_slots = 3;
  HashType hash_type = HashType::kSha256;
  uint8_t hash_size = 32;
  uint8_t page_size_log2 = 12;
  uint32_t code_limit = 3 * 4096;
};

size_t header_size_of(uint32_t version) {
  if (version >= kVersionExecSegment) return kHeaderSizeExecSegment;
  if (version >= 0x20300) return 64;
  if (version >= 0x20200) return 52;
  if (version >= 0x20100) return 48;
  return 44;
}

// Slot i (special slots negative) is filled with a byte unique to it, so tests
// can tell whether the hashes survived an edit.
Byte slot_fill(int slot) { return static_cast<Byte>(0x80 + slot); }

Bytes make_cd(const CdSpec& spec) {
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

  memcpy(cd.data() + ident_offset, spec.identifier.c_str(),
         spec.identifier.size() + 1);
  if (spec.team_id) {
    memcpy(cd.data() + team_offset, spec.team_id->c_str(),
           spec.team_id->size() + 1);
  }
  for (int slot = -static_cast<int>(spec.special_slots);
       slot < static_cast<int>(spec.code_slots); slot++) {
    memset(cd.data() + hash_offset + slot * spec.hash_size, slot_fill(slot),
           spec.hash_size);
  }
  return cd;
}

// The special and code slots, in storage order
Bytes hash_table(const Bytes& cd) {
  uint32_t hash_offset = get_be32(cd, kCdHashOffset);
  size_t begin =
      hash_offset - get_be32(cd, kCdNumSpecialSlots) * cd[kCdHashSize];
  size_t end = hash_offset + get_be32(cd, kCdNumCodeSlots) * cd[kCdHashSize];
  return Bytes(cd.begin() + begin, cd.begin() + end);
}

TEST(CodeDirectoryDeserialize, AcceptsWellFormed) {
  auto cd = CodeDirectory::deserialize(make_cd({}));
  ASSERT_TRUE(cd);
  EXPECT_EQ(cd->version(), kVersionExecSegment);
  EXPECT_TRUE(cd->has(CodeDirectory::Version::kTeamId));
  EXPECT_FALSE(cd->has(CodeDirectory::Version::kRuntime));
  EXPECT_EQ(cd->hash_type(), HashType::kSha256);
  EXPECT_EQ(cd->identifier(), "com.example.app");
  EXPECT_EQ(cd->team_id(), "ABCDE12345");
}

TEST(CodeDirectoryDeserialize, TeamIdIsEmptyWhenAbsent) {
  CdSpec spec;
  spec.team_id = std::nullopt;
  auto cd = CodeDirectory::deserialize(make_cd(spec));
  ASSERT_TRUE(cd);
  EXPECT_EQ(cd->team_id(), "");
}

TEST(CodeDirectoryDeserialize, RejectsBadHeader) {
  Bytes wrong_magic = make_cd({});
  wrong_magic[3] ^= 0xff;
  EXPECT_FALSE(CodeDirectory::deserialize(wrong_magic));

  Bytes wrong_length = make_cd({});
  put_be32(wrong_length, kCdLength, get_be32(wrong_length, kCdLength) - 1);
  EXPECT_FALSE(CodeDirectory::deserialize(wrong_length));

  Bytes header_too_big = make_cd({});
  put_be32(header_too_big, kCdVersion, 0x20600);
  header_too_big.resize(100);
  put_be32(header_too_big, kCdLength, 100);
  EXPECT_FALSE(CodeDirectory::deserialize(header_too_big));

  EXPECT_FALSE(CodeDirectory::deserialize(Bytes(8, 0)));
}

TEST(CodeDirectoryDeserialize, RejectsHashTableOverlappingHeader) {
  Bytes cd = make_cd({});
  put_be32(cd, kCdNumSpecialSlots, 0);
  put_be32(cd, kCdHashOffset, 8);
  EXPECT_FALSE(CodeDirectory::deserialize(cd));

  // Special slots reaching back into the header
  cd = make_cd({});
  put_be32(cd, kCdNumSpecialSlots, 10);
  EXPECT_FALSE(CodeDirectory::deserialize(cd));
}

TEST(CodeDirectoryDeserialize, RejectsHashTablePastEnd) {
  Bytes cd = make_cd({});
  put_be32(cd, kCdNumCodeSlots, 4);
  EXPECT_FALSE(CodeDirectory::deserialize(cd));
}

TEST(CodeDirectoryDeserialize, RejectsHashSizeNotMatchingHashType) {
  CdSpec truncated;
  truncated.hash_size = 20;  // SHA-256 needs 32
  EXPECT_FALSE(CodeDirectory::deserialize(make_cd(truncated)));

  CdSpec zero;
  zero.hash_size = 0;
  EXPECT_FALSE(CodeDirectory::deserialize(make_cd(zero)));

  CdSpec unknown_type;
  unknown_type.hash_type = static_cast<HashType>(9);
  EXPECT_FALSE(CodeDirectory::deserialize(make_cd(unknown_type)));
}

TEST(CodeDirectoryDeserialize, RejectsStringOffsetsInHeaderOrPastEnd) {
  Bytes ident_in_header = make_cd({});
  put_be32(ident_in_header, kCdIdentOffset, 0);
  EXPECT_FALSE(CodeDirectory::deserialize(ident_in_header));

  Bytes team_in_header = make_cd({});
  put_be32(team_in_header, kCdTeamOffset, 4);
  EXPECT_FALSE(CodeDirectory::deserialize(team_in_header));

  Bytes team_past_end = make_cd({});
  put_be32(team_past_end, kCdTeamOffset,
           static_cast<uint32_t>(team_past_end.size()));
  EXPECT_FALSE(CodeDirectory::deserialize(team_past_end));
}

TEST(CodeDirectoryDeserialize, RejectsUnterminatedString) {
  // With no hash slots the Team ID ends the blob; drop its NUL
  CdSpec spec;
  spec.special_slots = 0;
  spec.code_slots = 0;
  Bytes cd = make_cd(spec);
  cd.back() = 'x';
  EXPECT_FALSE(CodeDirectory::deserialize(cd));
}

TEST(CodeDirectorySetFlags, WritesFlagsField) {
  auto cd = CodeDirectory::deserialize(make_cd({}));
  ASSERT_TRUE(cd);
  cd->set_flags(0x10002);
  EXPECT_EQ(cd->flags(), 0x10002u);
  EXPECT_EQ(get_be32(cd->data(), kCdFlags), 0x10002u);
}

void expect_team_id_replaced(const std::string& new_team_id) {
  Bytes original = make_cd({});
  auto cd = CodeDirectory::deserialize(original);
  ASSERT_TRUE(cd);

  ASSERT_EQ(cd->set_team_id(new_team_id), ReturnCode::kOk);

  const Bytes& edited = cd->data();
  EXPECT_EQ(cd->team_id(), new_team_id);
  EXPECT_EQ(cd->identifier(), "com.example.app");
  EXPECT_EQ(get_be32(edited, kCdLength), edited.size());
  EXPECT_EQ(get_be32(edited, kCdTeamOffset),
            get_be32(original, kCdTeamOffset));

  // Everything after the Team ID moved by the change in its length
  int64_t shift = static_cast<int64_t>(new_team_id.size()) -
                  static_cast<int64_t>(std::string("ABCDE12345").size());
  EXPECT_EQ(edited.size(), original.size() + shift);
  EXPECT_EQ(get_be32(edited, kCdHashOffset),
            get_be32(original, kCdHashOffset) + shift);
  EXPECT_EQ(hash_table(edited), hash_table(original));
  EXPECT_TRUE(CodeDirectory::deserialize(edited));
}

TEST(CodeDirectorySetTeamId, ReplacesWithLongerTeamId) {
  expect_team_id_replaced("ABCDE12345-LONGER");
}

TEST(CodeDirectorySetTeamId, ReplacesWithShorterTeamId) {
  expect_team_id_replaced("XYZ");
}

TEST(CodeDirectorySetTeamId, ReplacesWithSameLengthTeamId) {
  expect_team_id_replaced("ZZZZZ99999");
}

TEST(CodeDirectorySetTeamId, InsertsAfterIdentifierWhenAbsent) {
  CdSpec spec;
  spec.team_id = std::nullopt;
  Bytes original = make_cd(spec);
  auto cd = CodeDirectory::deserialize(original);
  ASSERT_TRUE(cd);

  ASSERT_EQ(cd->set_team_id("NEWTEAM"), ReturnCode::kOk);

  const Bytes& edited = cd->data();
  EXPECT_EQ(cd->team_id(), "NEWTEAM");
  EXPECT_EQ(get_be32(edited, kCdTeamOffset),
            kHeaderSizeExecSegment + std::string("com.example.app").size() + 1);
  EXPECT_EQ(get_be32(edited, kCdHashOffset),
            get_be32(original, kCdHashOffset) + 8);
  EXPECT_EQ(hash_table(edited), hash_table(original));
  EXPECT_TRUE(CodeDirectory::deserialize(edited));
}

TEST(CodeDirectorySetTeamId, RejectsVersionWithoutTeamOffset) {
  CdSpec spec;
  spec.version = 0x20100;
  spec.team_id = std::nullopt;
  auto cd = CodeDirectory::deserialize(make_cd(spec));
  ASSERT_TRUE(cd);
  Bytes before = cd->data();
  EXPECT_EQ(cd->set_team_id("TEAM"), ReturnCode::kErrCommon);
  EXPECT_EQ(cd->data(), before);
}

TEST(CodeDirectorySetTeamId, RejectsEmbeddedNul) {
  auto cd = CodeDirectory::deserialize(make_cd({}));
  ASSERT_TRUE(cd);
  Bytes before = cd->data();
  EXPECT_EQ(cd->set_team_id(std::string("AB\0CD", 5)), ReturnCode::kErrCommon);
  EXPECT_EQ(cd->data(), before);
}

TEST(CodeDirectorySetTeamId, RejectsTeamIdInsideHashTable) {
  // A Team ID stored among the code slots: replacing it would shift the
  // page hashes after it
  Bytes bytes = make_cd({});
  uint32_t team_offset = get_be32(bytes, kCdHashOffset) + 1;
  put_be32(bytes, kCdTeamOffset, team_offset);
  bytes[team_offset + 4] = 0;
  auto cd = CodeDirectory::deserialize(bytes);
  ASSERT_TRUE(cd);

  EXPECT_EQ(cd->set_team_id("TEAM"), ReturnCode::kErrCommon);
  EXPECT_EQ(cd->data(), bytes);
}

TEST(CodeDirectorySetTeamId, RejectsTeamIdSharedWithIdentifier) {
  // identOffset == teamOffset: replacing the Team ID would rename the app
  Bytes bytes = make_cd({});
  put_be32(bytes, kCdTeamOffset, get_be32(bytes, kCdIdentOffset));
  auto cd = CodeDirectory::deserialize(bytes);
  ASSERT_TRUE(cd);

  EXPECT_EQ(cd->set_team_id("TEAM"), ReturnCode::kErrCommon);
  EXPECT_EQ(cd->data(), bytes);
}

TEST(CodeDirectorySetTeamId, RejectsTeamIdInsideIdentifier) {
  // teamOffset pointing at the identifier's suffix "app"
  Bytes bytes = make_cd({});
  put_be32(bytes, kCdTeamOffset, get_be32(bytes, kCdIdentOffset) + 12);
  auto cd = CodeDirectory::deserialize(bytes);
  ASSERT_TRUE(cd);
  ASSERT_EQ(cd->team_id(), "app");

  EXPECT_EQ(cd->set_team_id("TEAM"), ReturnCode::kErrCommon);
  EXPECT_EQ(cd->data(), bytes);
}

TEST(CodeDirectorySetTeamId, RejectsOtherOffsetInsideTeamId) {
  // scatterOffset pointing into the Team ID would end up mid-string
  Bytes bytes = make_cd({});
  put_be32(bytes, kCdScatterOffset, get_be32(bytes, kCdTeamOffset) + 2);
  auto cd = CodeDirectory::deserialize(bytes);
  ASSERT_TRUE(cd);

  EXPECT_EQ(cd->set_team_id("TEAM"), ReturnCode::kErrCommon);
  EXPECT_EQ(cd->data(), bytes);
}

TEST(CodeDirectorySetTeamId, ShiftsOtherOffsetsAfterTeamId) {
  Bytes bytes = make_cd({});
  uint32_t scatter_offset = get_be32(bytes, kCdHashOffset) - 4;
  put_be32(bytes, kCdScatterOffset, scatter_offset);
  auto cd = CodeDirectory::deserialize(bytes);
  ASSERT_TRUE(cd);

  ASSERT_EQ(cd->set_team_id("ABCDE12345XY"), ReturnCode::kOk);
  EXPECT_EQ(get_be32(cd->data(), kCdScatterOffset), scatter_offset + 2);
}

TEST(CodeDirectoryUpdateCodeSlots, WritesKnownSha256) {
  CdSpec spec;
  spec.special_slots = 0;
  spec.code_slots = 1;
  spec.page_size_log2 = 0;  // one page covering everything
  spec.code_limit = 3;
  auto cd = CodeDirectory::deserialize(make_cd(spec));
  ASSERT_TRUE(cd);

  const uint8_t code[] = {'a', 'b', 'c'};
  ASSERT_EQ(cd->update_code_slots(code, sizeof(code)), ReturnCode::kOk);
  EXPECT_EQ(hash_table(cd->data()),
            from_hex("ba7816bf8f01cfea414140de5dae2223"
                     "b00361a396177a9cb410ff61f20015ad"));
}

TEST(CodeDirectoryUpdateCodeSlots, WritesKnownSha1) {
  CdSpec spec;
  spec.hash_type = HashType::kSha1;
  spec.hash_size = 20;
  spec.special_slots = 0;
  spec.code_slots = 1;
  spec.page_size_log2 = 0;
  spec.code_limit = 3;
  auto cd = CodeDirectory::deserialize(make_cd(spec));
  ASSERT_TRUE(cd);

  const uint8_t code[] = {'a', 'b', 'c'};
  ASSERT_EQ(cd->update_code_slots(code, sizeof(code)), ReturnCode::kOk);
  EXPECT_EQ(hash_table(cd->data()),
            from_hex("a9993e364706816aba3e25717850c26c9cd0d89d"));
}

TEST(CodeDirectoryUpdateCodeSlots, HashesEachPageAndKeepsSpecialSlots) {
  CdSpec spec;
  spec.code_slots = 2;
  spec.code_limit = 4096 + 10;  // the last page is short
  Bytes original = make_cd(spec);
  auto cd = CodeDirectory::deserialize(original);
  ASSERT_TRUE(cd);

  Bytes code(spec.code_limit);
  for (size_t i = 0; i < code.size(); i++) code[i] = static_cast<Byte>(i * 7);
  ASSERT_EQ(cd->update_code_slots(code.data(), code.size()), ReturnCode::kOk);

  Bytes expected(original.begin() + get_be32(original, kCdHashOffset) - 64,
                 original.begin() + get_be32(original, kCdHashOffset));
  for (size_t page_start : {size_t{0}, size_t{4096}}) {
    size_t length = std::min<size_t>(4096, code.size() - page_start);
    auto digest =
        compute_digest(HashType::kSha256, code.data() + page_start, length);
    ASSERT_TRUE(digest);
    expected.insert(expected.end(), digest->begin(), digest->end());
  }
  EXPECT_EQ(hash_table(cd->data()), expected);
}

TEST(CodeDirectoryUpdateCodeSlots, RejectsWrongCodeSize) {
  auto cd = CodeDirectory::deserialize(make_cd({}));
  ASSERT_TRUE(cd);
  Bytes before = cd->data();
  Bytes code(3 * 4096 - 1);
  EXPECT_EQ(cd->update_code_slots(code.data(), code.size()),
            ReturnCode::kErrCommon);
  EXPECT_EQ(cd->data(), before);
}

TEST(CodeDirectoryUpdateCodeSlots, RejectsSlotCountNotMatchingPages) {
  CdSpec spec;
  spec.code_limit = 2 * 4096;  // 2 pages, but the CD has 3 code slots
  auto cd = CodeDirectory::deserialize(make_cd(spec));
  ASSERT_TRUE(cd);
  Bytes code(spec.code_limit);
  EXPECT_EQ(cd->update_code_slots(code.data(), code.size()),
            ReturnCode::kErrCommon);
}

TEST(CodeDirectoryUpdateCodeSlots, RejectsOverwritingStringTerminator) {
  // The Team ID's NUL is the last byte of the only code slot, and
  // SHA-256("abc") ends in 0xad
  CdSpec spec;
  spec.special_slots = 0;
  spec.code_slots = 1;
  spec.page_size_log2 = 0;
  spec.code_limit = 3;
  Bytes bytes = make_cd(spec);
  uint32_t team_offset = get_be32(bytes, kCdHashOffset) + 31;
  put_be32(bytes, kCdTeamOffset, team_offset);
  bytes[team_offset] = 0;
  auto cd = CodeDirectory::deserialize(bytes);
  ASSERT_TRUE(cd);

  const uint8_t code[] = {'a', 'b', 'c'};
  EXPECT_EQ(cd->update_code_slots(code, sizeof(code)), ReturnCode::kErrCommon);
  EXPECT_EQ(cd->data(), bytes);
}

Bytes make_blob(uint32_t magic, size_t size, Byte fill) {
  Bytes blob(size, fill);
  write_be32(blob.data(), magic);
  write_be32(blob.data() + 4, static_cast<uint32_t>(size));
  return blob;
}

Bytes make_superblob(const std::vector<std::pair<SlotType, Bytes>>& blobs) {
  size_t offset = 12 + 8 * blobs.size();
  Bytes data(offset);
  write_be32(data.data(),
             static_cast<uint32_t>(BlobMagic::kEmbeddedSignature));
  write_be32(data.data() + 8, static_cast<uint32_t>(blobs.size()));
  for (size_t i = 0; i < blobs.size(); i++) {
    write_be32(data.data() + 12 + 8 * i,
               static_cast<uint32_t>(blobs[i].first));
    write_be32(data.data() + 16 + 8 * i, static_cast<uint32_t>(data.size()));
    data.insert(data.end(), blobs[i].second.begin(), blobs[i].second.end());
  }
  write_be32(data.data() + 4, static_cast<uint32_t>(data.size()));
  return data;
}

TEST(SuperBlob, DeserializeThenSerializeRoundTrips) {
  Bytes cd = make_cd({});
  Bytes signature =
      make_blob(static_cast<uint32_t>(BlobMagic::kBlobWrapper), 16, 0xee);
  Bytes data = make_superblob(
      {{SlotType::kCodeDirectory, cd}, {SlotType::kSignature, signature}});

  auto superblob = SuperBlob::deserialize(data);
  ASSERT_TRUE(superblob);
  EXPECT_EQ(superblob->serialize(), data);

  const Blob* found = superblob->find_blob(SlotType::kCodeDirectory);
  ASSERT_NE(found, nullptr);
  EXPECT_EQ(found->data, cd);
  EXPECT_EQ(superblob->find_blob(SlotType::kEntitlements), nullptr);
}

TEST(SuperBlob, RemoveBlobDropsItFromIndex) {
  Bytes cd = make_cd({});
  Bytes signature =
      make_blob(static_cast<uint32_t>(BlobMagic::kBlobWrapper), 16, 0xee);
  auto superblob = SuperBlob::deserialize(make_superblob(
      {{SlotType::kCodeDirectory, cd}, {SlotType::kSignature, signature}}));
  ASSERT_TRUE(superblob);

  EXPECT_EQ(superblob->remove_blob(SlotType::kSignature), ReturnCode::kOk);
  EXPECT_EQ(superblob->find_blob(SlotType::kSignature), nullptr);
  EXPECT_EQ(superblob->remove_blob(SlotType::kSignature),
            ReturnCode::kErrCommon);
  EXPECT_EQ(superblob->serialize(),
            make_superblob({{SlotType::kCodeDirectory, cd}}));
}

TEST(SuperBlob, RejectsMalformed) {
  Bytes blob =
      make_blob(static_cast<uint32_t>(BlobMagic::kBlobWrapper), 16, 0xee);
  Bytes valid = make_superblob({{SlotType::kSignature, blob}});

  Bytes wrong_magic = valid;
  wrong_magic[3] ^= 0xff;
  EXPECT_FALSE(SuperBlob::deserialize(wrong_magic));

  Bytes too_many_entries = valid;
  put_be32(too_many_entries, 8, 100);
  EXPECT_FALSE(SuperBlob::deserialize(too_many_entries));

  Bytes offset_past_end = valid;
  put_be32(offset_past_end, 16, static_cast<uint32_t>(valid.size()));
  EXPECT_FALSE(SuperBlob::deserialize(offset_past_end));

  Bytes blob_past_end = valid;
  put_be32(blob_past_end, 20 + 4, 17);
  EXPECT_FALSE(SuperBlob::deserialize(blob_past_end));

  EXPECT_FALSE(SuperBlob::deserialize(Bytes(4, 0)));
}

}  // namespace
}  // namespace macho
}  // namespace ct_bypass
