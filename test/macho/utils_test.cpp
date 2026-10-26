#include "macho/utils.h"

#include <gtest/gtest.h>

namespace ct_bypass::macho {
namespace {

TEST(ReadBe32, ReadsMostSignificantByteFirst) {
  const uint8_t bytes[] = {0xfa, 0xde, 0x0c, 0x02};
  EXPECT_EQ(read_be32(bytes), 0xfade0c02u);
}

TEST(ReadBe32, ReadsOnlyFourBytes) {
  const uint8_t bytes[] = {0x00, 0x00, 0x00, 0x01, 0xff};
  EXPECT_EQ(read_be32(bytes), 1u);
}

TEST(ReadBe64, ReadsMostSignificantByteFirst) {
  const uint8_t bytes[] = {0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
  EXPECT_EQ(read_be64(bytes), 0x8001020304050607u);
}

TEST(WriteBe32, WritesMostSignificantByteFirst) {
  uint8_t bytes[] = {0, 0, 0, 0, 0xaa};
  write_be32(bytes, 0x80fe0c02);
  EXPECT_EQ(bytes[0], 0x80);
  EXPECT_EQ(bytes[1], 0xfe);
  EXPECT_EQ(bytes[2], 0x0c);
  EXPECT_EQ(bytes[3], 0x02);
  EXPECT_EQ(bytes[4], 0xaa);
}

TEST(WriteBe32, RoundTripsThroughReadBe32) {
  for (uint32_t value : {0u, 1u, 0x7fffffffu, 0x80000000u, 0xffffffffu}) {
    uint8_t bytes[4] = {};
    write_be32(bytes, value);
    EXPECT_EQ(read_be32(bytes), value);
  }
}

}  // namespace
}  // namespace ct_bypass::macho
