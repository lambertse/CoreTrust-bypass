#include "macho/digest.h"

#include <gtest/gtest.h>

#include <optional>
#include <string>

namespace ct_bypass::macho {
namespace {

Bytes from_hex(const std::string& hex) {
  Bytes bytes;
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    bytes.push_back(
        static_cast<Byte>(std::stoul(hex.substr(i, 2), nullptr, 16)));
  }
  return bytes;
}

std::optional<Bytes> digest_of(HashType type, const std::string& text) {
  return compute_digest(type, reinterpret_cast<const uint8_t*>(text.data()),
                        text.size());
}

TEST(DigestSize, MatchesEachHashType) {
  EXPECT_EQ(digest_size(HashType::kSha1), 20u);
  EXPECT_EQ(digest_size(HashType::kSha256), 32u);
  EXPECT_EQ(digest_size(HashType::kSha256Truncated), 20u);
  EXPECT_EQ(digest_size(HashType::kSha384), 48u);
}

TEST(DigestSize, IsZeroForUnknownHashType) {
  EXPECT_EQ(digest_size(static_cast<HashType>(0)), 0u);
  EXPECT_EQ(digest_size(static_cast<HashType>(5)), 0u);
}

TEST(ComputeDigest, Sha1KnownAnswer) {
  EXPECT_EQ(digest_of(HashType::kSha1, "abc"),
            from_hex("a9993e364706816aba3e25717850c26c9cd0d89d"));
}

TEST(ComputeDigest, Sha256KnownAnswer) {
  EXPECT_EQ(digest_of(HashType::kSha256, "abc"),
            from_hex("ba7816bf8f01cfea414140de5dae2223"
                     "b00361a396177a9cb410ff61f20015ad"));
}

TEST(ComputeDigest, Sha384KnownAnswer) {
  EXPECT_EQ(digest_of(HashType::kSha384, "abc"),
            from_hex("cb00753f45a35e8bb5a03d699ac65007"
                     "272c32ab0eded1631a8b605a43ff5bed"
                     "8086072ba1e7cc2358baeca134c825a7"));
}

TEST(ComputeDigest, TruncatedSha256IsPrefixOfSha256) {
  auto full = digest_of(HashType::kSha256, "abc");
  auto truncated = digest_of(HashType::kSha256Truncated, "abc");
  ASSERT_TRUE(full);
  ASSERT_TRUE(truncated);
  EXPECT_EQ(*truncated, Bytes(full->begin(), full->begin() + 20));
}

TEST(ComputeDigest, HashesEmptyInput) {
  EXPECT_EQ(compute_digest(HashType::kSha256, nullptr, 0),
            from_hex("e3b0c44298fc1c149afbf4c8996fb924"
                     "27ae41e4649b934ca495991b7852b855"));
}

TEST(ComputeDigest, ReturnsNulloptForUnknownHashType) {
  EXPECT_EQ(digest_of(static_cast<HashType>(0), "abc"), std::nullopt);
  EXPECT_EQ(digest_of(static_cast<HashType>(5), "abc"), std::nullopt);
}

}  // namespace
}  // namespace ct_bypass::macho
