#pragma once
// TrustedStateV1 (§4, §25-26) — содержимое доверенной области помимо ключей.
// Локальный формат (не часть недоверенного хранилища), но тоже канонический:
//   u32 format_version | u32 crypto_suite_id | 16 storage_uuid
//   | u64 trusted_generation | 32 trusted_manifest_hash
// Milestone 1: generation = 0, manifest_hash = 0^32 (не используются).

#include <cstdint>

#include "vault/common/bytes.hpp"

namespace vault::encoding {

struct TrustedStateV1 {
    std::uint32_t format_version = kFormatVersionV1;
    std::uint32_t crypto_suite_id = kCryptoSuiteV1;
    StorageUuid storage_uuid{};
    std::uint64_t trusted_generation = 0;
    Hash256 trusted_manifest_hash{};

    bool operator==(const TrustedStateV1&) const = default;
};

Bytes encode_trusted_state(const TrustedStateV1& s);
TrustedStateV1 decode_trusted_state(ByteView encoded);

}  // namespace vault::encoding
