#pragma once
// ManifestV1 (§22) — фиксированные 168 байт, полей переменной длины нет.
// Используется с Milestone 2.

#include <cstdint>

#include "vault/common/bytes.hpp"

namespace vault::encoding {

struct ManifestV1 {
    std::uint32_t format_version = kFormatVersionV1;
    std::uint32_t crypto_suite_id = kCryptoSuiteV1;
    StorageUuid storage_uuid{};
    std::uint64_t generation = 0;
    std::uint64_t file_count = 0;
    Hash256 merkle_root{};
    Hash256 kem_ct_hash{};
    Hash256 kem_key_id{};
    Hash256 sig_key_id{};

    bool operator==(const ManifestV1&) const = default;
};

Bytes encode_manifest(const ManifestV1& m);
ManifestV1 decode_manifest(ByteView encoded);  // ровно kManifestV1Size байт

}  // namespace vault::encoding
