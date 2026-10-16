#pragma once
// Константы формата v1 и crypto suite 1. Единственный источник истины для
// размеров полей, domain-separation префиксов и строковых меток.
// Подробности: docs/format_v1.md, crypto_project.md §1-§24.

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace vault {

inline constexpr std::uint32_t kFormatVersionV1 = 1;
inline constexpr std::uint32_t kCryptoSuiteV1 = 1;  // AES-256-GCM, AES-256-KW, ML-KEM-768,
                                                    // HKDF-SHA3-256, SHA3-256, ML-DSA-65

// --- размеры (байты) ---
inline constexpr std::size_t kStorageUuidSize = 16;
inline constexpr std::size_t kFileIdSize = 16;
inline constexpr std::size_t kHashSize = 32;  // SHA3-256
inline constexpr std::size_t kNonceSize = 12;  // AES-GCM, 96 bit
inline constexpr std::size_t kGcmTagSize = 16;  // 128 bit
inline constexpr std::size_t kDekSize = 32;
inline constexpr std::size_t kKekSize = 32;
inline constexpr std::size_t kWrappedDekSize = 40;  // AES-KW(32 bytes) = 32 + 8

// ML-KEM-768 (FIPS 203)
inline constexpr std::size_t kMlKem768PublicKeySize = 1184;
inline constexpr std::size_t kMlKem768SecretKeySize = 2400;
inline constexpr std::size_t kMlKem768CiphertextSize = 1088;
inline constexpr std::size_t kMlKem768SharedSecretSize = 32;
inline constexpr std::size_t kMlKem768KeygenSeedSize = 64;  // d || z
inline constexpr std::size_t kMlKem768EncapsSeedSize = 32;  // m

// ML-DSA-65 (FIPS 204)
inline constexpr std::size_t kMlDsa65PublicKeySize = 1952;
inline constexpr std::size_t kMlDsa65SecretKeySize = 4032;
inline constexpr std::size_t kMlDsa65SignatureSize = 3309;
inline constexpr std::size_t kMlDsa65KeygenSeedSize = 32;  // xi
inline constexpr std::size_t kMlDsa65SignRandSize = 32;  // rnd (hedged), 0^32 = deterministic
inline constexpr std::size_t kMlDsaMaxContextSize = 255;

// --- размеры канонических структур ---
// EncryptedFileV1 без ciphertext: u32+u32+16+16+12+40+u64 = 100, плюс tag 16
inline constexpr std::size_t kEncryptedFileHeaderSize = 4 + 4 + 16 + 16 + 12 + 40 + 8;
inline constexpr std::size_t kEncryptedFileFixedOverhead = kEncryptedFileHeaderSize + kGcmTagSize;
// ManifestV1: u32+u32+16+u64+u64+4*32 = 168
inline constexpr std::size_t kManifestV1Size = 4 + 4 + 16 + 8 + 8 + 4 * 32;
// TrustedStateV1 (локальный формат доверенной области): u32+u32+16+u64+32 = 64
inline constexpr std::size_t kTrustedStateV1Size = 4 + 4 + 16 + 8 + 32;

// --- политика реализации (не из спецификации, а ограничения прототипа) ---
inline constexpr std::uint32_t kMaxFilenameLength = 4096;

// --- domain separation для SHA3-256 (§16) ---
namespace domain {
inline constexpr std::uint8_t kMerkleLeaf = 0x00;
inline constexpr std::uint8_t kMerkleParent = 0x01;
inline constexpr std::uint8_t kMerkleUnpaired = 0x02;
inline constexpr std::uint8_t kMerkleEmpty = 0x03;
inline constexpr std::uint8_t kManifestHash = 0x10;
inline constexpr std::uint8_t kKemCtHash = 0x11;
inline constexpr std::uint8_t kKemKeyId = 0x12;
inline constexpr std::uint8_t kSigKeyId = 0x13;
}  // namespace domain

// --- строковые метки (ASCII, кодируются как сырые байты без длины и без '\0':
//     все они — фиксированные константы известной длины) ---
namespace label {
inline constexpr std::string_view kFileAad = "edu-vault-file-v1";
inline constexpr std::string_view kKekInfo = "edu-vault-kek-v1";
inline constexpr std::string_view kManifestSigContext = "edu-vault-manifest-v1";
inline constexpr std::string_view kEmptyTree = "edu-vault-empty-tree-v1";
}  // namespace label

}  // namespace vault
