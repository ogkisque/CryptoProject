// Регрессия формата v1: C++ кодирование и хеши против независимой Python-реализации
// (tests/vectors/gen_format_vectors.py -> format_v1_vectors.txt). Изменение любого
// байта формата ломает этот тест.
#include <gtest/gtest.h>

#include <fstream>
#include <map>
#include <sstream>

#include "vault/crypto/cpu_backends.hpp"
#include "vault/crypto/domain_hash.hpp"
#include "vault/encoding/encrypted_file.hpp"
#include "vault/encoding/file_plaintext.hpp"
#include "vault/encoding/manifest.hpp"
#include "vault/encoding/trusted_state.hpp"
#include "vault/merkle/merkle.hpp"
#include "vault/vault/key_hierarchy.hpp"

using namespace vault;

namespace {

std::map<std::string, std::string> load() {
    std::ifstream in(std::string(VAULT_TEST_VECTORS_DIR) + "/format_v1_vectors.txt");
    EXPECT_TRUE(in.good());
    std::map<std::string, std::string> m;
    for (std::string name, hex; in >> name >> hex;) m[name] = hex;
    return m;
}

Bytes pattern(std::size_t n, std::uint8_t start) {
    Bytes b(n);
    for (std::size_t i = 0; i < n; ++i) b[i] = static_cast<std::uint8_t>(start + i);
    return b;
}

template <std::size_t N>
std::array<std::uint8_t, N> arr(std::uint8_t start) {
    std::array<std::uint8_t, N> a{};
    for (std::size_t i = 0; i < N; ++i) a[i] = static_cast<std::uint8_t>(start + i);
    return a;
}

class FormatVectors : public ::testing::Test {
protected:
    std::map<std::string, std::string> v = load();
    std::shared_ptr<crypto::IHashBackend> h = crypto::make_cpu_hash_backend(1);
    StorageUuid uuid = arr<16>(0x00);
    FileId file_id = arr<16>(0x10);
    Bytes kem_pk = pattern(1184, 0x01), sig_pk = pattern(1952, 0x02), kem_ct = pattern(1088, 0x03);

    encoding::EncryptedFileV1 object() const {
        encoding::EncryptedFileV1 o;
        o.storage_uuid = uuid;
        o.file_id = file_id;
        o.nonce = arr<12>(0x20);
        o.wrapped_dek = arr<40>(0x30);
        o.ciphertext = pattern(37, 0x60);
        o.gcm_tag = arr<16>(0x80);
        return o;
    }
    encoding::ManifestV1 manifest() const {
        encoding::ManifestV1 m;
        m.storage_uuid = uuid;
        m.generation = 7;
        m.file_count = 1;
        m.merkle_root = crypto::merkle_leaf(*h, encoding::encode_encrypted_file(object()));
        m.kem_ct_hash = crypto::kem_ct_hash(*h, kem_ct);
        m.kem_key_id = crypto::kem_key_id(*h, kem_pk);
        m.sig_key_id = crypto::sig_key_id(*h, sig_pk);
        return m;
    }
};

}  // namespace

TEST_F(FormatVectors, FilePlaintext) {
    Bytes data = {'h', 'e', 'l', 'l', 'o'};
    EXPECT_EQ(to_hex(encoding::encode_file_plaintext("файл.txt", data).view()), v.at("FILE_PLAINTEXT"));
}

TEST_F(FormatVectors, Aad) {
    EXPECT_EQ(to_hex(encoding::build_file_aad(1, 1, uuid, file_id)), v.at("AAD"));
}

TEST_F(FormatVectors, Kek) {
    EXPECT_EQ(to_hex(core::derive_kek(pattern(32, 0xA0), uuid, 1).view()), v.at("KEK"));
}

TEST_F(FormatVectors, EncryptedFileAndLeaf) {
    Bytes enc = encoding::encode_encrypted_file(object());
    EXPECT_EQ(to_hex(enc), v.at("ENCRYPTED_FILE"));
    EXPECT_EQ(to_hex(as_view(crypto::merkle_leaf(*h, enc))), v.at("LEAF"));
}

TEST_F(FormatVectors, HashesAndIds) {
    EXPECT_EQ(to_hex(as_view(crypto::merkle_empty_root(*h))), v.at("EMPTY_ROOT"));
    EXPECT_EQ(to_hex(as_view(crypto::kem_key_id(*h, kem_pk))), v.at("KEM_KEY_ID"));
    EXPECT_EQ(to_hex(as_view(crypto::sig_key_id(*h, sig_pk))), v.at("SIG_KEY_ID"));
    EXPECT_EQ(to_hex(as_view(crypto::kem_ct_hash(*h, kem_ct))), v.at("KEM_CT_HASH"));
}

TEST_F(FormatVectors, ManifestAndHash) {
    encoding::ManifestV1 m = manifest();
    EXPECT_EQ(to_hex(encoding::encode_manifest(m)), v.at("MANIFEST"));
    EXPECT_EQ(to_hex(as_view(crypto::manifest_hash(*h, m))), v.at("MANIFEST_HASH"));
    // Корень дерева из одного объекта через Merkle backend = leaf (решение M-1).
    auto merkle = merkle::make_reference_merkle(h);
    Hash256 leaf = crypto::merkle_leaf(*h, encoding::encode_encrypted_file(object()));
    EXPECT_EQ(merkle->root_from_leaves(std::span<const Hash256>(&leaf, 1), nullptr), m.merkle_root);
}

TEST_F(FormatVectors, TrustedState) {
    encoding::TrustedStateV1 s;
    s.storage_uuid = uuid;
    s.trusted_generation = 7;
    s.trusted_manifest_hash = crypto::manifest_hash(*h, manifest());
    EXPECT_EQ(to_hex(encoding::encode_trusted_state(s)), v.at("TRUSTED_STATE"));
}
