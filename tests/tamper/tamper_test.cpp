// Модель атакующего для этапа 1 (§57): изменение полей объекта и kem.ct.
// Глобального контроля (Merkle) ещё нет, поэтому порча ловится при extract
// через AES-KW / AES-GCM, и plaintext наружу не выдаётся.
#include <gtest/gtest.h>

#include "vault/common/error.hpp"
#include "vault/encoding/encrypted_file.hpp"
#include "../integration/test_util.hpp"

using namespace vault;
using namespace vault::testing;

namespace {
struct Field { const char* name; std::size_t offset; };
}

class TamperTest : public VaultFixture {
protected:
    void SetUp() override {
        VaultFixture::SetUp();
        Vault::init(paths(), backends());
        Vault v = Vault::open(paths(), backends());
        id = v.add_bytes("secret.txt", Bytes(64, 0x5A));
        size = slurp(object_path(id)).size();
    }
    void expect_extract_fails(ErrorCode code) {
        Vault v = Vault::open(paths(), backends());
        try {
            v.extract(id);
            FAIL() << "plaintext was returned from a tampered vault";
        } catch (const VaultError& e) {
            EXPECT_EQ(e.code(), code) << e.what();
        }
    }
    void flip(std::size_t off, std::uint8_t mask) {
        Bytes b = slurp(object_path(id));
        b.at(off) ^= mask;
        spit(object_path(id), b);
    }
    FileId id{};
    std::size_t size = 0;
};

TEST_F(TamperTest, NonceBitFlip) {
    for (std::size_t i = 0; i < kNonceSize; ++i) {
        flip(40 + i, 0x01);
        expect_extract_fails(ErrorCode::AuthenticationFailed);
        flip(40 + i, 0x01);  // вернуть
    }
    Vault v = Vault::open(paths(), backends());
    EXPECT_NO_THROW(v.extract(id));
}

TEST_F(TamperTest, WrappedDekBitFlip) {
    for (std::size_t i = 0; i < kWrappedDekSize; ++i) {
        flip(52 + i, 0x80);
        expect_extract_fails(ErrorCode::AuthenticationFailed);
        flip(52 + i, 0x80);
    }
}

TEST_F(TamperTest, CiphertextBitFlip) {
    std::size_t ct_len = size - kEncryptedFileFixedOverhead;
    for (std::size_t i = 0; i < ct_len; i += 7) {
        flip(100 + i, 0x01);
        expect_extract_fails(ErrorCode::AuthenticationFailed);
        flip(100 + i, 0x01);
    }
}

TEST_F(TamperTest, GcmTagBitFlip) {
    for (std::size_t i = 0; i < kGcmTagSize; ++i) {
        flip(size - kGcmTagSize + i, 0x01);
        expect_extract_fails(ErrorCode::AuthenticationFailed);
        flip(size - kGcmTagSize + i, 0x01);
    }
}

TEST_F(TamperTest, KemCiphertextSubstitution) {
    // ML-KEM — implicit rejection: Decaps не падает, но KEK получается другим, и AES-KW unwrap отказывает.
    Bytes ct = slurp(vault_dir / "kem.ct");
    ct[10] ^= 1;
    spit(vault_dir / "kem.ct", ct);
    expect_extract_fails(ErrorCode::AuthenticationFailed);
}

TEST_F(TamperTest, ObjectFromAnotherVaultRejected) {
    // Объект, созданный в другом хранилище, подкладывается под тем же именем.
    std::filesystem::path other_root = root / "other";
    VaultPaths op{other_root / "vault", other_root / "trusted"};
    Vault::init(op, backends());
    Vault ov = Vault::open(op, backends());
    FileId oid = ov.add_bytes("x", Bytes(1, 1));
    Bytes foreign = slurp(other_root / "vault" / "objects" / (to_hex(as_view(oid)) + ".obj"));
    spit(vault_dir / "objects" / (to_hex(as_view(oid)) + ".obj"), foreign);
    try {
        Vault::open(paths(), backends());
        FAIL();
    } catch (const VerificationError& e) {
        EXPECT_EQ(e.step(), VerifyStep::ObjectBinding);
    }
}

TEST_F(TamperTest, RenamedObjectRejected) {
    FileId other{};
    other.fill(0xEE);
    std::filesystem::rename(object_path(id), object_path(other));
    try {
        Vault::open(paths(), backends());
        FAIL();
    } catch (const VerificationError& e) {
        EXPECT_EQ(e.step(), VerifyStep::ObjectNameMismatch);
    }
}

TEST_F(TamperTest, DuplicateFileIdUnderTwoNamesRejected) {
    // Копия объекта под чужим именем — не должна проходить как второй файл.
    FileId other{};
    other.fill(0xEE);
    std::filesystem::copy_file(object_path(id), object_path(other));
    EXPECT_THROW(Vault::open(paths(), backends()), VerificationError);
}

TEST_F(TamperTest, HeaderCorruptionRejectedAtOpen) {
    flip(3, 0x02);  // format_version
    try {
        Vault::open(paths(), backends());
        FAIL();
    } catch (const VerificationError& e) {
        EXPECT_EQ(e.step(), VerifyStep::ObjectParse);
    }
}

TEST_F(TamperTest, AadBindsFileId) {
    // Меняем file_id внутри объекта и имя файла согласованно: AAD не совпадёт -> GCM падает.
    Bytes b = slurp(object_path(id));
    FileId nid = id;
    nid[0] ^= 0xFF;
    std::copy(nid.begin(), nid.end(), b.begin() + 24);
    std::filesystem::remove(object_path(id));
    spit(object_path(nid), b);
    Vault v = Vault::open(paths(), backends());
    EXPECT_THROW(v.extract(nid), VaultError);
}
