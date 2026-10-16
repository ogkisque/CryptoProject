// Модель атакующего (§57), этап 2: недоверенное хранилище меняется произвольно.
// Каждая атака проверяет ОЖИДАЕМЫЙ VerifyStep, причём ошибка должна возникнуть уже при
// открытии/verify (до Decaps и расшифрования), а не при extract.
#include <gtest/gtest.h>

#include <atomic>
#include <set>

#include "vault/common/error.hpp"
#include "vault/crypto/domain_hash.hpp"
#include "vault/encoding/encrypted_file.hpp"
#include "vault/encoding/manifest.hpp"
#include "../integration/test_util.hpp"

using namespace vault;
using namespace vault::testing;

namespace {

// KEM-обёртка со счётчиком Decaps: доказывает, что при порче состояния секреты не трогаются.
class CountingKem final : public crypto::IKemBackend {
public:
    CountingKem(std::shared_ptr<crypto::IKemBackend> inner, std::shared_ptr<std::atomic<int>> n)
        : inner_(std::move(inner)), decaps_(std::move(n)) {}
    std::string_view name() const override { return "counting"; }
    crypto::KemKeyPair keygen(std::optional<ByteView> s) override { return inner_->keygen(s); }
    crypto::KemEncapsResult encaps(ByteView pk, std::optional<ByteView> m) override { return inner_->encaps(pk, m); }
    SecureBytes decaps(ByteView sk, ByteView ct) override {
        ++*decaps_;
        return inner_->decaps(sk, ct);
    }
    void keygen_batch(std::size_t c, std::optional<ByteView> s, crypto::KemBatch& o, TimingBreakdown* t) override {
        inner_->keygen_batch(c, s, o, t);
    }
    void encaps_batch(crypto::KemBatch& b, std::optional<ByteView> s, TimingBreakdown* t) override {
        inner_->encaps_batch(b, s, t);
    }
    void decaps_batch(crypto::KemBatch& b, TimingBreakdown* t) override {
        decaps_batch_calls++;
        inner_->decaps_batch(b, t);
    }
    int decaps_batch_calls = 0;

private:
    std::shared_ptr<crypto::IKemBackend> inner_;
    std::shared_ptr<std::atomic<int>> decaps_;
};

struct Outcome {
    bool threw = false;
    VerifyStep step{};
};

}  // namespace

class TamperTest : public VaultFixture {
protected:
    void SetUp() override {
        VaultFixture::SetUp();
        Vault::init(paths(), backends());
        Vault v = Vault::open(paths(), backends());
        a = v.add_bytes("a.txt", Bytes(64, 0x5A));
        b = v.add_bytes("b.txt", Bytes(100, 0x11));
        c = v.add_bytes("c.txt", Bytes(7, 0x77));
        ids = {a, b, c};
        std::sort(ids.begin(), ids.end());
        size_a = slurp(object_path(a)).size();
    }

    // Результат полной проверки без Decaps (то же, что делает `vault verify`).
    Outcome check() const {
        try {
            Vault::verify_state(paths(), backends());
            return {};
        } catch (const VerificationError& e) {
            return {true, e.step()};
        }
    }
    void expect_step(VerifyStep expected) const {
        Outcome o = check();
        ASSERT_TRUE(o.threw) << "tampered vault passed verification";
        EXPECT_EQ(o.step, expected) << to_string(o.step);
        // open() обязан отказать так же — и тоже до Decaps.
        auto n = std::make_shared<std::atomic<int>>(0);
        auto b2 = backends();
        b2.kem = std::make_shared<CountingKem>(b2.kem, n);
        try {
            Vault::open(paths(), b2);
            FAIL() << "open() accepted a tampered vault";
        } catch (const VerificationError& e) {
            EXPECT_EQ(e.step(), expected);
        }
        EXPECT_EQ(n->load(), 0) << "Decaps was called on a tampered vault";
    }
    void expect_step_in(const std::set<VerifyStep>& allowed, const std::string& what) const {
        Outcome o = check();
        ASSERT_TRUE(o.threw) << what << ": tampered vault passed verification";
        EXPECT_TRUE(allowed.count(o.step)) << what << ": unexpected step " << to_string(o.step);
    }

    std::filesystem::path manifest_path() const { return vault_dir / "manifest.bin"; }
    std::filesystem::path sig_path() const { return vault_dir / "manifest.sig"; }

    void flip_object(const FileId& id, std::size_t off, std::uint8_t mask) {
        Bytes bytes = slurp(object_path(id));
        bytes.at(off) ^= mask;
        spit(object_path(id), bytes);
    }
    void flip_file(const std::filesystem::path& p, std::size_t off, std::uint8_t mask) {
        Bytes bytes = slurp(p);
        bytes.at(off) ^= mask;
        spit(p, bytes);
    }

    // Подписывает manifest НАСТОЯЩИМ ключом хранилища (модель: проверка порядка шагов).
    void write_manifest_signed(const encoding::ManifestV1& m, const Bytes& sk) {
        Bytes enc = encoding::encode_manifest(m);
        auto sig = backends().sig;
        spit(manifest_path(), enc);
        spit(sig_path(), sig->sign(sk, enc, label::kManifestSigContext, std::nullopt));
    }
    Bytes real_sig_sk() const { return slurp(trusted_dir / "keys" / "sig.sk"); }
    encoding::ManifestV1 current_manifest() const { return encoding::decode_manifest(slurp(manifest_path())); }

    FileId a{}, b{}, c{};
    std::vector<FileId> ids;
    std::size_t size_a = 0;
};

TEST_F(TamperTest, UntamperedVaultIsValid) {
    EXPECT_FALSE(check().threw);
    Vault v = Vault::open(paths(), backends());
    EXPECT_EQ(v.state().objects.size(), 3u);
    EXPECT_EQ(v.state().manifest.file_count, 3u);
}

// --- объекты: ciphertext / tag / wrapped_DEK / nonce -> MerkleRoot на verify, не на extract ---

TEST_F(TamperTest, NonceBitFlipDetectedAtVerify) {
    for (std::size_t i = 0; i < kNonceSize; ++i) {
        flip_object(a, 40 + i, 0x01);
        expect_step(VerifyStep::MerkleRoot);
        flip_object(a, 40 + i, 0x01);
    }
    EXPECT_FALSE(check().threw);
}

TEST_F(TamperTest, WrappedDekBitFlipDetectedAtVerify) {
    for (std::size_t i = 0; i < kWrappedDekSize; ++i) {
        flip_object(a, 52 + i, 0x80);
        expect_step(VerifyStep::MerkleRoot);
        flip_object(a, 52 + i, 0x80);
    }
}

TEST_F(TamperTest, CiphertextBitFlipDetectedAtVerify) {
    std::size_t ct_len = size_a - kEncryptedFileFixedOverhead;
    for (std::size_t i = 0; i < ct_len; i += 7) {
        flip_object(a, 100 + i, 0x01);
        expect_step(VerifyStep::MerkleRoot);
        flip_object(a, 100 + i, 0x01);
    }
}

TEST_F(TamperTest, GcmTagBitFlipDetectedAtVerify) {
    for (std::size_t i = 0; i < kGcmTagSize; ++i) {
        flip_object(a, size_a - kGcmTagSize + i, 0x01);
        expect_step(VerifyStep::MerkleRoot);
        flip_object(a, size_a - kGcmTagSize + i, 0x01);
    }
}

TEST_F(TamperTest, HeaderCorruptionRejectedAtParse) {
    flip_object(a, 3, 0x02);  // format_version
    expect_step(VerifyStep::ObjectParse);
}

// --- состав объектов ---

TEST_F(TamperTest, DeletedObjectDetected) {
    std::filesystem::remove(object_path(b));
    expect_step(VerifyStep::FileCount);
}

TEST_F(TamperTest, AllObjectsDeletedDetected) {
    for (auto& id : ids) std::filesystem::remove(object_path(id));
    expect_step(VerifyStep::FileCount);
}

TEST_F(TamperTest, ObjectFromAnotherVaultRejected) {
    std::filesystem::path other_root = root / "other";
    VaultPaths op{other_root / "vault", other_root / "trusted"};
    Vault::init(op, backends());
    Vault ov = Vault::open(op, backends());
    FileId oid = ov.add_bytes("x", Bytes(1, 1));
    Bytes foreign = slurp(other_root / "vault" / "objects" / (to_hex(as_view(oid)) + ".obj"));
    spit(object_path(oid), foreign);
    expect_step(VerifyStep::ObjectBinding);
}

TEST_F(TamperTest, ForeignObjectWithForgedUuidRejected) {
    // Объект другого vault'а с подставленным storage_uuid этого vault'а: привязка проходит,
    // но file_count и Merkle root уже не сходятся с подписанным Manifest.
    std::filesystem::path other_root = root / "other";
    VaultPaths op{other_root / "vault", other_root / "trusted"};
    Vault::init(op, backends());
    Vault ov = Vault::open(op, backends());
    FileId oid = ov.add_bytes("x", Bytes(1, 1));
    Bytes foreign = slurp(other_root / "vault" / "objects" / (to_hex(as_view(oid)) + ".obj"));
    Bytes mine = slurp(object_path(a));
    std::copy(mine.begin() + 8, mine.begin() + 24, foreign.begin() + 8);  // storage_uuid
    spit(object_path(oid), foreign);
    expect_step(VerifyStep::FileCount);
}

TEST_F(TamperTest, ForgedExtraObjectReplacingOneKeepsCountButBreaksRoot) {
    // Удаляем b, вставляем копию a под новым file_id (имя и поле согласованы): count == 3.
    Bytes copy = slurp(object_path(a));
    FileId nid = a;
    nid[0] ^= 0xFF;
    std::copy(nid.begin(), nid.end(), copy.begin() + 24);
    std::filesystem::remove(object_path(b));
    spit(object_path(nid), copy);
    expect_step(VerifyStep::MerkleRoot);
}

TEST_F(TamperTest, SwapObjectContentsBetweenNames) {
    Bytes ba = slurp(object_path(a)), bb = slurp(object_path(b));
    spit(object_path(a), bb);
    spit(object_path(b), ba);
    expect_step(VerifyStep::ObjectNameMismatch);
}

TEST_F(TamperTest, ObjectReplacedByAnotherAndRenamed) {
    // b заменён копией a под именем b: имя != file_id внутри.
    spit(object_path(b), slurp(object_path(a)));
    expect_step(VerifyStep::ObjectNameMismatch);
}

TEST_F(TamperTest, RenamedObjectRejected) {
    FileId other{};
    other.fill(0xEE);
    std::filesystem::rename(object_path(a), object_path(other));
    expect_step(VerifyStep::ObjectNameMismatch);
}

TEST_F(TamperTest, DuplicateObjectUnderTwoNamesRejected) {
    FileId other{};
    other.fill(0xEE);
    std::filesystem::copy_file(object_path(a), object_path(other));
    expect_step_in({VerifyStep::ObjectNameMismatch, VerifyStep::DuplicateFileId, VerifyStep::FileCount}, "duplicate");
}

TEST_F(TamperTest, AadBindsFileId) {
    // file_id внутри объекта и имя файла изменены согласованно: подписанный Merkle root это ловит.
    Bytes bytes = slurp(object_path(a));
    FileId nid = a;
    nid[0] ^= 0xFF;
    std::copy(nid.begin(), nid.end(), bytes.begin() + 24);
    std::filesystem::remove(object_path(a));
    spit(object_path(nid), bytes);
    expect_step(VerifyStep::MerkleRoot);
}

// --- manifest.bin / manifest.sig ---

TEST_F(TamperTest, EveryManifestBitFlipDetected) {
    Bytes orig = slurp(manifest_path());
    ASSERT_EQ(orig.size(), kManifestV1Size);
    const std::set<VerifyStep> allowed = {VerifyStep::ManifestParse,        VerifyStep::FormatVersion,
                                          VerifyStep::CryptoSuite,          VerifyStep::StorageUuidMismatch,
                                          VerifyStep::KemKeyId,             VerifyStep::SigKeyId,
                                          VerifyStep::Signature};
    for (std::size_t byte = 0; byte < orig.size(); ++byte)
        for (int bit = 0; bit < 8; ++bit) {
            Bytes m = orig;
            m[byte] ^= static_cast<std::uint8_t>(1u << bit);
            spit(manifest_path(), m);
            expect_step_in(allowed, "manifest byte " + std::to_string(byte) + " bit " + std::to_string(bit));
        }
    spit(manifest_path(), orig);
    EXPECT_FALSE(check().threw);
}

TEST_F(TamperTest, ManifestWrongLengthRejected) {
    Bytes orig = slurp(manifest_path());
    Bytes longer = orig;
    longer.push_back(0);
    spit(manifest_path(), longer);
    expect_step(VerifyStep::ManifestParse);
    spit(manifest_path(), Bytes(orig.begin(), orig.end() - 1));
    expect_step(VerifyStep::ManifestParse);
    spit(manifest_path(), {});
    expect_step(VerifyStep::ManifestParse);
}

TEST_F(TamperTest, ManifestSignatureCorruptionDetected) {
    Bytes orig = slurp(sig_path());
    ASSERT_EQ(orig.size(), kMlDsa65SignatureSize);
    for (std::size_t i = 0; i < orig.size(); i += 29) {
        flip_file(sig_path(), i, 0x04);
        expect_step(VerifyStep::Signature);
        spit(sig_path(), orig);
    }
    flip_file(sig_path(), orig.size() - 1, 0x01);
    expect_step(VerifyStep::Signature);
}

TEST_F(TamperTest, ManifestSignatureWrongLengthRejected) {
    Bytes orig = slurp(sig_path());
    Bytes longer = orig;
    longer.push_back(0);
    spit(sig_path(), longer);
    expect_step(VerifyStep::Signature);
    spit(sig_path(), Bytes(orig.begin(), orig.end() - 1));
    expect_step(VerifyStep::Signature);
    spit(sig_path(), {});
    expect_step(VerifyStep::Signature);
    spit(sig_path(), Bytes(kMlDsa65SignatureSize, 0));
    expect_step(VerifyStep::Signature);
}

TEST_F(TamperTest, MissingManifestOrSignatureRejected) {
    Bytes m = slurp(manifest_path()), s = slurp(sig_path());
    std::filesystem::remove(manifest_path());
    expect_step(VerifyStep::LoadManifest);
    spit(manifest_path(), m);
    std::filesystem::remove(sig_path());
    expect_step(VerifyStep::LoadManifest);
    spit(sig_path(), s);
    EXPECT_FALSE(check().threw);
}

TEST_F(TamperTest, ManifestOfAnotherVaultRejected) {
    std::filesystem::path other_root = root / "other";
    VaultPaths op{other_root / "vault", other_root / "trusted"};
    Vault::init(op, backends());
    spit(manifest_path(), slurp(other_root / "vault" / "manifest.bin"));
    spit(sig_path(), slurp(other_root / "vault" / "manifest.sig"));
    expect_step(VerifyStep::StorageUuidMismatch);
}

TEST_F(TamperTest, ManifestAndSignatureFromAttackerKeyRejected) {
    // Атакующий строит согласованный Manifest (верные root/count/uuid/hash'и) и подписывает СВОИМ ключом.
    auto sig = backends().sig;
    crypto::SigKeyPair evil = sig->keygen(std::nullopt);
    auto hash = backends().hash;
    encoding::ManifestV1 m = current_manifest();

    // (a) sig_key_id указывает на ключ атакующего -> не совпадает с доверенным.
    encoding::ManifestV1 m1 = m;
    m1.sig_key_id = crypto::sig_key_id(*hash, evil.public_key);
    Bytes e1 = encoding::encode_manifest(m1);
    spit(manifest_path(), e1);
    spit(sig_path(), sig->sign(evil.secret_key.view(), e1, label::kManifestSigContext, std::nullopt));
    expect_step(VerifyStep::SigKeyId);

    // (b) sig_key_id остаётся доверенным, но подпись чужая -> Signature.
    Bytes e2 = encoding::encode_manifest(m);
    spit(manifest_path(), e2);
    spit(sig_path(), sig->sign(evil.secret_key.view(), e2, label::kManifestSigContext, std::nullopt));
    expect_step(VerifyStep::Signature);
}

TEST_F(TamperTest, SignatureWithWrongContextRejected) {
    Bytes e = slurp(manifest_path());
    spit(sig_path(), backends().sig->sign(real_sig_sk(), e, "edu-vault-manifest-v2", std::nullopt));
    expect_step(VerifyStep::Signature);
}

// --- порядок шагов: подписанные настоящим ключом, но внутренне противоречивые Manifest'ы ---

TEST_F(TamperTest, SignedManifestWithWrongFieldsFailsAtRespectiveStep) {
    Bytes sk = real_sig_sk();
    encoding::ManifestV1 good = current_manifest();
    auto with = [&](auto&& mutate) {
        encoding::ManifestV1 m = good;
        mutate(m);
        write_manifest_signed(m, sk);
    };
    with([](auto& m) { m.file_count += 1; });
    expect_step(VerifyStep::FileCount);
    with([](auto& m) { m.merkle_root[0] ^= 1; });
    expect_step(VerifyStep::MerkleRoot);
    with([](auto& m) { m.kem_ct_hash[0] ^= 1; });
    expect_step(VerifyStep::KemCtHash);
    with([](auto& m) { m.kem_key_id[0] ^= 1; });
    expect_step(VerifyStep::KemKeyId);
    with([](auto& m) { m.storage_uuid[0] ^= 1; });
    expect_step(VerifyStep::StorageUuidMismatch);
    with([](auto& m) { m.crypto_suite_id = 2; });
    expect_step(VerifyStep::CryptoSuite);
    with([](auto& m) { m.format_version = 2; });
    expect_step(VerifyStep::FormatVersion);
    write_manifest_signed(good, sk);
    EXPECT_FALSE(check().threw);
}

// --- kem.ct ---

TEST_F(TamperTest, KemCiphertextCorruptionDetectedBeforeDecaps) {
    // expect_step() дополнительно проверяет по мок-KEM, что Decaps не вызывался.
    for (std::size_t i : {0u, 10u, 500u, 1087u}) {
        flip_file(vault_dir / "kem.ct", i, 0x01);
        expect_step(VerifyStep::KemCtHash);
        flip_file(vault_dir / "kem.ct", i, 0x01);
    }
}

TEST_F(TamperTest, KemCiphertextWrongSizeRejected) {
    Bytes ct = slurp(vault_dir / "kem.ct");
    ct.pop_back();
    spit(vault_dir / "kem.ct", ct);
    expect_step(VerifyStep::LoadSnapshot);
}

TEST_F(TamperTest, ValidOpenCallsDecapsExactlyOnce) {
    auto n = std::make_shared<std::atomic<int>>(0);
    auto b2 = backends();
    b2.kem = std::make_shared<CountingKem>(b2.kem, n);
    Vault v = Vault::open(paths(), b2);
    EXPECT_EQ(n->load(), 1);
}

// --- прочее ---

TEST_F(TamperTest, StaleTmpFromCrashDoesNotBreakVault) {
    spit(vault_dir / (to_hex(as_view(a)) + ".obj.tmp"), Bytes(5, 0));
    Vault v = Vault::open(paths(), backends());
    EXPECT_NO_THROW(v.extract(a));
    EXPECT_NO_THROW(v.add_bytes("y", Bytes(3, 3)));
}

TEST_F(TamperTest, TamperedStateNeverYieldsPlaintext) {
    flip_object(a, 100, 0x01);
    EXPECT_THROW(Vault::open(paths(), backends()), VerificationError);
}

TEST_F(TamperTest, ChangesKeepManifestConsistent) {
    // add/remove пересобирают Merkle и подпись: состояние остаётся валидным.
    Vault v = Vault::open(paths(), backends());
    FileId d = v.add_bytes("d", Bytes(5, 5));
    EXPECT_FALSE(check().threw);
    v.remove(a);
    EXPECT_FALSE(check().threw);
    v.remove(d);
    v.remove(b);
    v.remove(c);
    EXPECT_FALSE(check().threw);
    Vault v2 = Vault::open(paths(), backends());
    EXPECT_EQ(v2.state().manifest.file_count, 0u);
}
