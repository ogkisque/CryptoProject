// Этап 3: rollback и fork (§25-§26, §57). Ожидаемые шаги: Generation, ManifestHash.
#include <gtest/gtest.h>

#include "vault/common/error.hpp"
#include "vault/crypto/domain_hash.hpp"
#include "vault/encoding/manifest.hpp"
#include "vault/encoding/trusted_state.hpp"
#include "vault/merkle/merkle.hpp"
#include "../integration/test_util.hpp"

using namespace vault;
using namespace vault::testing;
namespace fs = std::filesystem;

class RollbackTest : public VaultFixture {
protected:
    void SetUp() override {
        VaultFixture::SetUp();
        Vault::init(paths(), backends());
        Vault v = Vault::open(paths(), backends());
        a = v.add_bytes("a", Bytes(10, 1));  // generation 1
        copy_vault(root / "snapshot_gen1");
        b = v.add_bytes("b", Bytes(20, 2));  // 2
        c = v.add_bytes("c", Bytes(30, 3));  // 3
    }
    void copy_vault(const fs::path& to) { fs::copy(vault_dir, to, fs::copy_options::recursive); }

    void expect_step(VerifyStep expected) {
        try {
            Vault::verify_state(paths(), backends());
            FAIL() << "state accepted";
        } catch (const VerificationError& e) {
            EXPECT_EQ(e.step(), expected) << e.what();
        }
        try {
            Vault::open(paths(), backends());
            FAIL() << "open accepted";
        } catch (const VerificationError& e) {
            EXPECT_EQ(e.step(), expected);
        }
    }
    FileId a{}, b{}, c{};
};

TEST_F(RollbackTest, WholeVaultRestoredFromOldCopy) {
    ASSERT_EQ(trusted_generation(trusted_dir), 3u);
    fs::remove_all(vault_dir);
    fs::copy(root / "snapshot_gen1", vault_dir, fs::copy_options::recursive);
    // Копия сама по себе внутренне непротиворечива и подписана верным ключом.
    expect_step(VerifyStep::Generation);
}

TEST_F(RollbackTest, OnlyGenerationsDirectoryReplaced) {
    fs::remove_all(vault_dir / "generations");
    fs::copy(root / "snapshot_gen1" / "generations", vault_dir / "generations", fs::copy_options::recursive);
    expect_step(VerifyStep::Generation);
}

TEST_F(RollbackTest, OldGenerationRenamedToTrustedNumber) {
    // Атакующий подкладывает поколение 1 под номером 3: manifest.generation != trusted_generation.
    fs::remove_all(generation_dir(vault_dir, 3));
    fs::remove_all(generation_dir(vault_dir, 2));
    fs::rename(generation_dir(vault_dir, 1), generation_dir(vault_dir, 3));
    expect_step(VerifyStep::Generation);
}

TEST_F(RollbackTest, TrustedGenerationDeletedIsRollback) {
    // Поколение 3 удалено, остались только старые: хранилище «откатилось».
    fs::remove_all(generation_dir(vault_dir, 3));
    expect_step(VerifyStep::Generation);
}

TEST_F(RollbackTest, NoGenerationsAtAll) {
    fs::remove_all(vault_dir / "generations");
    fs::create_directories(vault_dir / "generations");
    expect_step(VerifyStep::LoadSnapshot);
}

TEST_F(RollbackTest, ForkSameGenerationDifferentManifestDetected) {
    // Атакующий владеет SK_SIG (худший случай): второй, корректно подписанный Manifest того же
    // поколения с другим набором файлов и согласованными объектами. Сам по себе он валиден,
    // но его hash не совпадает с зафиксированным в trusted state.
    Vault v = Vault::open(paths(), backends());
    const auto& st = v.state();
    std::size_t idx = 0;
    while (st.objects[idx].file_id != b) ++idx;
    std::vector<Hash256> leaves = st.leaves;
    leaves.erase(leaves.begin() + idx);
    encoding::ManifestV1 m = st.manifest;
    m.file_count = leaves.size();
    m.merkle_root = backends().merkle->root_from_leaves(leaves, nullptr);
    Bytes enc = encoding::encode_manifest(m);
    Bytes sk = slurp(trusted_dir / "keys" / "sig.sk");
    fs::remove(object_path(b));
    spit(current_dir() / "manifest.bin", enc);
    spit(current_dir() / "manifest.sig", backends().sig->sign(sk, enc, label::kManifestSigContext, std::nullopt));
    expect_step(VerifyStep::ManifestHash);
}

TEST_F(RollbackTest, ReplayOfOldManifestIntoCurrentGenerationDetected) {
    // Manifest поколения 1 (валидная подпись) подложен в каталог поколения 3.
    fs::copy_file(generation_dir(root / "snapshot_gen1", 1) / "manifest.bin", current_dir() / "manifest.bin",
                  fs::copy_options::overwrite_existing);
    fs::copy_file(generation_dir(root / "snapshot_gen1", 1) / "manifest.sig", current_dir() / "manifest.sig",
                  fs::copy_options::overwrite_existing);
    expect_step(VerifyStep::Generation);
}

TEST_F(RollbackTest, UnconfirmedNewerGenerationIsOnlyAWarning) {
    // Опубликованное, но не подтверждённое trusted state поколение (crash между publish и update).
    fs::copy(generation_dir(vault_dir, 3), generation_dir(vault_dir, 4), fs::copy_options::recursive);
    core::VerifyReport r = Vault::verify_state(paths(), backends());
    EXPECT_EQ(r.state.generation, 3u);
    ASSERT_EQ(r.warnings.size(), 1u);
    // Orphan не влияет на содержимое: читается именно trusted_generation.
    Vault v = Vault::open(paths(), backends());
    EXPECT_EQ(v.list(false).size(), 3u);
    EXPECT_EQ(v.garbage_collect(), 4u);  // 0, 1, 2 и orphan 4
    EXPECT_TRUE(Vault::verify_state(paths(), backends()).warnings.empty());
}

TEST_F(RollbackTest, TrustedStateTamperingIsOutsideThreatModelButFailsClosed) {
    // Усечённый trusted_state.bin -> LoadTrustedState, а не молчаливый успех.
    Bytes ts = slurp(trusted_dir / "trusted_state.bin");
    ts.pop_back();
    spit(trusted_dir / "trusted_state.bin", ts);
    try {
        Vault::verify_state(paths(), backends());
        FAIL();
    } catch (const VerificationError& e) {
        EXPECT_EQ(e.step(), VerifyStep::LoadTrustedState);
    }
}
