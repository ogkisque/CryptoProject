// Этап 3: immutable поколения, hardlink, GC, блокировка и параллельные транзакции.
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <map>

#include "vault/common/error.hpp"
#include "vault/storage/storage_backend.hpp"
#include "vault/storage/trusted_storage.hpp"
#include "vault/vault/commit.hpp"
#include "vault/vault/state_verifier.hpp"
#include "test_util.hpp"

using namespace vault;
using namespace vault::testing;
namespace fs = std::filesystem;


class GenerationTest : public VaultFixture {
protected:
    void SetUp() override {
        VaultFixture::SetUp();
        Vault::init(paths(), backends());
    }
    // путь -> содержимое для всех файлов каталога
    static std::map<std::string, Bytes> dump_dir(const fs::path& dir) {
        std::map<std::string, Bytes> out;
        for (const auto& e : fs::recursive_directory_iterator(dir))
            if (e.is_regular_file()) out[fs::relative(e.path(), dir).string()] = slurp(e.path());
        return out;
    }
    std::vector<std::uint64_t> generations() {
        return storage::make_generation_storage(vault_dir)->list_generations();
    }
};

TEST_F(GenerationTest, InitCreatesGenerationZero) {
    EXPECT_EQ(generations(), (std::vector<std::uint64_t>{0}));
    EXPECT_TRUE(fs::exists(generation_dir(vault_dir, 0) / "manifest.bin"));
    EXPECT_EQ(trusted_generation(trusted_dir), 0u);
    EXPECT_TRUE(fs::exists(vault_dir / "kem.ct"));
}

TEST_F(GenerationTest, EveryChangeCreatesNewGeneration) {
    Vault v = Vault::open(paths(), backends());
    FileId a = v.add_bytes("a", Bytes(5, 1));
    FileId b = v.add_bytes("b", Bytes(5, 2));
    v.remove(a);
    EXPECT_EQ(generations(), (std::vector<std::uint64_t>{0, 1, 2, 3}));
    EXPECT_EQ(trusted_generation(trusted_dir), 3u);
    EXPECT_EQ(v.state().generation, 3u);
    EXPECT_EQ(v.state().manifest.generation, 3u);
    // Без повторной проверки с диска состояние в памяти равно проверенному состоянию на диске.
    core::VerifyReport r = Vault::verify_state(paths(), backends());
    EXPECT_EQ(r.state.manifest_hash, v.state().manifest_hash);
    EXPECT_EQ(r.state.leaves, v.state().leaves);
    ASSERT_EQ(r.state.objects.size(), 1u);
    EXPECT_EQ(r.state.objects[0].file_id, b);
}

TEST_F(GenerationTest, RemoveDoesNotTouchPreviousGeneration) {
    Vault v = Vault::open(paths(), backends());
    FileId a = v.add_bytes("a", Bytes(50, 1));
    v.add_bytes("b", Bytes(60, 2));
    auto before = dump_dir(generation_dir(vault_dir, 2));
    v.remove(a);
    auto after = dump_dir(generation_dir(vault_dir, 2));
    EXPECT_EQ(before, after);  // поколение N побайтно не изменилось
    EXPECT_EQ(dump_dir(generation_dir(vault_dir, 3)).size(), 3u);  // 1 объект + manifest.bin + manifest.sig
}

TEST_F(GenerationTest, UnchangedObjectsAreHardlinked) {
    Vault v = Vault::open(paths(), backends());
    FileId a = v.add_bytes("a", Bytes(50, 1));
    v.add_bytes("b", Bytes(60, 2));
    std::string name = to_hex(as_view(a)) + ".obj";
    fs::path in1 = generation_dir(vault_dir, 1) / "objects" / name;
    fs::path in2 = generation_dir(vault_dir, 2) / "objects" / name;
    EXPECT_TRUE(fs::equivalent(in1, in2));
    struct stat st{};
    ASSERT_EQ(::stat(in1.c_str(), &st), 0);
    EXPECT_EQ(st.st_nlink, 2u);
}

TEST_F(GenerationTest, GarbageCollectKeepsOnlyTrustedGeneration) {
    Vault v = Vault::open(paths(), backends());
    FileId a = v.add_bytes("a", Bytes(5, 1));
    v.add_bytes("b", Bytes(5, 2));
    fs::create_directories(vault_dir / "generations" / "0000000000000009.tmp" / "objects");
    EXPECT_EQ(v.garbage_collect(), 3u);  // 0, 1 и .tmp
    EXPECT_EQ(generations(), (std::vector<std::uint64_t>{2}));
    EXPECT_FALSE(fs::exists(vault_dir / "generations" / "0000000000000009.tmp"));
    EXPECT_NO_THROW(Vault::verify_state(paths(), backends()));
    EXPECT_EQ(v.garbage_collect(), 0u);
    // Хранилище работает после GC, объекты (hardlink) читаются.
    Vault v2 = Vault::open(paths(), backends());
    EXPECT_EQ(v2.extract(a).data.size(), 5u);
    v2.remove(a);
    EXPECT_EQ(generations(), (std::vector<std::uint64_t>{2, 3}));
}

TEST_F(GenerationTest, CommitNeverAutoCollectsOldGenerations) {
    Vault v = Vault::open(paths(), backends());
    for (int i = 0; i < 3; ++i) v.add_bytes("x", Bytes(1, 1));
    EXPECT_EQ(generations().size(), 4u);
}

TEST_F(GenerationTest, OrphanGenerationDoesNotBlockNextCommit) {
    Vault v = Vault::open(paths(), backends());
    v.add_bytes("a", Bytes(5, 1));
    // Остаток прерванного commit: опубликованное, но не подтверждённое поколение 2 и .tmp
    fs::copy(generation_dir(vault_dir, 1), generation_dir(vault_dir, 2), fs::copy_options::recursive);
    fs::create_directories(vault_dir / "generations" / "0000000000000002.tmp");
    EXPECT_NO_THROW(v.add_bytes("b", Bytes(5, 2)));
    EXPECT_EQ(trusted_generation(trusted_dir), 2u);
    EXPECT_NO_THROW(Vault::verify_state(paths(), backends()));
    EXPECT_TRUE(Vault::verify_state(paths(), backends()).warnings.empty());
}

TEST_F(GenerationTest, StaleHandleRefreshesStateBeforeCommit) {
    // Два открытых хэндла (два «процесса»): второй видит чужой commit и не теряет файл первого.
    Vault v1 = Vault::open(paths(), backends());
    Vault v2 = Vault::open(paths(), backends());
    FileId a = v1.add_bytes("a", Bytes(5, 1));
    FileId b = v2.add_bytes("b", Bytes(5, 2));
    EXPECT_EQ(trusted_generation(trusted_dir), 2u);
    Vault v3 = Vault::open(paths(), backends());
    EXPECT_EQ(v3.list(false).size(), 2u);
    EXPECT_NO_THROW(v3.extract(a));
    EXPECT_NO_THROW(v3.extract(b));
}

TEST_F(GenerationTest, ConcurrentCliAddsAreSerialized) {
    spit(root / "in.txt", Bytes(100, 7));
    std::string base = "cd '" + root.string() + "' && '" VAULT_CLI_PATH "' --vault vault --trusted trusted add in.txt";
    std::string cmd = "(";
    for (int i = 0; i < 8; ++i) cmd += base + " >/dev/null 2>&1 & ";
    cmd += "wait)";
    ASSERT_EQ(std::system(cmd.c_str()), 0);
    core::VerifyReport r = Vault::verify_state(paths(), backends());
    EXPECT_EQ(r.state.objects.size(), 8u);  // ни одно поколение N+1 не потеряно
    EXPECT_EQ(r.state.generation, 8u);
}

TEST_F(GenerationTest, WritesLeaveNoTmpArtifacts) {
    Vault v = Vault::open(paths(), backends());
    v.add_bytes("a", Bytes(5, 1));
    EXPECT_TRUE(storage::make_generation_storage(vault_dir)->list_incomplete_snapshots().empty());
    EXPECT_FALSE(fs::exists(trusted_dir / "trusted_state.bin.tmp"));
}

// Ревью этапа 3: commit со «старым» проверенным состоянием (другой процесс успел
// сделать commit после проверки) не должен трогать актуальное доверенное поколение.
// Раньше commit удалял «осиротевшие» поколения > N, включая текущее trusted N+1,
// и терял чужое изменение.
TEST_F(GenerationTest, CommitWithStaleVerifiedStateIsRefused) {
    auto b = backends();
    auto st = storage::make_generation_storage(vault_dir);
    auto tr = storage::make_file_trusted_storage(trusted_dir);
    core::VerifiedState stale = core::StateVerifier(b, *st, *tr).verify_current().state;  // поколение 0

    FileId other;
    {
        Vault v = Vault::open(paths(), backends());
        other = v.add_bytes("other.txt", Bytes(5, 1));  // поколение 1 от «другого процесса»
    }
    ASSERT_EQ(trusted_generation(trusted_dir), 1u);

    core::ChangeSet cs;
    cs.removed = {};
    EXPECT_THROW(core::CommitProtocol(b, *st, *tr).commit(stale, cs), VaultError);
    EXPECT_EQ(stale.generation, 0u);  // при ошибке current не меняется

    // Чужое изменение на месте, хранилище валидно.
    EXPECT_EQ(trusted_generation(trusted_dir), 1u);
    Vault v = Vault::open(paths(), backends());
    ASSERT_EQ(v.list(false).size(), 1u);
    EXPECT_EQ(v.list(false)[0].file_id, other);
}

// Отчёт верификатора несёт ровно тот TrustedState, по которому шла проверка.
TEST_F(GenerationTest, VerifyReportCarriesTrustedStateItChecked) {
    auto b = backends();
    auto st = storage::make_generation_storage(vault_dir);
    auto tr = storage::make_file_trusted_storage(trusted_dir);
    core::VerifyReport r = core::StateVerifier(b, *st, *tr).verify_current();
    EXPECT_EQ(r.trusted_state.trusted_generation, r.state.generation);
    EXPECT_EQ(r.trusted_state.trusted_manifest_hash, r.state.manifest_hash);
}
