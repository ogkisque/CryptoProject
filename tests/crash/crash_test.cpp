// Crash-тесты (§28-§29, §57): CLI завершается в заданной точке (VAULT_CRASH_POINT, код 86),
// после чего хранилище должно оставаться валидным и показывать либо старое, либо новое поколение.
// Проверяется состояние на уровне процесса; потерю питания (fsync каталога) такие тесты не моделируют.
#include <gtest/gtest.h>
#include <sys/wait.h>

#include <cstdlib>
#include <sstream>

#include "vault/storage/crash_injection.hpp"
#include "vault/storage/storage_backend.hpp"
#include "../integration/test_util.hpp"

using namespace vault;
using namespace vault::testing;
namespace fs = std::filesystem;

class CrashTest : public VaultFixture {
protected:
    void SetUp() override {
        VaultFixture::SetUp();
        ASSERT_EQ(run("init"), 0);
        spit(root / "in.txt", Bytes(100, 7));
        ASSERT_EQ(run("add in.txt"), 0);
        existing = text("out.txt").substr(0, 32);  // поколение 1, один файл
    }
    int run(const std::string& args, const char* crash_point = nullptr) {
        std::string env = crash_point ? std::string("VAULT_CRASH_POINT=") + crash_point + " " : "";
        std::string cmd = "cd '" + root.string() + "' && " + env + "'" VAULT_CLI_PATH "' --vault vault --trusted trusted " +
                          args + " >out.txt 2>err.txt";
        int st = std::system(cmd.c_str());
        return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    }
    std::string text(const std::string& name) {
        Bytes b = slurp(root / name);
        return std::string(b.begin(), b.end());
    }
    std::size_t listed() {
        EXPECT_EQ(run("list"), 0);
        std::istringstream in(text("out.txt"));
        std::size_t n = 0;
        for (std::string l; std::getline(in, l);) n += !l.empty();
        return n;
    }
    std::vector<std::uint64_t> generations() { return storage::make_generation_storage(vault_dir)->list_generations(); }
    std::vector<std::string> incomplete() { return storage::make_generation_storage(vault_dir)->list_incomplete_snapshots(); }

    std::string existing;
};

namespace {
using storage::CrashPoint;
struct Case {
    const char* point;
    bool committed;  // виден ли результат после crash
};
const Case kCases[] = {
    {"before-snapshot-write", false}, {"during-snapshot-write", false}, {"after-snapshot-fsync", false},
    {"before-trusted-update", false}, {"during-trusted-update", false}, {"after-trusted-update", true},
};
}  // namespace

TEST_F(CrashTest, AddCrashAtEveryPointKeepsVaultConsistent) {
    for (const Case& c : kCases) {
        SCOPED_TRACE(c.point);
        std::size_t before = listed();
        std::uint64_t gen_before = trusted_generation(trusted_dir);
        ASSERT_EQ(run("add in.txt", c.point), storage::kCrashExitCode);
        EXPECT_EQ(run("verify"), 0) << text("err.txt");
        EXPECT_EQ(text("out.txt"), "VALID\n");
        EXPECT_EQ(listed(), c.committed ? before + 1 : before);
        EXPECT_EQ(trusted_generation(trusted_dir), c.committed ? gen_before + 1 : gen_before);

        // После crash работа продолжается; GC убирает осиротевшее и ничего не ломает.
        ASSERT_EQ(run("gc"), 0);
        EXPECT_TRUE(incomplete().empty());
        EXPECT_EQ(generations(), (std::vector<std::uint64_t>{trusted_generation(trusted_dir)}));
        EXPECT_EQ(run("verify"), 0);
        EXPECT_EQ(text("err.txt"), "");  // без предупреждений
    }
}

TEST_F(CrashTest, RemoveCrashAtEveryPointKeepsVaultConsistent) {
    for (const Case& c : kCases) {
        SCOPED_TRACE(c.point);
        ASSERT_EQ(run("add in.txt"), 0);
        std::string victim = text("out.txt").substr(0, 32);
        std::size_t before = listed();
        ASSERT_EQ(run("remove " + victim, c.point), storage::kCrashExitCode);
        EXPECT_EQ(run("verify"), 0) << text("err.txt");
        EXPECT_EQ(listed(), c.committed ? before - 1 : before);
        ASSERT_EQ(run("gc"), 0);
        EXPECT_EQ(run("verify"), 0);
    }
}

TEST_F(CrashTest, OrphanAfterPublishIsReportedAndDoesNotBlockRetry) {
    std::uint64_t n = trusted_generation(trusted_dir);
    ASSERT_EQ(run("add in.txt", "before-trusted-update"), storage::kCrashExitCode);
    EXPECT_EQ(generations(), (std::vector<std::uint64_t>{0, n, n + 1}));  // N+1 опубликовано, но не подтверждено
    ASSERT_EQ(run("verify"), 0);
    EXPECT_NE(text("err.txt").find("warning"), std::string::npos);
    EXPECT_EQ(listed(), 1u);  // читается trusted поколение N, а не опубликованное N+1
    // Повтор операции: orphan N+1 заменяется настоящим.
    ASSERT_EQ(run("add in.txt"), 0);
    EXPECT_EQ(trusted_generation(trusted_dir), n + 1);
    EXPECT_EQ(listed(), 2u);
    EXPECT_EQ(run("verify"), 0);
}

TEST_F(CrashTest, IncompleteSnapshotIsReportedAndRemovedByGc) {
    ASSERT_EQ(run("add in.txt", "after-snapshot-fsync"), storage::kCrashExitCode);
    EXPECT_EQ(incomplete().size(), 1u);
    ASSERT_EQ(run("verify"), 0);
    EXPECT_NE(text("err.txt").find("incomplete"), std::string::npos);
    ASSERT_EQ(run("gc"), 0);
    EXPECT_TRUE(incomplete().empty());
}

TEST_F(CrashTest, TrustedUpdateRenameIsAtomicTruncatedTmpIsIgnored) {
    // Crash между записью tmp и rename оставляет trusted_state.bin.tmp; валиден ровно один файл.
    ASSERT_EQ(run("add in.txt", "during-trusted-update"), storage::kCrashExitCode);
    ASSERT_TRUE(fs::exists(trusted_dir / "trusted_state.bin.tmp"));
    EXPECT_EQ(run("verify"), 0);
    // Усечённый tmp (сбой посреди записи) не мешает: читается trusted_state.bin.
    Bytes tmp = slurp(trusted_dir / "trusted_state.bin.tmp");
    tmp.resize(tmp.size() / 2);
    spit(trusted_dir / "trusted_state.bin.tmp", tmp);
    EXPECT_EQ(run("verify"), 0);
    // Следующий commit перезаписывает остаток.
    ASSERT_EQ(run("add in.txt"), 0);
    EXPECT_FALSE(fs::exists(trusted_dir / "trusted_state.bin.tmp"));
    EXPECT_EQ(run("verify"), 0);
}

TEST_F(CrashTest, InitCrashLeavesNoValidVaultAndRetryIsExplained) {
    // Моделируем убитый init: vault/ создан, trusted/ нет.
    std::string cmd = "cd '" + root.string() + "' && '" VAULT_CLI_PATH "' --vault v2 --trusted t2 init >/dev/null 2>&1";
    ASSERT_EQ(std::system(cmd.c_str()), 0);
    fs::remove_all(root / "t2");
    cmd = "cd '" + root.string() + "' && '" VAULT_CLI_PATH "' --vault v2 --trusted t2 init >/dev/null 2>err2.txt";
    EXPECT_NE(std::system(cmd.c_str()), 0);
    EXPECT_NE(text("err2.txt").find("incomplete initialization"), std::string::npos);
}
