// Сквозные тесты бинарника vault: коды возврата и поведение extract.
#include <gtest/gtest.h>
#include <sys/wait.h>

#include <cstdlib>

#include "test_util.hpp"

using namespace vault;
using namespace vault::testing;

class CliTest : public VaultFixture {
protected:
    int run(const std::string& args) {
        std::string cmd = "cd '" + root.string() + "' && '" VAULT_CLI_PATH "' --vault vault --trusted trusted " +
                          args + " >out.txt 2>err.txt";
        int st = std::system(cmd.c_str());
        return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    }
    std::string read_text(const std::string& name) {
        Bytes b = slurp(root / name);
        return std::string(b.begin(), b.end());
    }
};

TEST_F(CliTest, CycleAndExitCodes) {
    ASSERT_EQ(run("init"), 0);
    EXPECT_EQ(run("init"), 1);  // уже существует
    spit(root / "in.txt", Bytes{'d', 'a', 't', 'a'});
    ASSERT_EQ(run("add in.txt"), 0);
    std::string id = read_text("out.txt").substr(0, 32);
    ASSERT_EQ(run("extract " + id + " -o res.bin"), 0);
    EXPECT_EQ(slurp(root / "res.bin"), (Bytes{'d', 'a', 't', 'a'}));
    EXPECT_EQ(run("extract " + id + " -o res.bin"), 1);  // не перезаписывает без --force
    EXPECT_EQ(run("extract " + id + " -o res.bin --force"), 0);
    EXPECT_EQ(run("verify"), 0);
    EXPECT_EQ(run("extract nothex"), 1);
    EXPECT_EQ(run("remove " + id), 0);
    EXPECT_EQ(run("remove " + id), 1);  // NotFound
}

TEST_F(CliTest, AuthFailureGivesCode2AndNoOutputFile) {
    ASSERT_EQ(run("init"), 0);
    FileId id;
    {
        Vault v = Vault::open(paths(), backends());
        id = v.add_bytes("x.txt", Bytes(32, 7));
    }
    Bytes obj = slurp(object_path(id));
    obj.back() ^= 1;  // gcm_tag
    spit(object_path(id), obj);
    EXPECT_EQ(run("extract " + to_hex(as_view(id)) + " -o leaked.bin"), 2);
    EXPECT_FALSE(std::filesystem::exists(root / "leaked.bin"));
}

TEST_F(CliTest, VerificationFailureGivesCode2) {
    ASSERT_EQ(run("init"), 0);
    spit(vault_dir / "kem.ct", Bytes(10, 0));
    EXPECT_EQ(run("verify"), 2);
    EXPECT_NE(read_text("err.txt").find("INVALID: LoadSnapshot"), std::string::npos);
}

TEST_F(CliTest, VerifyPrintsValidAndVerboseDetails) {
    ASSERT_EQ(run("init"), 0);
    spit(root / "in.txt", Bytes{'x'});
    ASSERT_EQ(run("add in.txt"), 0);
    ASSERT_EQ(run("verify"), 0);
    EXPECT_EQ(read_text("out.txt"), "VALID\n");
    ASSERT_EQ(run("-v verify"), 0);
    EXPECT_NE(read_text("out.txt").find("merkle root"), std::string::npos);
    EXPECT_NE(read_text("out.txt").find("VALID"), std::string::npos);
}

TEST_F(CliTest, EveryCommandRefusesTamperedState) {
    ASSERT_EQ(run("init"), 0);
    spit(root / "in.txt", Bytes{'x'});
    ASSERT_EQ(run("add in.txt"), 0);
    std::string id = read_text("out.txt").substr(0, 32);
    Bytes sig = slurp(current_dir() / "manifest.sig");
    sig[0] ^= 1;
    spit(current_dir() / "manifest.sig", sig);
    for (const char* cmd : {"verify", "list", "list --names", "add in.txt", "extract ID -o r.bin", "remove ID", "gc"}) {
        std::string c = cmd;
        if (auto pos = c.find("ID"); pos != std::string::npos) c.replace(pos, 2, id);
        EXPECT_EQ(run(c), 2) << cmd;
        EXPECT_NE(read_text("err.txt").find("INVALID: Signature"), std::string::npos) << cmd;
    }
    EXPECT_FALSE(std::filesystem::exists(root / "r.bin"));
}

TEST_F(CliTest, ExtractSanitizesStoredFilename) {
    ASSERT_EQ(run("init"), 0);
    FileId id;
    {
        Vault v = Vault::open(paths(), backends());
        id = v.add_bytes("../../evil.sh", Bytes{'x'});
    }
    std::filesystem::create_directories(root / "sub");
    std::string cmd = "cd '" + (root / "sub").string() + "' && '" VAULT_CLI_PATH "' --vault ../vault --trusted ../trusted extract " +
                      to_hex(as_view(id)) + " >/dev/null 2>&1";
    ASSERT_EQ(std::system(cmd.c_str()), 0);
    EXPECT_TRUE(std::filesystem::exists(root / "sub" / "evil.sh"));
    EXPECT_FALSE(std::filesystem::exists(root / "evil.sh"));
    EXPECT_FALSE(std::filesystem::exists(root.parent_path() / "evil.sh"));
}
