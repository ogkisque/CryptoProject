#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

#include "vault/common/error.hpp"
#include "vault/crypto/backends.hpp"
#include "vault/vault/vault.hpp"
#include "test_util.hpp"

using namespace vault;
using namespace vault::testing;

TEST_F(VaultFixture, FullCycle) {
    Vault::init(paths(), backends());
    Vault v = Vault::open(paths(), backends());
    EXPECT_TRUE(v.list(false).empty());

    Bytes data = {'h', 'e', 'l', 'l', 'o'};
    FileId id = v.add_bytes("hello.txt", data);
    auto list = v.list(true);
    ASSERT_EQ(list.size(), 1u);
    EXPECT_EQ(list[0].file_id, id);
    EXPECT_EQ(*list[0].filename, "hello.txt");
    EXPECT_EQ(list[0].ciphertext_size, 4u + 9u + 8u + 5u);

    ExtractedFile f = v.extract(id);
    EXPECT_EQ(f.filename, "hello.txt");
    EXPECT_EQ(Bytes(f.data.view().begin(), f.data.view().end()), data);

    // новое открытие видит те же данные
    Vault v2 = Vault::open(paths(), backends());
    EXPECT_EQ(v2.list(false).size(), 1u);
    EXPECT_EQ(v2.extract(id).filename, "hello.txt");

    v2.remove(id);
    EXPECT_TRUE(v2.list(false).empty());
    EXPECT_THROW(v2.extract(id), VaultError);
    EXPECT_THROW(v2.remove(id), VaultError);
    EXPECT_TRUE(Vault::open(paths(), backends()).list(false).empty());
}

TEST_F(VaultFixture, FilenameNotStoredInPlaintext) {
    Vault::init(paths(), backends());
    Vault v = Vault::open(paths(), backends());
    Bytes data(100, 'Z');
    v.add_bytes("super-secret-name.txt", data);
    for (const auto& e : std::filesystem::recursive_directory_iterator(vault_dir)) {
        EXPECT_EQ(e.path().filename().string().find("secret"), std::string::npos);
        if (!e.is_regular_file()) continue;
        std::ifstream in(e.path(), std::ios::binary);
        std::string content((std::istreambuf_iterator<char>(in)), {});
        EXPECT_EQ(content.find("super-secret-name"), std::string::npos);
        EXPECT_EQ(content.find("ZZZZZZZZ"), std::string::npos);
    }
}

TEST_F(VaultFixture, ManyFilesDistinctIdsAndWrappedKeys) {
    Vault::init(paths(), backends());
    Vault v = Vault::open(paths(), backends());
    std::set<FileId> ids;
    for (int i = 0; i < 20; ++i) ids.insert(v.add_bytes("f" + std::to_string(i), Bytes(i, 1)));
    EXPECT_EQ(ids.size(), 20u);
    std::set<WrappedDek> wraps;
    for (const auto& o : v.state().objects) wraps.insert(o.wrapped_dek);
    EXPECT_EQ(wraps.size(), 20u);  // у каждого объекта свой DEK
}

TEST_F(VaultFixture, EmptyFile) {
    Vault::init(paths(), backends());
    Vault v = Vault::open(paths(), backends());
    FileId id = v.add_bytes("empty", ByteView());
    EXPECT_EQ(v.extract(id).data.size(), 0u);
}

TEST_F(VaultFixture, InitRefusesExisting) {
    Vault::init(paths(), backends());
    EXPECT_THROW(Vault::init(paths(), backends()), VaultError);
}

TEST_F(VaultFixture, OpenWithoutInitFails) {
    EXPECT_THROW(Vault::open(paths(), backends()), VaultError);
}

TEST_F(VaultFixture, TrustedDirPermissions) {
    Vault::init(paths(), backends());
    namespace fs = std::filesystem;
    EXPECT_EQ(fs::status(trusted_dir).permissions() & (fs::perms::group_all | fs::perms::others_all), fs::perms::none);
    EXPECT_EQ(fs::status(trusted_dir / "keys" / "kem.sk").permissions() & (fs::perms::group_all | fs::perms::others_all),
              fs::perms::none);
}
