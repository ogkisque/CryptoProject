#pragma once
#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <random>
#include <set>

#include "vault/crypto/backends.hpp"
#include "vault/encoding/trusted_state.hpp"
#include "vault/vault/vault.hpp"

namespace vault::testing {

class VaultFixture : public ::testing::Test {
protected:
    void SetUp() override {
        std::random_device rd;
        root = std::filesystem::temp_directory_path() / ("vault_test_" + std::to_string(rd()) + std::to_string(rd()));
        std::filesystem::create_directories(root);
        vault_dir = root / "vault";
        trusted_dir = root / "trusted";
    }
    void TearDown() override { std::filesystem::remove_all(root); }

    VaultPaths paths() const { return {vault_dir, trusted_dir}; }
    crypto::CryptoBackends backends() const { return crypto::make_backends({}); }

    // Поколение из доверенной области (trusted_state.bin).
    static std::uint64_t trusted_generation(const std::filesystem::path& trusted) {
        return encoding::decode_trusted_state(slurp(trusted / "trusted_state.bin")).trusted_generation;
    }
    static std::filesystem::path generation_dir(const std::filesystem::path& vault, std::uint64_t g) {
        char buf[32];
        std::snprintf(buf, sizeof buf, "%016llx", static_cast<unsigned long long>(g));
        return vault / "generations" / buf;
    }
    // Каталог текущего (trusted) поколения этого vault.
    std::filesystem::path current_dir() const { return generation_dir(vault_dir, trusted_generation(trusted_dir)); }
    std::filesystem::path object_path(const FileId& id) const {
        return current_dir() / "objects" / (to_hex(as_view(id)) + ".obj");
    }
    static Bytes slurp(const std::filesystem::path& p) {
        std::ifstream in(p, std::ios::binary);
        return Bytes((std::istreambuf_iterator<char>(in)), {});
    }
    static void spit(const std::filesystem::path& p, const Bytes& b) {
        std::ofstream out(p, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(b.data()), static_cast<std::streamsize>(b.size()));
    }

    std::filesystem::path root, vault_dir, trusted_dir;
};

}  // namespace vault::testing
