// ML-KEM-768: NIST ACVP (keyGen, encapsulation, decapsulation, проверки ключей).
// Закрывает пункт, перенесённый с этапа 1 (там были только свойства API).
#include <gtest/gtest.h>

#include <fstream>
#include <sstream>

#include "vault/common/error.hpp"
#include "vault/crypto/cpu_backends.hpp"

using namespace vault;
using namespace vault::crypto;

namespace {

Bytes H(const std::string& s) {
    auto b = from_hex(s);
    EXPECT_TRUE(b.has_value());
    return b.value_or(Bytes{});
}

std::vector<std::vector<std::string>> read_vectors(const std::string& kind) {
    std::ifstream in(std::string(VAULT_TEST_VECTORS_DIR) + "/mlkem768_acvp.txt");
    EXPECT_TRUE(in.good());
    std::vector<std::vector<std::string>> out;
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream ss(line);
        std::vector<std::string> f;
        for (std::string w; ss >> w;) f.push_back(w);
        if (!f.empty() && f[0] == kind) out.push_back(std::move(f));
    }
    return out;
}

}  // namespace

TEST(MlKemAcvp, KeyGen) {
    auto kem = make_cpu_kem_backend(1);
    auto v = read_vectors("KEYGEN");
    ASSERT_FALSE(v.empty());
    for (const auto& f : v) {
        Bytes seed = H(f[1]);
        KemKeyPair kp = kem->keygen(ByteView(seed));
        EXPECT_EQ(to_hex(kp.public_key), f[2]);
        EXPECT_EQ(to_hex(kp.secret_key.view()), f[3]);
    }
}

TEST(MlKemAcvp, Encapsulation) {
    auto kem = make_cpu_kem_backend(1);
    auto v = read_vectors("ENCAPS");
    ASSERT_FALSE(v.empty());
    for (const auto& f : v) {
        Bytes ek = H(f[1]), m = H(f[2]);
        KemEncapsResult r = kem->encaps(ek, ByteView(m));
        EXPECT_EQ(to_hex(r.ciphertext), f[3]);
        EXPECT_EQ(to_hex(r.shared_secret.view()), f[4]);
    }
}

TEST(MlKemAcvp, DecapsulationIncludingImplicitRejection) {
    auto kem = make_cpu_kem_backend(1);
    auto v = read_vectors("DECAPS");
    ASSERT_FALSE(v.empty());
    for (const auto& f : v) {
        Bytes dk = H(f[1]), c = H(f[2]);
        EXPECT_EQ(to_hex(kem->decaps(dk, c).view()), f[3]);
    }
}

// Невалидный открытый ключ (коэффициенты вне Z_q) должен отвергаться при encaps,
// а невалидный секретный ключ (не тот H(ek) внутри dk) — при decaps.
TEST(MlKemAcvp, EncapsulationKeyCheck) {
    auto kem = make_cpu_kem_backend(1);
    auto v = read_vectors("EKCHECK");
    ASSERT_FALSE(v.empty());
    for (const auto& f : v) {
        Bytes ek = H(f[2]);
        if (f[1] == "1")
            EXPECT_NO_THROW(kem->encaps(ek, std::nullopt));
        else
            EXPECT_THROW(kem->encaps(ek, std::nullopt), VaultError);
    }
}

TEST(MlKemAcvp, DecapsulationKeyCheck) {
    auto kem = make_cpu_kem_backend(1);
    auto v = read_vectors("DKCHECK");
    ASSERT_FALSE(v.empty());
    Bytes ct(kMlKem768CiphertextSize, 0);
    for (const auto& f : v) {
        Bytes dk = H(f[2]);
        if (f[1] == "1")
            EXPECT_NO_THROW(kem->decaps(dk, ct));
        else
            EXPECT_THROW(kem->decaps(dk, ct), VaultError);
    }
}
