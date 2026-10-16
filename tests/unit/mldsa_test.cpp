// ML-DSA-65 (этап 2.3): NIST ACVP (keyGen, sigGen external/pure, sigVer) и свойства API.
#include <gtest/gtest.h>

#include <fstream>
#include <sstream>

#include "vault/common/error.hpp"
#include "vault/crypto/cpu_backends.hpp"
#include "vault/encoding/manifest.hpp"

using namespace vault;
using namespace vault::crypto;

namespace {

Bytes H(const std::string& s) {
    if (s == "-") return {};
    auto b = from_hex(s);
    EXPECT_TRUE(b.has_value());
    return b.value_or(Bytes{});
}

std::string ctx_str(const Bytes& c) { return std::string(c.begin(), c.end()); }

std::vector<std::vector<std::string>> read_vectors(const std::string& kind) {
    std::ifstream in(std::string(VAULT_TEST_VECTORS_DIR) + "/mldsa65_acvp.txt");
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

TEST(MlDsa, AcvpKeyGen) {
    auto sig = make_cpu_sig_backend(1);
    auto v = read_vectors("KEYGEN");
    ASSERT_FALSE(v.empty());
    for (const auto& f : v) {
        Bytes seed = H(f[1]);
        SigKeyPair kp = sig->keygen(ByteView(seed));
        EXPECT_EQ(to_hex(kp.public_key), f[2]);
        EXPECT_EQ(to_hex(kp.secret_key.view()), f[3]);
    }
}

TEST(MlDsa, AcvpSigGen) {
    auto sig = make_cpu_sig_backend(1);
    auto v = read_vectors("SIGGEN");
    ASSERT_FALSE(v.empty());
    for (const auto& f : v) {
        Bytes rnd = H(f[1]), sk = H(f[2]), msg = H(f[3]), ctx = H(f[4]);
        Bytes s = sig->sign(sk, msg, ctx_str(ctx), ByteView(rnd));
        EXPECT_EQ(to_hex(s), f[5]);
    }
}

TEST(MlDsa, AcvpSigVer) {
    auto sig = make_cpu_sig_backend(1);
    auto v = read_vectors("SIGVER");
    ASSERT_FALSE(v.empty());
    int passed = 0;
    for (const auto& f : v) {
        bool expected = f[1] == "1";
        passed += expected;
        EXPECT_EQ(sig->verify(H(f[2]), H(f[3]), ctx_str(H(f[4])), H(f[5])), expected);
    }
    EXPECT_GT(passed, 0);
}

TEST(MlDsa, SignVerifyRoundTripHedged) {
    auto sig = make_cpu_sig_backend(1);
    SigKeyPair kp = sig->keygen(std::nullopt);
    ASSERT_EQ(kp.public_key.size(), kMlDsa65PublicKeySize);
    ASSERT_EQ(kp.secret_key.size(), kMlDsa65SecretKeySize);
    Bytes msg(168, 0x33);
    Bytes s1 = sig->sign(kp.secret_key.view(), msg, "edu-vault-manifest-v1", std::nullopt);
    Bytes s2 = sig->sign(kp.secret_key.view(), msg, "edu-vault-manifest-v1", std::nullopt);
    EXPECT_EQ(s1.size(), kMlDsa65SignatureSize);
    EXPECT_NE(s1, s2);  // hedged: подпись рандомизирована
    EXPECT_TRUE(sig->verify(kp.public_key, msg, "edu-vault-manifest-v1", s1));
    EXPECT_TRUE(sig->verify(kp.public_key, msg, "edu-vault-manifest-v1", s2));
}

TEST(MlDsa, DeterministicModeIsReproducibleAndVerifiesViaPublicApi) {
    auto sig = make_cpu_sig_backend(1);
    Bytes seed(32, 7), zero(32, 0), msg = {1, 2, 3};
    SigKeyPair kp = sig->keygen(ByteView(seed));
    Bytes s1 = sig->sign(kp.secret_key.view(), msg, "ctx", ByteView(zero));
    Bytes s2 = sig->sign(kp.secret_key.view(), msg, "ctx", ByteView(zero));
    EXPECT_EQ(s1, s2);
    EXPECT_TRUE(sig->verify(kp.public_key, msg, "ctx", s1));  // проверяет публичный liboqs-путь
}

TEST(MlDsa, WrongContextMessageKeyOrSignatureRejected) {
    auto sig = make_cpu_sig_backend(1);
    SigKeyPair kp = sig->keygen(std::nullopt), other = sig->keygen(std::nullopt);
    Bytes msg(168, 1);
    Bytes s = sig->sign(kp.secret_key.view(), msg, "edu-vault-manifest-v1", std::nullopt);
    EXPECT_FALSE(sig->verify(kp.public_key, msg, "edu-vault-manifest-v2", s));
    EXPECT_FALSE(sig->verify(kp.public_key, msg, "", s));
    Bytes bad_msg = msg;
    bad_msg[0] ^= 1;
    EXPECT_FALSE(sig->verify(kp.public_key, bad_msg, "edu-vault-manifest-v1", s));
    EXPECT_FALSE(sig->verify(other.public_key, msg, "edu-vault-manifest-v1", s));
    Bytes bad_sig = s;
    bad_sig[100] ^= 1;
    EXPECT_FALSE(sig->verify(kp.public_key, msg, "edu-vault-manifest-v1", bad_sig));
    s.pop_back();
    EXPECT_FALSE(sig->verify(kp.public_key, msg, "edu-vault-manifest-v1", s));  // неверная длина — не исключение
}

TEST(MlDsa, BatchMatchesSingle) {
    auto sig = make_cpu_sig_backend(1);
    SigBatch b;
    Bytes seeds(3 * kMlDsa65KeygenSeedSize, 9);
    for (std::size_t i = 0; i < seeds.size(); ++i) seeds[i] = static_cast<std::uint8_t>(i);
    sig->keygen_batch(3, ByteView(seeds), b, nullptr);
    b.message_size = 4;
    b.messages = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Bytes rnds(3 * kMlDsa65SignRandSize, 0);
    sig->sign_batch(b, "c", ByteView(rnds), nullptr);
    sig->verify_batch(b, "c", nullptr);
    for (std::size_t i = 0; i < 3; ++i) {
        EXPECT_EQ(b.verify_ok[i], 1);
        SigKeyPair kp = sig->keygen(ByteView(seeds).subspan(i * 32, 32));
        Bytes s = sig->sign(kp.secret_key.view(), ByteView(b.messages).subspan(i * 4, 4), "c", ByteView(rnds).subspan(0, 32));
        EXPECT_EQ(Bytes(b.signatures.begin() + i * kMlDsa65SignatureSize, b.signatures.begin() + (i + 1) * kMlDsa65SignatureSize), s);
    }
    b.signatures[5] ^= 1;
    sig->verify_batch(b, "c", nullptr);
    EXPECT_EQ(b.verify_ok[0], 0);
    EXPECT_EQ(b.verify_ok[1], 1);
}

TEST(Manifest, EncodesToExactly168BytesAndRoundTrips) {
    encoding::ManifestV1 m;
    m.generation = 5;
    m.file_count = 9;
    m.merkle_root.fill(1);
    m.kem_ct_hash.fill(2);
    m.kem_key_id.fill(3);
    m.sig_key_id.fill(4);
    m.storage_uuid.fill(5);
    Bytes e = encoding::encode_manifest(m);
    EXPECT_EQ(e.size(), 168u);
    EXPECT_EQ(encoding::decode_manifest(e), m);
    e.push_back(0);
    EXPECT_THROW(encoding::decode_manifest(e), VaultError);
    e.resize(167);
    EXPECT_THROW(encoding::decode_manifest(e), VaultError);
}
