#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "vault/common/error.hpp"
#include "vault/crypto/backends.hpp"
#include "vault/crypto/cpu_backends.hpp"
#include "vault/crypto/domain_hash.hpp"
#include "vault/crypto/symmetric.hpp"
#include "vault/vault/key_hierarchy.hpp"

using namespace vault;
using namespace vault::crypto;

namespace {
Bytes H(const char* hex) { return *from_hex(hex); }
template <std::size_t N>
std::array<std::uint8_t, N> A(const char* hex) {
    Bytes b = H(hex);
    std::array<std::uint8_t, N> a{};
    std::copy(b.begin(), b.end(), a.begin());
    return a;
}
}  // namespace

TEST(Sha3, KnownVectors) {
    auto h = make_cpu_hash_backend(1);
    EXPECT_EQ(to_hex(as_view(h->sha3_256(ByteView()))),
              "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    EXPECT_EQ(to_hex(as_view(h->sha3_256(as_view("abc")))),
              "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
}

TEST(Sha3, DomainHashIsPrefixedHash) {
    auto h = make_cpu_hash_backend(1);
    Bytes msg = {1, 2, 3};
    Bytes prefixed = {0x11, 1, 2, 3};
    EXPECT_EQ(h->domain_hash(0x11, msg), h->sha3_256(prefixed));
    EXPECT_NE(h->domain_hash(0x11, msg), h->domain_hash(0x12, msg));
}

TEST(Sha3, BatchMatchesSingle) {
    auto h = make_cpu_hash_backend(1);
    Bytes a = {1}, b = {2, 3}, c;
    std::vector<ByteView> in = {a, b, c};
    std::vector<Hash256> out(3);
    h->domain_hash_batch(0x00, in, out, nullptr);
    for (std::size_t i = 0; i < 3; ++i) EXPECT_EQ(out[i], h->domain_hash(0x00, in[i]));
}

TEST(DomainHash, KeyIds) {
    auto h = make_cpu_hash_backend(1);
    Bytes pk(10, 7);
    Bytes p12 = {0x12};
    p12.insert(p12.end(), pk.begin(), pk.end());
    EXPECT_EQ(kem_key_id(*h, pk), h->sha3_256(p12));
    EXPECT_NE(kem_key_id(*h, pk), sig_key_id(*h, pk));
}

TEST(Gcm, KnownVectors) {
    Bytes key(32, 0);
    Nonce n{};
    // GCM spec test case 13 (empty) и 14 (16 нулевых байт)
    auto r0 = aes256_gcm_encrypt(key, n, ByteView(), ByteView());
    EXPECT_EQ(to_hex(as_view(r0.tag)), "530f8afbc74536b9a963b4f1c4cb738b");
    Bytes zeros(16, 0);
    auto r1 = aes256_gcm_encrypt(key, n, ByteView(), zeros);
    EXPECT_EQ(to_hex(r1.ciphertext), "cea7403d4d606b6e074ec5d3baf39d18");
    EXPECT_EQ(to_hex(as_view(r1.tag)), "d0d1c8a799996bf0265b98b5d48ab919");
}

TEST(Gcm, RoundTripAndFailures) {
    Bytes key(32, 3), aad = {1, 2, 3}, pt = {10, 20, 30, 40};
    Nonce n{};
    n.fill(9);
    auto c = aes256_gcm_encrypt(key, n, aad, pt);
    EXPECT_EQ(aes256_gcm_decrypt(key, n, aad, c.ciphertext, c.tag).view().size(), 4u);
    auto expect_auth_fail = [&](auto&& f) {
        try { f(); FAIL(); } catch (const VaultError& e) { EXPECT_EQ(e.code(), ErrorCode::AuthenticationFailed); }
    };
    Bytes ct = c.ciphertext; ct[0] ^= 1;
    expect_auth_fail([&] { aes256_gcm_decrypt(key, n, aad, ct, c.tag); });
    GcmTag t = c.tag; t[15] ^= 0x80;
    expect_auth_fail([&] { aes256_gcm_decrypt(key, n, aad, c.ciphertext, t); });
    Nonce n2 = n; n2[0] ^= 1;
    expect_auth_fail([&] { aes256_gcm_decrypt(key, n2, aad, c.ciphertext, c.tag); });
    Bytes aad2 = {1, 2, 4};
    expect_auth_fail([&] { aes256_gcm_decrypt(key, n, aad2, c.ciphertext, c.tag); });
}

TEST(Kw, Rfc3394_4_6) {
    Bytes kek = H("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    Bytes key = H("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");
    WrappedDek w = aes256_kw_wrap(kek, key);
    EXPECT_EQ(to_hex(as_view(w)),
              "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21");
    SecureBytes un = aes256_kw_unwrap(kek, w);
    EXPECT_EQ(Bytes(un.view().begin(), un.view().end()), key);
}

TEST(Kw, CorruptionDetected) {
    Bytes kek(32, 1), dek(32, 2);
    WrappedDek w = aes256_kw_wrap(kek, dek);
    for (std::size_t i = 0; i < w.size(); ++i) {
        WrappedDek bad = w;
        bad[i] ^= 1;
        EXPECT_THROW(aes256_kw_unwrap(kek, bad), VaultError);
    }
    Bytes kek2(32, 9);
    EXPECT_THROW(aes256_kw_unwrap(kek2, w), VaultError);
}

TEST(Hkdf, MatchesManualRfc5869WithSha3) {
    Bytes ikm(32, 0x0b), salt(16, 0x01), info = {'i', 'n', 'f', 'o'};
    // extract
    unsigned char prk[32];
    unsigned int len = 0;
    ASSERT_TRUE(HMAC(EVP_sha3_256(), salt.data(), static_cast<int>(salt.size()), ikm.data(), ikm.size(), prk, &len));
    ASSERT_EQ(len, 32u);
    // expand, L = 32 -> один блок T(1) = HMAC(PRK, info || 0x01)
    Bytes t1 = info;
    t1.push_back(1);
    unsigned char okm[32];
    ASSERT_TRUE(HMAC(EVP_sha3_256(), prk, 32, t1.data(), t1.size(), okm, &len));
    SecureBytes got = hkdf_sha3_256(ikm, salt, info, 32);
    EXPECT_EQ(to_hex(got.view()), to_hex(ByteView(okm, 32)));
}

TEST(KeyHierarchy, KekDependsOnUuidAndSuite) {
    Bytes k(32, 5);
    StorageUuid u1{}, u2{};
    u2[0] = 1;
    auto a = core::derive_kek(k, u1, 1);
    auto b = core::derive_kek(k, u2, 1);
    auto c = core::derive_kek(k, u1, 2);
    EXPECT_EQ(a.size(), 32u);
    EXPECT_NE(to_hex(a.view()), to_hex(b.view()));
    EXPECT_NE(to_hex(a.view()), to_hex(c.view()));
    EXPECT_EQ(to_hex(a.view()), to_hex(core::derive_kek(k, u1, 1).view()));
}

TEST(MlKem, SizesRoundTripAndImplicitRejection) {
    auto kem = make_cpu_kem_backend(1);
    auto kp = kem->keygen(std::nullopt);
    EXPECT_EQ(kp.public_key.size(), kMlKem768PublicKeySize);
    EXPECT_EQ(kp.secret_key.size(), kMlKem768SecretKeySize);
    auto e = kem->encaps(kp.public_key, std::nullopt);
    EXPECT_EQ(e.ciphertext.size(), kMlKem768CiphertextSize);
    EXPECT_EQ(to_hex(kem->decaps(kp.secret_key.view(), e.ciphertext).view()), to_hex(e.shared_secret.view()));
    Bytes bad = e.ciphertext;
    bad[0] ^= 1;
    EXPECT_NE(to_hex(kem->decaps(kp.secret_key.view(), bad).view()), to_hex(e.shared_secret.view()));
}

TEST(MlKem, DerandIsDeterministic) {
    auto kem = make_cpu_kem_backend(1);
    Bytes seed(64, 0x42), m(32, 0x24);
    auto a = kem->keygen(seed), b = kem->keygen(seed);
    EXPECT_EQ(a.public_key, b.public_key);
    auto ea = kem->encaps(a.public_key, m), eb = kem->encaps(a.public_key, m);
    EXPECT_EQ(ea.ciphertext, eb.ciphertext);
    EXPECT_EQ(to_hex(ea.shared_secret.view()), to_hex(eb.shared_secret.view()));
}

TEST(MlKem, BatchMatchesSingle) {
    auto kem = make_cpu_kem_backend(1);
    Bytes seeds(3 * 64, 0);
    for (std::size_t i = 0; i < seeds.size(); ++i) seeds[i] = static_cast<std::uint8_t>(i * 7);
    KemBatch b;
    kem->keygen_batch(3, seeds, b, nullptr);
    Bytes m(3 * 32, 1);
    kem->encaps_batch(b, m, nullptr);
    kem->decaps_batch(b, nullptr);
    for (std::size_t i = 0; i < 3; ++i) {
        auto kp = kem->keygen(ByteView(seeds).subspan(i * 64, 64));
        EXPECT_EQ(Bytes(b.public_keys.begin() + static_cast<long>(i * 1184), b.public_keys.begin() + static_cast<long>((i + 1) * 1184)), kp.public_key);
        auto e = kem->encaps(kp.public_key, ByteView(m).subspan(i * 32, 32));
        EXPECT_EQ(to_hex(b.shared_secrets.view().subspan(i * 32, 32)), to_hex(e.shared_secret.view()));
    }
}

TEST(Random, DeterministicForTests) {
    Bytes seed = {1, 2, 3};
    auto r1 = make_deterministic_random_for_tests(seed), r2 = make_deterministic_random_for_tests(seed);
    Bytes a(32), b(32), c(32);
    r1->fill(a); r2->fill(b); r1->fill(c);
    EXPECT_EQ(a, b);
    EXPECT_NE(a, c);
}
