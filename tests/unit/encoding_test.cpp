#include <gtest/gtest.h>

#include "vault/common/error.hpp"
#include "vault/encoding/canonical.hpp"
#include "vault/encoding/encrypted_file.hpp"
#include "vault/encoding/file_plaintext.hpp"
#include "vault/encoding/manifest.hpp"
#include "vault/encoding/trusted_state.hpp"

using namespace vault;
using namespace vault::encoding;

namespace {
EncryptedFileV1 sample_object() {
    EncryptedFileV1 o;
    for (std::size_t i = 0; i < o.storage_uuid.size(); ++i) o.storage_uuid[i] = static_cast<std::uint8_t>(i);
    for (std::size_t i = 0; i < o.file_id.size(); ++i) o.file_id[i] = static_cast<std::uint8_t>(0x10 + i);
    for (std::size_t i = 0; i < o.nonce.size(); ++i) o.nonce[i] = static_cast<std::uint8_t>(0x20 + i);
    for (std::size_t i = 0; i < o.wrapped_dek.size(); ++i) o.wrapped_dek[i] = static_cast<std::uint8_t>(0x30 + i);
    o.ciphertext = {1, 2, 3, 4, 5};
    for (std::size_t i = 0; i < o.gcm_tag.size(); ++i) o.gcm_tag[i] = static_cast<std::uint8_t>(0x80 + i);
    return o;
}
template <class F>
void expect_code(F&& f, ErrorCode code) {
    try {
        f();
        FAIL() << "expected VaultError";
    } catch (const VaultError& e) {
        EXPECT_EQ(e.code(), code) << e.what();
    }
}
}  // namespace

TEST(Canonical, BigEndian) {
    ByteWriter w;
    w.u32(0x01020304);
    w.u64(0x0102030405060708ull);
    EXPECT_EQ(to_hex(w.bytes()), "010203040102030405060708");
}

TEST(EncryptedFile, LayoutAndRoundTrip) {
    EncryptedFileV1 o = sample_object();
    Bytes enc = encode_encrypted_file(o);
    EXPECT_EQ(enc.size(), kEncryptedFileFixedOverhead + 5);
    EXPECT_EQ(to_hex(ByteView(enc).subspan(0, 8)), "0000000100000001");
    EXPECT_EQ(to_hex(ByteView(enc).subspan(92, 8)), "0000000000000005");  // ciphertext_length
    EncryptedFileV1 d = decode_encrypted_file(enc);
    EXPECT_EQ(d.file_id, o.file_id);
    EXPECT_EQ(d.nonce, o.nonce);
    EXPECT_EQ(d.wrapped_dek, o.wrapped_dek);
    EXPECT_EQ(d.ciphertext, o.ciphertext);
    EXPECT_EQ(d.gcm_tag, o.gcm_tag);
    EXPECT_EQ(encode_encrypted_file(d), enc);
}

TEST(EncryptedFile, EveryTruncationRejected) {
    Bytes enc = encode_encrypted_file(sample_object());
    for (std::size_t n = 0; n < enc.size(); ++n)
        expect_code([&] { decode_encrypted_file(ByteView(enc).subspan(0, n)); }, ErrorCode::FormatError);
}

TEST(EncryptedFile, TrailingDataRejected) {
    Bytes enc = encode_encrypted_file(sample_object());
    enc.push_back(0);
    expect_code([&] { decode_encrypted_file(enc); }, ErrorCode::FormatError);
}

TEST(EncryptedFile, UnsupportedVersionAndSuite) {
    Bytes enc = encode_encrypted_file(sample_object());
    Bytes v = enc;
    v[3] = 2;
    expect_code([&] { decode_encrypted_file(v); }, ErrorCode::UnsupportedVersion);
    Bytes s = enc;
    s[7] = 9;
    expect_code([&] { decode_encrypted_file(s); }, ErrorCode::UnsupportedVersion);
}

TEST(EncryptedFile, HugeLengthDoesNotAllocate) {
    Bytes enc = encode_encrypted_file(sample_object());
    for (int i = 92; i < 100; ++i) enc[static_cast<std::size_t>(i)] = 0xFF;
    expect_code([&] { decode_encrypted_file(enc); }, ErrorCode::FormatError);
}

TEST(EncryptedFile, Aad) {
    StorageUuid u{};
    FileId f{};
    u.fill(0xAA);
    f.fill(0xBB);
    Bytes aad = build_file_aad(1, 1, u, f);
    EXPECT_EQ(aad.size(), 57u);
    EXPECT_EQ(std::string(aad.begin(), aad.begin() + 17), "edu-vault-file-v1");
}

TEST(FilePlaintext, RoundTrip) {
    Bytes data = {9, 8, 7};
    SecureBytes enc = encode_file_plaintext("привет.txt", data);
    FilePlaintext p = decode_file_plaintext(enc.view());
    EXPECT_EQ(p.filename, "привет.txt");
    EXPECT_EQ(Bytes(p.file_data.view().begin(), p.file_data.view().end()), data);
}

TEST(FilePlaintext, EmptyData) {
    SecureBytes enc = encode_file_plaintext("a", ByteView());
    EXPECT_EQ(decode_file_plaintext(enc.view()).file_data.size(), 0u);
}

TEST(FilePlaintext, Rejects) {
    expect_code([] { encode_file_plaintext("", ByteView()); }, ErrorCode::InvalidArgument);
    expect_code([] { encode_file_plaintext("\xC0\xAF", ByteView()); }, ErrorCode::InvalidArgument);  // overlong
    expect_code([] { encode_file_plaintext("\xED\xA0\x80", ByteView()); }, ErrorCode::InvalidArgument);  // surrogate
    SecureBytes enc = encode_file_plaintext("abc", Bytes{1, 2});
    for (std::size_t n = 0; n < enc.size(); ++n)
        expect_code([&] { decode_file_plaintext(enc.view().subspan(0, n)); }, ErrorCode::FormatError);
    Bytes extra(enc.view().begin(), enc.view().end());
    extra.push_back(0);
    expect_code([&] { decode_file_plaintext(extra); }, ErrorCode::FormatError);
}

TEST(Manifest, RoundTripSize) {
    ManifestV1 m;
    m.generation = 7;
    m.file_count = 3;
    m.merkle_root.fill(1);
    Bytes enc = encode_manifest(m);
    EXPECT_EQ(enc.size(), kManifestV1Size);
    EXPECT_EQ(decode_manifest(enc), m);
}

TEST(TrustedState, RoundTripSize) {
    TrustedStateV1 s;
    s.trusted_generation = 42;
    s.storage_uuid.fill(5);
    Bytes enc = encode_trusted_state(s);
    EXPECT_EQ(enc.size(), kTrustedStateV1Size);
    EXPECT_EQ(decode_trusted_state(enc), s);
}
