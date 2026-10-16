// Проверка состояния по docs/format_v1.md §11 (шаги 1-6, 9-12; 7-8 — этап 3).
// Все решения о доверии принимаются здесь; Decaps/расшифрование вызывающий код
// выполняет только после возврата из verify_current().
#include "vault/vault/state_verifier.hpp"

#include <algorithm>

#include "vault/common/error.hpp"
#include "vault/crypto/domain_hash.hpp"
#include "vault/encoding/canonical.hpp"
#include "vault/merkle/merkle.hpp"

namespace vault::core {

StateVerifier::StateVerifier(const crypto::CryptoBackends& backends, const storage::IStorageBackend& storage,
                             const storage::ITrustedStorage& trusted)
    : backends_(backends), storage_(storage), trusted_(trusted) {}

namespace {

bool equal(const Hash256& a, const Hash256& b) { return constant_time_equal(as_view(a), as_view(b)); }

struct ParsedObject {
    encoding::EncryptedFileV1 obj;
    Bytes raw;  // байты на диске = CanonicalEncode(obj) (разбор строгий, trailing data запрещены)
};

}  // namespace

VerifyReport StateVerifier::verify_current() const {
    if (!backends_.hash || !backends_.merkle || !backends_.sig)
        throw VaultError(ErrorCode::InvalidArgument, "verifier: hash/merkle/sig backends are required");
    VerifyReport report;
    VerifiedState& st = report.state;
    crypto::IHashBackend& hash = *backends_.hash;

    // --- 1. TrustedState и публичные ключи ---
    encoding::TrustedStateV1 ts;
    storage::TrustedPublicKeys keys;
    try {
        ts = trusted_.load_state();
        keys = trusted_.load_public_keys();
    } catch (const VaultError& e) {
        throw VerificationError(VerifyStep::LoadTrustedState, e.what());
    }
    if (!keys.sig_pk || keys.sig_pk->size() != kMlDsa65PublicKeySize)
        throw VerificationError(VerifyStep::LoadTrustedState, "trusted area has no valid signature public key");

    // --- 2. Загрузка snapshot, manifest, signature ---
    storage::RawSnapshot snap;
    try {
        ScopedPhase p(&report.profile, Phase::Filesystem);
        snap = storage_.read_snapshot(ts.trusted_generation);
        st.kem_ct = storage_.read_kem_ct();
    } catch (const VaultError& e) {
        throw VerificationError(VerifyStep::LoadSnapshot, e.what());
    }
    st.generation = ts.trusted_generation;
    if (st.kem_ct.size() != kMlKem768CiphertextSize)
        throw VerificationError(VerifyStep::LoadSnapshot, "kem.ct has wrong size");
    if (!snap.manifest) throw VerificationError(VerifyStep::LoadManifest, "manifest.bin is missing");
    if (!snap.signature) throw VerificationError(VerifyStep::LoadManifest, "manifest.sig is missing");

    // --- 3. Канонический разбор Manifest ---
    encoding::ManifestV1 m;
    {
        ScopedPhase p(&report.profile, Phase::Serialization);
        if (snap.manifest->size() != kManifestV1Size)
            throw VerificationError(VerifyStep::ManifestParse, "manifest.bin has wrong size");
        try {
            m = encoding::decode_manifest(*snap.manifest);
        } catch (const VaultError& e) {
            if (e.code() != ErrorCode::UnsupportedVersion) throw VerificationError(VerifyStep::ManifestParse, e.what());
            // Размер верный, значит отвергнуто одно из первых двух полей.
            encoding::ByteReader r(*snap.manifest);
            throw VerificationError(r.u32() != kFormatVersionV1 ? VerifyStep::FormatVersion : VerifyStep::CryptoSuite,
                                    e.what());
        }
    }

    // --- 4. format_version, crypto_suite_id, storage_uuid == trusted ---
    if (m.format_version != ts.format_version)
        throw VerificationError(VerifyStep::FormatVersion, "manifest format_version differs from trusted state");
    if (m.crypto_suite_id != ts.crypto_suite_id)
        throw VerificationError(VerifyStep::CryptoSuite, "manifest crypto_suite_id differs from trusted state");
    if (!constant_time_equal(as_view(m.storage_uuid), as_view(ts.storage_uuid)))
        throw VerificationError(VerifyStep::StorageUuidMismatch, "manifest belongs to another vault");

    // --- 5. key ids == SHA3 от доверенных публичных ключей ---
    {
        ScopedPhase p(&report.profile, Phase::Algorithm);
        if (!equal(m.kem_key_id, crypto::kem_key_id(hash, keys.kem_pk)))
            throw VerificationError(VerifyStep::KemKeyId, "manifest kem_key_id does not match trusted ML-KEM key");
        if (!equal(m.sig_key_id, crypto::sig_key_id(hash, *keys.sig_pk)))
            throw VerificationError(VerifyStep::SigKeyId, "manifest sig_key_id does not match trusted ML-DSA key");
    }

    // --- 6. ML-DSA Verify ---
    {
        ScopedPhase p(&report.profile, Phase::Algorithm);
        if (!backends_.sig->verify(*keys.sig_pk, *snap.manifest, label::kManifestSigContext, *snap.signature))
            throw VerificationError(VerifyStep::Signature, "manifest signature is invalid");
    }
    st.manifest = m;
    st.manifest_hash = crypto::manifest_hash(hash, m);

    // --- 9. kem.ct == подписанный kem_ct_hash (ДО любого Decaps) ---
    {
        ScopedPhase p(&report.profile, Phase::Algorithm);
        if (!equal(m.kem_ct_hash, crypto::kem_ct_hash(hash, st.kem_ct)))
            throw VerificationError(VerifyStep::KemCtHash, "kem.ct does not match signed kem_ct_hash");
    }

    // --- 10. Разбор объектов, привязка, имена, уникальность ---
    std::vector<ParsedObject> parsed;
    parsed.reserve(snap.objects.size());
    for (auto& raw : snap.objects) {
        ParsedObject po;
        try {
            ScopedPhase p(&report.profile, Phase::Serialization);
            po.obj = encoding::decode_encrypted_file(raw.data);
        } catch (const VaultError& e) {
            throw VerificationError(VerifyStep::ObjectParse, raw.file_name + ": " + e.what());
        }
        if (po.obj.format_version != ts.format_version || po.obj.crypto_suite_id != ts.crypto_suite_id ||
            !constant_time_equal(as_view(po.obj.storage_uuid), as_view(ts.storage_uuid)))
            throw VerificationError(VerifyStep::ObjectBinding, raw.file_name + ": object is not bound to this vault");
        if (raw.file_name != storage::object_file_name(po.obj.file_id))
            throw VerificationError(VerifyStep::ObjectNameMismatch, raw.file_name + ": name does not match file_id");
        po.raw = std::move(raw.data);
        parsed.push_back(std::move(po));
    }
    std::sort(parsed.begin(), parsed.end(), [](const auto& a, const auto& b) { return a.obj.file_id < b.obj.file_id; });
    for (std::size_t i = 1; i < parsed.size(); ++i)
        if (parsed[i].obj.file_id == parsed[i - 1].obj.file_id)
            throw VerificationError(VerifyStep::DuplicateFileId, "duplicate file_id");

    // --- 11. file_count ---
    if (m.file_count != parsed.size())
        throw VerificationError(VerifyStep::FileCount, "object count differs from manifest file_count");

    // --- 12. Листья и Merkle root ---
    {
        ScopedPhase p(&report.profile, Phase::Algorithm);
        std::vector<ByteView> views;
        views.reserve(parsed.size());
        for (const auto& po : parsed) views.emplace_back(po.raw);
        st.leaves.resize(parsed.size());
        backends_.merkle->compute_leaves(views, st.leaves, &report.merkle_timing);
        Hash256 root = backends_.merkle->root_from_leaves(st.leaves, &report.merkle_timing);
        if (!equal(root, m.merkle_root))
            throw VerificationError(VerifyStep::MerkleRoot, "merkle root differs from signed manifest");
    }
    st.objects.reserve(parsed.size());
    for (auto& po : parsed) st.objects.push_back(std::move(po.obj));
    return report;
}

}  // namespace vault::core
