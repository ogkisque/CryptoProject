// Этап 1: проверяется только структура объектов (разбор, привязка к хранилищу,
// имена файлов, уникальность file_id). Manifest/Merkle/подпись — этап 2,
// generation/manifest_hash — этап 3.
#include "vault/vault/state_verifier.hpp"

#include <algorithm>

#include "vault/common/error.hpp"

namespace vault::core {

StateVerifier::StateVerifier(const crypto::CryptoBackends& backends, const storage::IStorageBackend& storage,
                             const storage::ITrustedStorage& trusted)
    : backends_(backends), storage_(storage), trusted_(trusted) {}

VerifyReport StateVerifier::verify_current() const {
    VerifyReport report;
    VerifiedState& st = report.state;

    encoding::TrustedStateV1 ts;
    try {
        ts = trusted_.load_state();
    } catch (const VaultError& e) {
        throw VerificationError(VerifyStep::LoadTrustedState, e.what());
    }

    storage::RawSnapshot snap;
    try {
        ScopedPhase p(&report.profile, Phase::Filesystem);
        snap = storage_.read_snapshot(ts.trusted_generation);
        st.kem_ct = storage_.read_kem_ct();
    } catch (const VaultError& e) {
        throw VerificationError(VerifyStep::LoadManifest, e.what());
    }
    st.generation = ts.trusted_generation;

    for (const auto& raw : snap.objects) {
        encoding::EncryptedFileV1 obj;
        try {
            ScopedPhase p(&report.profile, Phase::Serialization);
            obj = encoding::decode_encrypted_file(raw.data);
        } catch (const VaultError& e) {
            throw VerificationError(VerifyStep::ObjectParse, raw.file_name + ": " + e.what());
        }
        if (obj.format_version != ts.format_version || obj.crypto_suite_id != ts.crypto_suite_id ||
            !constant_time_equal(as_view(obj.storage_uuid), as_view(ts.storage_uuid)))
            throw VerificationError(VerifyStep::ObjectBinding, raw.file_name + ": object is not bound to this vault");
        if (raw.file_name != storage::object_file_name(obj.file_id))
            throw VerificationError(VerifyStep::ObjectNameMismatch, raw.file_name + ": name does not match file_id");
        st.objects.push_back(std::move(obj));
    }

    std::sort(st.objects.begin(), st.objects.end(),
              [](const auto& a, const auto& b) { return a.file_id < b.file_id; });
    for (std::size_t i = 1; i < st.objects.size(); ++i)
        if (st.objects[i].file_id == st.objects[i - 1].file_id)
            throw VerificationError(VerifyStep::DuplicateFileId, "duplicate file_id");

    (void)backends_;
    return report;
}

}  // namespace vault::core
