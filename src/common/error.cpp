#include "vault/common/error.hpp"

namespace vault {

const char* to_string(VerifyStep step) noexcept {
    switch (step) {
        case VerifyStep::LoadTrustedState: return "LoadTrustedState";
        case VerifyStep::LoadManifest: return "LoadManifest";
        case VerifyStep::ManifestParse: return "ManifestParse";
        case VerifyStep::FormatVersion: return "FormatVersion";
        case VerifyStep::CryptoSuite: return "CryptoSuite";
        case VerifyStep::StorageUuidMismatch: return "StorageUuid";
        case VerifyStep::KemKeyId: return "KemKeyId";
        case VerifyStep::SigKeyId: return "SigKeyId";
        case VerifyStep::Signature: return "Signature";
        case VerifyStep::Generation: return "Generation";
        case VerifyStep::ManifestHash: return "ManifestHash";
        case VerifyStep::KemCtHash: return "KemCtHash";
        case VerifyStep::ObjectParse: return "ObjectParse";
        case VerifyStep::ObjectBinding: return "ObjectBinding";
        case VerifyStep::ObjectNameMismatch: return "ObjectNameMismatch";
        case VerifyStep::DuplicateFileId: return "DuplicateFileId";
        case VerifyStep::FileCount: return "FileCount";
        case VerifyStep::MerkleRoot: return "MerkleRoot";
    }
    return "Unknown";
}

}  // namespace vault
