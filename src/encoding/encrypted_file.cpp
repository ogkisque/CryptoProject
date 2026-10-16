#include "vault/encoding/encrypted_file.hpp"

#include <limits>

#include "vault/encoding/canonical.hpp"

namespace vault::encoding {

Bytes encode_encrypted_file(const EncryptedFileV1& obj) {
    ByteWriter w(kEncryptedFileFixedOverhead + obj.ciphertext.size());
    w.u32(obj.format_version);
    w.u32(obj.crypto_suite_id);
    w.fixed(obj.storage_uuid);
    w.fixed(obj.file_id);
    w.fixed(obj.nonce);
    w.fixed(obj.wrapped_dek);
    w.var_u64(obj.ciphertext);
    w.fixed(obj.gcm_tag);
    return std::move(w).take();
}

EncryptedFileV1 decode_encrypted_file(ByteView encoded) {
    ByteReader r(encoded);
    EncryptedFileV1 obj;
    obj.format_version = r.u32();
    obj.crypto_suite_id = r.u32();
    require_supported(obj.format_version, obj.crypto_suite_id);
    obj.storage_uuid = r.fixed_array<kStorageUuidSize>();
    obj.file_id = r.fixed_array<kFileIdSize>();
    obj.nonce = r.fixed_array<kNonceSize>();
    obj.wrapped_dek = r.fixed_array<kWrappedDekSize>();
    ByteView ct = r.var_u64(std::numeric_limits<std::uint64_t>::max());
    obj.ciphertext.assign(ct.begin(), ct.end());
    obj.gcm_tag = r.fixed_array<kGcmTagSize>();
    r.expect_end();
    return obj;
}

Bytes build_file_aad(std::uint32_t format_version, std::uint32_t crypto_suite_id,
                     const StorageUuid& storage_uuid, const FileId& file_id) {
    ByteWriter w(label::kFileAad.size() + 8 + kStorageUuidSize + kFileIdSize);
    w.fixed(as_view(label::kFileAad));
    w.u32(format_version);
    w.u32(crypto_suite_id);
    w.fixed(storage_uuid);
    w.fixed(file_id);
    return std::move(w).take();
}

}  // namespace vault::encoding
