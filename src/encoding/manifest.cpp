#include "vault/encoding/manifest.hpp"

#include "vault/encoding/canonical.hpp"

namespace vault::encoding {

Bytes encode_manifest(const ManifestV1& m) {
    ByteWriter w(kManifestV1Size);
    w.u32(m.format_version);
    w.u32(m.crypto_suite_id);
    w.fixed(m.storage_uuid);
    w.u64(m.generation);
    w.u64(m.file_count);
    w.fixed(m.merkle_root);
    w.fixed(m.kem_ct_hash);
    w.fixed(m.kem_key_id);
    w.fixed(m.sig_key_id);
    return std::move(w).take();
}

ManifestV1 decode_manifest(ByteView encoded) {
    ByteReader r(encoded);
    ManifestV1 m;
    m.format_version = r.u32();
    m.crypto_suite_id = r.u32();
    require_supported(m.format_version, m.crypto_suite_id);
    m.storage_uuid = r.fixed_array<kStorageUuidSize>();
    m.generation = r.u64();
    m.file_count = r.u64();
    m.merkle_root = r.fixed_array<kHashSize>();
    m.kem_ct_hash = r.fixed_array<kHashSize>();
    m.kem_key_id = r.fixed_array<kHashSize>();
    m.sig_key_id = r.fixed_array<kHashSize>();
    r.expect_end();
    return m;
}

}  // namespace vault::encoding
