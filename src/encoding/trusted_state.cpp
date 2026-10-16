#include "vault/encoding/trusted_state.hpp"

#include "vault/encoding/canonical.hpp"

namespace vault::encoding {

Bytes encode_trusted_state(const TrustedStateV1& s) {
    ByteWriter w(kTrustedStateV1Size);
    w.u32(s.format_version);
    w.u32(s.crypto_suite_id);
    w.fixed(s.storage_uuid);
    w.u64(s.trusted_generation);
    w.fixed(s.trusted_manifest_hash);
    return std::move(w).take();
}

TrustedStateV1 decode_trusted_state(ByteView encoded) {
    ByteReader r(encoded);
    TrustedStateV1 s;
    s.format_version = r.u32();
    s.crypto_suite_id = r.u32();
    require_supported(s.format_version, s.crypto_suite_id);
    s.storage_uuid = r.fixed_array<kStorageUuidSize>();
    s.trusted_generation = r.u64();
    s.trusted_manifest_hash = r.fixed_array<kHashSize>();
    r.expect_end();
    return s;
}

}  // namespace vault::encoding
