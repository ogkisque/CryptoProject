#include "vault/crypto/domain_hash.hpp"

#include "vault/encoding/manifest.hpp"

namespace vault::crypto {

Hash256 merkle_leaf(IHashBackend& h, ByteView encoded_object) {
    return h.domain_hash(domain::kMerkleLeaf, encoded_object);
}

Hash256 merkle_parent(IHashBackend& h, const Hash256& left, const Hash256& right) {
    std::array<std::uint8_t, 2 * kHashSize> buf;
    std::copy(left.begin(), left.end(), buf.begin());
    std::copy(right.begin(), right.end(), buf.begin() + kHashSize);
    return h.domain_hash(domain::kMerkleParent, as_view(buf));
}

Hash256 merkle_unpaired(IHashBackend& h, const Hash256& last) {
    return h.domain_hash(domain::kMerkleUnpaired, as_view(last));
}

Hash256 merkle_empty_root(IHashBackend& h) {
    return h.domain_hash(domain::kMerkleEmpty, as_view(label::kEmptyTree));
}

Hash256 manifest_hash(IHashBackend& h, const encoding::ManifestV1& m) {
    Bytes enc = encoding::encode_manifest(m);
    return h.domain_hash(domain::kManifestHash, enc);
}

Hash256 kem_ct_hash(IHashBackend& h, ByteView kem_ct) { return h.domain_hash(domain::kKemCtHash, kem_ct); }
Hash256 kem_key_id(IHashBackend& h, ByteView pk_kem) { return h.domain_hash(domain::kKemKeyId, pk_kem); }
Hash256 sig_key_id(IHashBackend& h, ByteView pk_sig) { return h.domain_hash(domain::kSigKeyId, pk_sig); }

}  // namespace vault::crypto
