#pragma once
// Все domain-separated хеши проекта (§16-§23) в одном месте.
// Реализованы поверх IHashBackend, поэтому одинаковы для CPU и GPU.

#include "vault/common/bytes.hpp"
#include "vault/crypto/hash_backend.hpp"
#include "vault/encoding/manifest.hpp"

namespace vault::crypto {

// SHA3-256(0x00 || CanonicalEncode(EncryptedFileV1))
Hash256 merkle_leaf(IHashBackend& h, ByteView encoded_object);
// SHA3-256(0x01 || left || right)
Hash256 merkle_parent(IHashBackend& h, const Hash256& left, const Hash256& right);
// SHA3-256(0x02 || last)
Hash256 merkle_unpaired(IHashBackend& h, const Hash256& last);
// SHA3-256(0x03 || "edu-vault-empty-tree-v1")
Hash256 merkle_empty_root(IHashBackend& h);
// SHA3-256(0x10 || CanonicalEncode(ManifestV1))
Hash256 manifest_hash(IHashBackend& h, const encoding::ManifestV1& m);
// SHA3-256(0x11 || CT_KEM)
Hash256 kem_ct_hash(IHashBackend& h, ByteView kem_ct);
// SHA3-256(0x12 || PK_KEM)
Hash256 kem_key_id(IHashBackend& h, ByteView pk_kem);
// SHA3-256(0x13 || PK_SIG)
Hash256 sig_key_id(IHashBackend& h, ByteView pk_sig);

}  // namespace vault::crypto
