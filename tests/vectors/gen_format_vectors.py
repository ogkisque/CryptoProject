#!/usr/bin/env python3
"""Независимая (только stdlib) реализация байтовых форматов v1 -> format_v1_vectors.txt.

Сверяет с C++ кодом раскладку из docs/format_v1.md: FilePlaintext, AAD, KEK (HKDF-SHA3-256),
EncryptedFileV1 и его Merkle leaf, ManifestV1 и manifest_hash, key ids, kem_ct_hash, TrustedStateV1.
Входы детерминированы (см. константы ниже, те же — в tests/unit/format_vectors_test.cpp).
Использование: gen_format_vectors.py > format_v1_vectors.txt
"""
import hashlib, hmac, struct

def u32(x): return struct.pack(">I", x)
def u64(x): return struct.pack(">Q", x)
def sha3(prefix, data): return hashlib.sha3_256(bytes([prefix]) + data).digest()
def pattern(n, start): return bytes((start + i) & 0xFF for i in range(n))

def hkdf_sha3_256(ikm, salt, info, length):
    prk = hmac.new(salt, ikm, hashlib.sha3_256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha3_256).digest()
        out += t
        i += 1
    return out[:length]

FORMAT, SUITE = 1, 1
uuid = pattern(16, 0x00)
file_id = pattern(16, 0x10)
nonce = pattern(12, 0x20)
wrapped = pattern(40, 0x30)
ciphertext = pattern(37, 0x60)
tag = pattern(16, 0x80)
k_mlkem = pattern(32, 0xA0)
kem_pk = pattern(1184, 0x01)
sig_pk = pattern(1952, 0x02)
kem_ct = pattern(1088, 0x03)

def out(name, b): print(name, b.hex())

plain = u32(len("файл.txt".encode())) + "файл.txt".encode() + u64(5) + b"hello"
out("FILE_PLAINTEXT", plain)

aad = b"edu-vault-file-v1" + u32(FORMAT) + u32(SUITE) + uuid + file_id
out("AAD", aad)

out("KEK", hkdf_sha3_256(k_mlkem, uuid, b"edu-vault-kek-v1" + u32(SUITE), 32))

obj = u32(FORMAT) + u32(SUITE) + uuid + file_id + nonce + wrapped + u64(len(ciphertext)) + ciphertext + tag
out("ENCRYPTED_FILE", obj)
out("LEAF", sha3(0x00, obj))

out("EMPTY_ROOT", sha3(0x03, b"edu-vault-empty-tree-v1"))
out("KEM_KEY_ID", sha3(0x12, kem_pk))
out("SIG_KEY_ID", sha3(0x13, sig_pk))
out("KEM_CT_HASH", sha3(0x11, kem_ct))

root = sha3(0x00, obj)  # дерево из одного листа: root = leaf (решение M-1)
manifest = (u32(FORMAT) + u32(SUITE) + uuid + u64(7) + u64(1) + root
            + sha3(0x11, kem_ct) + sha3(0x12, kem_pk) + sha3(0x13, sig_pk))
assert len(manifest) == 168
out("MANIFEST", manifest)
out("MANIFEST_HASH", sha3(0x10, manifest))

trusted = u32(FORMAT) + u32(SUITE) + uuid + u64(7) + sha3(0x10, manifest)
assert len(trusted) == 64
out("TRUSTED_STATE", trusted)
