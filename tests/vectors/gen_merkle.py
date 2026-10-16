#!/usr/bin/env python3
"""Независимая (hashlib) реализация Merkle из docs/format_v1.md §6 -> merkle_vectors.txt.

Объект i (i = 0..N-1) = bytes([i]) * (i + 1); объекты уже "отсортированы".
Строка: "<N> <root_hex>". N = 0 даёт EMPTY_ROOT.
Использование: gen_merkle.py > merkle_vectors.txt
"""
import hashlib

def H(prefix, *parts):
    m = hashlib.sha3_256(bytes([prefix]))
    for p in parts: m.update(p)
    return m.digest()

def root(objs):
    if not objs: return H(0x03, b"edu-vault-empty-tree-v1")
    level = [H(0x00, o) for o in objs]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(H(0x01, level[i], level[i + 1]) if i + 1 < len(level) else H(0x02, level[i]))
        level = nxt
    return level[0]

for n in range(0, 18):
    print(n, root([bytes([i]) * (i + 1) for i in range(n)]).hex())
