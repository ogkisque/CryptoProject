#!/usr/bin/env python3
"""Конвертирует NIST ACVP-векторы ML-DSA-65 в строчный формат mldsa65_acvp.txt.

Источник: https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
  ML-DSA-{keyGen,sigGen,sigVer}-FIPS204/internalProjection.json
Использование: gen_mldsa_acvp.py <dir с файлами ML-DSA-<op>-FIPS204-internalProjection.json> > mldsa65_acvp.txt

Формат (hex через пробел; "-" = пустое поле):
  KEYGEN <seed> <pk> <sk>
  SIGGEN <rnd32> <sk> <message> <context> <signature>   (deterministic: rnd = 0^32)
  SIGVER <1|0> <pk> <message> <context> <signature>
Берутся только external/pure (то, что использует проект), первые PER_GROUP тестов группы.
"""
import json, sys, os

PER_GROUP = 8
d = sys.argv[1]
def load(op):
    return json.load(open(os.path.join(d, f"ML-DSA-{op}-FIPS204-internalProjection.json")))
def h(x): return x.lower() if x else "-"

for g in load("keyGen")["testGroups"]:
    if g["parameterSet"] != "ML-DSA-65": continue
    for t in g["tests"][:PER_GROUP]:
        print("KEYGEN", h(t["seed"]), h(t["pk"]), h(t["sk"]))

for g in load("sigGen")["testGroups"]:
    if g["parameterSet"] != "ML-DSA-65" or g["signatureInterface"] != "external" or g["preHash"] != "pure": continue
    for t in g["tests"][:PER_GROUP]:
        rnd = "00" * 32 if g["deterministic"] else h(t["rnd"])
        print("SIGGEN", rnd, h(t["sk"]), h(t["message"]), h(t["context"]), h(t["signature"]))

for g in load("sigVer")["testGroups"]:
    if g["parameterSet"] != "ML-DSA-65" or g["signatureInterface"] != "external" or g["preHash"] != "pure": continue
    for t in g["tests"][:PER_GROUP]:
        print("SIGVER", 1 if t["testPassed"] else 0, h(t["pk"]), h(t["message"]), h(t["context"]), h(t["signature"]))
