#!/usr/bin/env python3
"""Конвертирует NIST ACVP-векторы ML-KEM-768 в строчный формат mlkem768_acvp.txt.

Источник: https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
  ML-KEM-{keyGen,encapDecap}-FIPS203/internalProjection.json
Использование: gen_mlkem_acvp.py <dir с файлами ML-KEM-<op>-FIPS203-internalProjection.json> > mlkem768_acvp.txt

Формат (hex через пробел):
  KEYGEN  <d||z> <ek> <dk>
  ENCAPS  <ek> <m> <c> <k>
  DECAPS  <dk> <c> <k>          (в т.ч. изменённые c -> k = implicit rejection)
  EKCHECK <1|0> <ek>            (проверка модуля открытого ключа, FIPS 203 §7.2)
  DKCHECK <1|0> <dk>            (проверка хеша внутри секретного ключа, FIPS 203 §7.3)
Берутся первые PER_GROUP тестов каждой группы ML-KEM-768.
"""
import json, os, sys

PER_GROUP = 8
d = sys.argv[1]
def load(op):
    return json.load(open(os.path.join(d, f"ML-KEM-{op}-FIPS203-internalProjection.json")))
def h(x): return x.lower()

for g in load("keyGen")["testGroups"]:
    if g["parameterSet"] != "ML-KEM-768": continue
    for t in g["tests"][:PER_GROUP]:
        print("KEYGEN", h(t["d"]) + h(t["z"]), h(t["ek"]), h(t["dk"]))

for g in load("encapDecap")["testGroups"]:
    if g["parameterSet"] != "ML-KEM-768": continue
    fn = g["function"]
    for t in g["tests"][:PER_GROUP]:
        if fn == "encapsulation":
            print("ENCAPS", h(t["ek"]), h(t["m"]), h(t["c"]), h(t["k"]))
        elif fn == "decapsulation":
            print("DECAPS", h(t["dk"]), h(t["c"]), h(t["k"]))
        elif fn == "encapsulationKeyCheck":
            print("EKCHECK", "1" if t["testPassed"] else "0", h(t["ek"]))
        elif fn == "decapsulationKeyCheck":
            print("DKCHECK", "1" if t["testPassed"] else "0", h(t["dk"]))
