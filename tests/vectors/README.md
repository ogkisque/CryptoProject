# Test vectors

Сюда кладутся эталонные векторы (файлы не генерируются автоматически — скачать один раз и закоммитить).

| Примитив | Источник | Что проверяем |
|---|---|---|
| SHA3-256 | NIST CAVP `SHA3_256ShortMsg.rsp`, `SHA3_256LongMsg.rsp` | CPU и GPU hash backend |
| AES-256-GCM | NIST CAVP `gcmEncryptExtIV256.rsp` / `gcmDecrypt256.rsp` (IV 96 bit, tag 128 bit) | обёртка над OpenSSL, отказ при неверном tag |
| AES-256-KW | RFC 3394 §4.6 (256-bit KEK, 256-bit key data), NIST CAVP `KW_AE_256.txt`/`KW_AD_256.txt` | wrap/unwrap, отказ integrity check |
| HKDF-SHA3-256 | официальных векторов нет → сгенерировать независимой реализацией (Python `cryptography`: `HKDF(hashes.SHA3_256())`), сохранить в `hkdf_sha3_256.json` | |
| ML-KEM-768 | NIST ACVP-Server JSON (`ML-KEM-keyGen-FIPS203`, `ML-KEM-encapDecap-FIPS203`) | keygen/encaps с фиксированными seed, decaps; CPU vs GPU байт-в-байт |
| ML-DSA-65 | NIST ACVP-Server JSON (`ML-DSA-keyGen-FIPS204`, `ML-DSA-sigGen-FIPS204`, `ML-DSA-sigVer-FIPS204`) | keygen(seed), детерминированная подпись с context, verify |
| Формат v1 | `format_v1_vectors.json` — генерируются нашей CPU-реализацией после ревью и фиксируются | регрессия формата: EMPTY_ROOT, Merkle на 1..7 листьях, Manifest hash, AAD, KEK |

ACVP: https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
