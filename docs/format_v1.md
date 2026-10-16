# Формат v1 — сводная байтовая спецификация

Сжатая выжимка из `crypto_project.md` (§10–§31) плюс **решения по местам, где ТЗ допускает двоякое толкование**. Эти решения надо зафиксировать до реализации Milestone 1–2: если поменять их потом, сломаются уже созданные хранилища и test vectors.

Константы в коде лежат в `include/vault/common/constants.hpp`.

## 1. Примитивы кодирования

| Тип | Кодирование |
|---|---|
| `u32` / `u64` | big-endian, ровно 4 / 8 байт |
| `bytes[N]` (фиксированный) | ровно N байт, без длины |
| переменный массив | `u32 len` или `u64 len`, затем `len` байт |
| строковые метки (`"edu-vault-..."`) | сырые ASCII-байты **без длины и без `\0`** — допустимо, т.к. это константы известной длины, всегда стоящие в начале |

Парсер отклоняет: неверные длины, нехватку байт, trailing data, неподдерживаемые `format_version` и `crypto_suite_id`. Длину поля сначала сравнивает с остатком буфера и только потом выделяет память.

## 2. FilePlaintext (вход AES-GCM)

```
u32   filename_length        (1 .. kMaxFilenameLength=4096, политика прототипа)
bytes filename               (валидный UTF-8)
u64   file_data_length
bytes file_data
```
После расшифрования всё должно разобраться ровно до конца буфера.

## 3. AAD

```
"edu-vault-file-v1"  (17 байт)
u32 format_version
u32 crypto_suite_id
bytes[16] storage_uuid
bytes[16] file_id
```
Итого 17 + 4 + 4 + 16 + 16 = 57 байт.

## 4. KEK

```
KEK = HKDF-SHA3-256(IKM = K_MLKEM (32),
                    salt = storage_uuid (16),
                    info = "edu-vault-kek-v1" (16 байт) || u32 crypto_suite_id,
                    L = 32)
```
`info` = 20 байт.

## 5. EncryptedFileV1

```
off  size  поле
0    4     u32 format_version = 1
4    4     u32 crypto_suite_id = 1
8    16    storage_uuid
24   16    file_id
40   12    nonce
52   40    wrapped_DEK  (AES-256-KW, RFC 3394, IV A6A6A6A6A6A6A6A6)
92   8     u64 ciphertext_length = N
100  N     ciphertext   (= |CanonicalEncode(FilePlaintext)|, GCM не меняет длину)
100+N 16   gcm_tag
```
Полный размер = 116 + N.

## 6. Merkle Tree

```
leaves = [ SHA3(0x00 || CanonicalEncode(obj)) for obj in sort_by_file_id(objects) ]

if len(leaves) == 0: root = SHA3(0x03 || "edu-vault-empty-tree-v1")
level = leaves
while len(level) > 1:
    next = []
    for i in 0, 2, 4, ...:
        if i+1 < len(level): next.append(SHA3(0x01 || level[i] || level[i+1]))
        else:                next.append(SHA3(0x02 || level[i]))      # непарный, без дублирования
    level = next
root = level[0]
```

**Решение M-1 (одиночный лист):** при `file_count == 1` корень равен самому листу, то есть `SHA3(0x00 || obj)`, без обёртки `0x02`. Обёртка 0x02 применяется только к непарному узлу на уровне, где узлов больше одного. Неоднозначности это не создаёт: `file_count` входит в Manifest, а префиксы у листа и внутренних узлов разные.

**Proof.** Каждый шаг доказательства содержит `kind ∈ {SiblingLeft, SiblingRight, Unpaired}` и, кроме `Unpaired`, 32-байтного соседа. Проверяющий пересчитывает путь до корня. `leaf_count` входит в proof, чтобы проверяющий мог восстановить, на каких уровнях узел непарный.

## 7. ManifestV1 (168 байт)

```
off  size
0    4    u32 format_version
4    4    u32 crypto_suite_id
8    16   storage_uuid
24   8    u64 generation
32   8    u64 file_count
40   32   merkle_root
72   32   kem_ct_hash   = SHA3(0x11 || CT_KEM)
104  32   kem_key_id    = SHA3(0x12 || PK_KEM)
136  32   sig_key_id    = SHA3(0x13 || PK_SIG)
```
`manifest_hash = SHA3(0x10 || manifest_bytes)`.

## 8. Подпись Manifest

* ML-DSA-65, **pure**-вариант (не HashML-DSA), context = `"edu-vault-manifest-v1"` (21 байт). По FIPS 204 подписывается `M' = 0x00 || u8(len(ctx)) || ctx || manifest_bytes`; это делает сама библиотека: в liboqs — `OQS_SIG_sign_with_ctx_str`.
* **Решение S-1:** в продакшене подпись hedged (rnd от CSPRNG). Для тестов CPU==GPU используется детерминированный режим (`rnd = 0^32`) и seed для keygen.
* Подпись на диске хранится в `manifest.sig`: ровно 3309 байт, без заголовка. Файл другого размера означает ошибку формата.

## 9. TrustedStateV1 (локальный, 64 байта)

```
u32 format_version | u32 crypto_suite_id | bytes[16] storage_uuid
u64 trusted_generation | bytes[32] trusted_manifest_hash
```
В M1 поля `trusted_generation = 0` и `trusted_manifest_hash = 0^32` не используются.

## 10. Раскладка на диске по этапам

**Недоверенное хранилище**

```
M1–M2 (FlatStorage)               M3+ (GenerationStorage)
vault/                            vault/
  kem.ct          (1088 B)          kem.ct
  objects/                          generations/
    <32hex file_id>.obj               0000000000000000/
  manifest.bin    (M2)                  objects/<32hex>.obj
  manifest.sig    (M2)                  manifest.bin
                                        manifest.sig
                                      0000000000000001/ ...
                                      0000000000000002.tmp/   ← orphan после crash
                                    optional_cache/
```
* Имя поколения: 16 hex-цифр (`%016x`), в нижнем регистре.
* **Решение L-1:** в M3 неизменённые объекты переходят в новое поколение через **hardlink** (объекты immutable). Если hardlink невозможен — копия + fsync.
* **Решение L-2:** имя файла объекта должно совпадать с `file_id` внутри объекта. Несовпадение — ошибка `VerifyStep::ObjectNameMismatch`. Это дополнительная проверка, основная защита всё равно Merkle. Файлы с посторонними именами/расширениями внутри `objects/` тоже считаются ошибкой.
* Состояние M1/M2 мигрировать в M3 не требуется: хранилища прототипа пересоздаются. Если понадобится, `vault migrate` — отдельная задача.

**Доверенная область** (по умолчанию `./trusted`, права 0700/0600)

```
trusted/
  trusted_state.bin
  keys/kem.pk  kem.sk  sig.pk(M2)  sig.sk(M2)
```

## 11. Порядок проверки (`vault verify`, §27/§52)

1. Загрузка TrustedState и публичных ключей.
2. Загрузка `manifest.bin` и `manifest.sig` (для M3 — поколения `trusted_generation`).
3. Канонический разбор Manifest.
4. `format_version`, `crypto_suite_id`, `storage_uuid` == trusted.
5. `kem_key_id`, `sig_key_id` == SHA3 от доверенных PK.
6. ML-DSA Verify.
7. `generation == trusted_generation` (M3).
8. `manifest_hash == trusted_manifest_hash` (M3).
9. `SHA3(0x11 || kem.ct) == kem_ct_hash`.
10. Разбор объектов, привязка к uuid/version/suite, имя == file_id, уникальность file_id.
11. `file_count`.
12. Листья и Merkle root == `manifest.merkle_root`.

Decaps выполняется только после того, как прошли все 12 шагов.

## 12. Открытые вопросы

| # | Вопрос | Текущее решение |
|---|---|---|
| Q1 | Одиночный лист Merkle | root = leaf (M-1) |
| Q2 | Нужен ли `vault gc` отдельной командой | да, `vault gc`; GC никогда не запускается автоматически внутри commit |
| Q3 | Поддерживает ли cuPQC ML-DSA context string и derand API | проверить на GPU-машине (M6). Если нет — собрать `M'` вручную и вызвать internal sign; для KAT использовать derand |
| Q4 | Большие файлы (> RAM) | в прототипе файл целиком в памяти. Потоковый GCM всё равно потребовал бы буферизации до проверки tag |
