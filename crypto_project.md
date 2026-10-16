# Тема

**Разработка и экспериментальное исследование защищённого файлового хранилища с постквантовой защитой ключевого материала и GPU-ускоренным контролем целостности**

---

# Цель работы

Разработать прототип файлового хранилища, обеспечивающего:

- конфиденциальность и аутентичность содержимого файлов с помощью AES-256-GCM;
- индивидуальный симметричный ключ DEK для каждого зашифрованного объекта;
- защиту DEK с помощью AES-256-KW;
- постквантовую защиту ключевого материала с помощью ML-KEM-768;
- криптографическое разделение назначения секрета ML-KEM и ключа KEK с помощью KDF;
- защиту состояния хранилища от несанкционированной модификации с помощью SHA3-256, Merkle Tree и ML-DSA-65;
- криптографическую привязку `CT_KEM` и используемых публичных ключей к подписанному состоянию хранилища;
- обнаружение rollback-атак и fork-состояний с помощью доверенного якоря состояния;
- crash-safe подтверждение нового поколения хранилища;
- однозначную каноническую сериализацию всех криптографически значимых структур;
- GPU-ускорение операций SHA3/Merkle Tree, ML-KEM и ML-DSA с использованием NVIDIA CUDA/cuPQC;
- экспериментальное сравнение CPU- и GPU-реализаций при различных размерах данных и степени пакетного параллелизма.

---

# 1. Криптографические примитивы

В системе используются следующие криптографические механизмы.

## AES-256-GCM

Используется для:

- шифрования содержимого каждого файла;
- аутентификации ciphertext;
- аутентификации связанных с объектом метаданных через AAD.

Для каждого зашифрованного объекта применяется отдельный случайный 256-битный DEK.

Размер authentication tag:

```text
128 bit
```

Размер nonce:

```text
96 bit
```

Один DEK не должен использоваться более чем для одной операции AES-GCM encryption.

---

## AES-256-KW

Используется для защиты индивидуальных DEK.

Каждый DEK имеет длину:

```text
256 bit = 32 bytes
```

и оборачивается с помощью KEK:

```text
wrapped_DEK = AES-256-KW(KEK, DEK)
```

Для 32-байтного DEK результат AES-KW имеет длину 40 байт.

---

## ML-KEM-768

Используется для формирования общего 256-битного секрета, из которого выводится KEK.

ML-KEM обеспечивает постквантовую защиту ключевого материала.

---

## KDF

Между shared secret ML-KEM и AES-256 KEK используется механизм вывода ключа.

В версии формата `v1` используется:

```text
HKDF-SHA3-256
```

Вход:

```text
IKM  = K_MLKEM
salt = storage_uuid
info = "edu-vault-kek-v1" || crypto_suite_id
```

Результат:

```text
KEK = 32 bytes
```

KDF обеспечивает:

- domain separation;
- привязку KEK к конкретному хранилищу;
- возможность дальнейшего расширения схемы управления ключами.

---

## SHA3-256

Используется для:

- хеширования зашифрованных объектов;
- построения Merkle Tree;
- вычисления `Manifest` hash;
- вычисления хеша `CT_KEM`;
- вычисления идентификаторов криптографических ключей.

---

## ML-DSA-65

Используется для цифровой подписи состояния хранилища.

Подписывается каноническое бинарное представление `Manifest`.

Для подписей Manifest используется отдельный контекст:

```text
"edu-vault-manifest-v1"
```

---

# 2. Идентификатор криптографического набора

Для возможности изменения алгоритмов в будущих версиях вводится:

```text
crypto_suite_id
```

Для текущей версии:

```text
crypto_suite_id = 1
```

Suite `1` означает:

```text
AES-256-GCM
AES-256-KW
ML-KEM-768
HKDF-SHA3-256
SHA3-256
ML-DSA-65
```

Значение `crypto_suite_id` входит:

- в AAD зашифрованных файлов;
- в Manifest;
- в KDF context.

---

# 3. Ключи системы

При создании хранилища один раз создаются две постквантовые пары ключей.

## ML-KEM-768

```text
PK_KEM — открытый ключ ML-KEM
SK_KEM — секретный ключ ML-KEM
```

Они используются для восстановления ключевого материала KEK.

Для идентификации ключа определяется:

```text
kem_key_id =
    SHA3-256(
        0x12 ||
        PK_KEM
    )
```

---

## ML-DSA-65

```text
PK_SIG — открытый ключ проверки подписи
SK_SIG — секретный ключ формирования подписи
```

Они используются для аутентификации состояния всего хранилища.

Идентификатор:

```text
sig_key_id =
    SHA3-256(
        0x13 ||
        PK_SIG
    )
```

---

# 4. Доверенная область

Следующие данные не хранятся внутри атакуемого файлового хранилища:

```text
SK_KEM
PK_KEM

SK_SIG
PK_SIG

storage_uuid

trusted_generation
trusted_manifest_hash

crypto_suite_id
```

Логически доверенное состояние имеет вид:

```text
TrustedState {
    storage_uuid
    crypto_suite_id

    trusted_generation
    trusted_manifest_hash
}
```

Доверенное хранилище ключей считается защищённой частью системы.

Атакующий не может:

- читать секретные ключи;
- изменять ключи;
- изменять `TrustedState`;
- выполнять rollback самого доверенного состояния.

Rollback доверенной области находится вне threat model проекта.

---

# 5. Создание хранилища

При первоначальной инициализации выполняется:

```text
ML-KEM-768.KeyGen
        │
        ├──► PK_KEM
        └──► SK_KEM
```

и:

```text
ML-DSA-65.KeyGen
        │
        ├──► PK_SIG
        └──► SK_SIG
```

После этого создаётся:

```text
storage_uuid = random 128 bit
```

---

# 6. Формирование ключа KEK

При инициализации выполняется:

```text
ML-KEM-768.Encaps(PK_KEM)
            │
            ├────────► CT_KEM
            │
            └────────► K_MLKEM
```

где:

```text
CT_KEM   — ciphertext ML-KEM
K_MLKEM  — 256-битный shared secret
```

После этого:

```text
K_MLKEM
    │
    ▼
HKDF-SHA3-256
    │
    ▼
KEK
```

Конкретно:

```text
KEK =
    HKDF-SHA3-256(
        IKM  = K_MLKEM,
        salt = storage_uuid,
        info = "edu-vault-kek-v1" ||
               crypto_suite_id,
        L    = 32 bytes
    )
```

`CT_KEM` не является секретным и сохраняется в недоверенном файловом хранилище.

`K_MLKEM` и `KEK` постоянно на диске не сохраняются.

---

# 7. Восстановление KEK

При открытии уже существующего хранилища сначала должна быть проверена целостность состояния.

Только после проверки Manifest и криптографической привязки `CT_KEM` выполняется:

```text
CT_KEM + SK_KEM
       │
       ▼
ML-KEM-768.Decaps
       │
       ▼
K_MLKEM
       │
       ▼
HKDF-SHA3-256
       │
       ▼
KEK
```

После закрытия хранилища:

```text
K_MLKEM
KEK
DEK
plaintext
```

удаляются из оперативной памяти настолько, насколько это позволяет конкретная реализация.

---

# 8. Добавление файла

Для каждого нового шифрования генерируется отдельный случайный ключ:

```text
DEK_i = CSPRNG(256 bit)
```

Таким образом:

```text
file1 → DEK_1
file2 → DEK_2
file3 → DEK_3
...
```

Один DEK не используется для нескольких AES-GCM encryption.

Если файл в будущем изменяется, для новой версии объекта генерируется новый DEK.

---

# 9. Идентификатор файла

Для каждого нового файла генерируется:

```text
file_id = random 128 bit
```

Перед подтверждением транзакции программа должна убедиться, что данный `file_id` отсутствует в текущем состоянии хранилища.

Дублирование `file_id` запрещено.

---

# 10. Шифрование файла

Для нового объекта генерируется:

```text
nonce = random 96 bit
```

Формируется AAD:

```text
AAD =
    "edu-vault-file-v1" ||
    format_version      ||
    crypto_suite_id     ||
    storage_uuid        ||
    file_id
```

Все числовые значения кодируются в каноническом бинарном формате, определённом далее.

Имя исходного файла не хранится в открытом виде.

Перед шифрованием plaintext имеет логическую структуру:

```text
FilePlaintext {
    filename_length
    filename
    file_data_length
    file_data
}
```

После чего выполняется:

```text
AES-256-GCM(
    key   = DEK_i,
    nonce = nonce,
    AAD   = AAD,
    data  = CanonicalEncode(FilePlaintext)
)
             │
             ├──► ciphertext
             └──► gcm_tag
```

Размер:

```text
gcm_tag = 128 bit
```

Открытый файл на диске хранилища не сохраняется.

---

# 11. Защита DEK

DEK не хранится рядом с ciphertext в открытом виде.

Выполняется:

```text
              KEK
               │
               ▼
          AES-256-KW
               ▲
               │
              DEK
               │
               ▼
         wrapped_DEK
```

Иерархия ключевого материала:

```text
                 SK_KEM
                    │
                    │ + CT_KEM
                    ▼
              ML-KEM Decaps
                    │
                    ▼
                K_MLKEM
                    │
                    ▼
            HKDF-SHA3-256
                    │
                    ▼
                   KEK
                    │
          ┌─────────┼─────────┐
          ▼         ▼         ▼
       unwrap    unwrap    unwrap
          │         │         │
        DEK_1     DEK_2     DEK_N
          │         │         │
          ▼         ▼         ▼
      AES-GCM   AES-GCM   AES-GCM
          │         │         │
          ▼         ▼         ▼
       file1     file2      fileN
```

Таким образом:

```text
SK_KEM
    ↓
защищает возможность получения K_MLKEM

K_MLKEM
    ↓
используется только для вывода KEK

KEK
    ↓
защищает DEK

DEK
    ↓
защищает один конкретный encrypted object
```

---

# 12. Каноническая сериализация

Криптографические операции выполняются только над однозначным каноническим бинарным представлением структур.

Запрещается использовать неопределённое:

```text
A || B || C
```

если размеры полей не фиксированы или заранее не известны.

Для всех структур версии `v1` устанавливаются следующие правила:

```text
u32 — unsigned 32-bit, big-endian
u64 — unsigned 64-bit, big-endian

byte arrays — точное число байт,
если размер фиксирован

variable byte arrays —
обязательно имеют явное поле длины
```

Парсер должен отклонять:

- некорректные длины;
- отсутствующие обязательные поля;
- trailing data там, где он не разрешён;
- дублированные `file_id`;
- неподдерживаемый `format_version`;
- неподдерживаемый `crypto_suite_id`.

---

# 13. Каноническое представление plaintext

Перед AES-GCM данные представляются как:

```text
u32 filename_length
byte filename[filename_length]

u64 file_data_length
byte file_data[file_data_length]
```

`filename` кодируется в UTF-8.

После расшифрования должно выполняться:

```text
decoded_length == plaintext_length
```

Наличие неожиданных дополнительных данных считается ошибкой формата.

---

# 14. Формат зашифрованного объекта

Логическая структура объекта:

```text
EncryptedFileV1 {
    format_version
    crypto_suite_id
    storage_uuid
    file_id

    nonce
    wrapped_DEK

    ciphertext_length
    ciphertext
    gcm_tag
}
```

Каноническое бинарное представление:

```text
u32      format_version
u32      crypto_suite_id
16 bytes storage_uuid
16 bytes file_id

12 bytes nonce
40 bytes wrapped_DEK

u64      ciphertext_length
N bytes  ciphertext
16 bytes gcm_tag
```

`filename` находится только внутри `ciphertext`.

---

# 15. Чтение файла

Чтение объекта разрешается только после проверки текущего состояния хранилища.

Последовательность:

```text
TrustedState
      │
      ▼
Manifest verification
      │
      ▼
Merkle state verification
      │
      ▼
CT_KEM binding verification
      │
      ▼
ML-KEM Decaps
      │
      ▼
K_MLKEM
      │
      ▼
KDF
      │
      ▼
KEK
      │
      ▼
AES-KW unwrap
      │
      ▼
DEK
      │
      ▼
AES-256-GCM decrypt + verify
      │
      ▼
filename + file_data
```

Если атакующий изменил:

```text
ciphertext
nonce
AAD-associated metadata
gcm_tag
```

AES-GCM authentication завершается ошибкой и plaintext не должен передаваться вызывающей стороне.

---

# 16. Domain separation для SHA3-256

Для различных типов SHA3-хешей используются разные префиксы.

Определяются:

```text
0x00 — Merkle leaf

0x01 — Merkle binary parent

0x02 — Merkle unpaired node

0x03 — empty Merkle tree

0x10 — Manifest hash

0x11 — CT_KEM hash

0x12 — ML-KEM public-key identifier

0x13 — ML-DSA public-key identifier
```

Это исключает использование одного типа хешируемого объекта в роли другого.

---

# 17. Контроль состояния каждого encrypted object

Для каждого зашифрованного объекта вычисляется:

```text
Leaf_i =
    SHA3-256(
        0x00 ||
        CanonicalEncode(EncryptedFileV1)
    )
```

Таким образом, Merkle leaf аутентифицирует:

```text
format_version
crypto_suite_id
storage_uuid
file_id
nonce
wrapped_DEK
ciphertext
gcm_tag
```

---

# 18. Канонический порядок объектов

Перед построением Merkle Tree все encrypted objects сортируются:

```text
по file_id
в лексикографическом порядке
по 16 байтам идентификатора
```

Файловая система и порядок чтения directory entries не влияют на Merkle Root.

Два объекта с одинаковым `file_id` считаются ошибкой состояния.

---

# 19. Построение Merkle Tree

Из отсортированного массива leaf hashes строится бинарное Merkle Tree.

Для двух дочерних узлов:

```text
Hparent =
    SHA3-256(
        0x01 ||
        Hleft ||
        Hright
    )
```

Если на уровне остаётся один непарный hash:

```text
Hsingle =
    SHA3-256(
        0x02 ||
        Hlast
    )
```

Таким образом, последний узел не дублируется.

---

# 20. Пустое Merkle Tree

Для хранилища без файлов определяется фиксированное значение:

```text
EMPTY_ROOT =
    SHA3-256(
        0x03 ||
        "edu-vault-empty-tree-v1"
    )
```

Если:

```text
file_count == 0
```

то:

```text
merkle_root = EMPTY_ROOT
```

---

# 21. Привязка CT_KEM

`CT_KEM` входит в доверенное криптографическое состояние не непосредственно, а посредством хеша:

```text
kem_ct_hash =
    SHA3-256(
        0x11 ||
        CT_KEM
    )
```

`kem_ct_hash` включается в Manifest.

Это означает, что незаметная замена:

```text
CT_KEM → CT_KEM'
```

невозможна без нарушения проверки подписанного состояния.

---

# 22. Manifest

После каждого изменения формируется:

```text
ManifestV1 {
    format_version
    crypto_suite_id

    storage_uuid

    generation
    file_count

    merkle_root

    kem_ct_hash
    kem_key_id
    sig_key_id
}
```

Каноническое бинарное представление:

```text
u32      format_version
u32      crypto_suite_id

16 bytes storage_uuid

u64      generation
u64      file_count

32 bytes merkle_root

32 bytes kem_ct_hash
32 bytes kem_key_id
32 bytes sig_key_id
```

Manifest не содержит полей переменной длины.

---

# 23. Manifest hash

Для идентификации конкретного состояния вычисляется:

```text
manifest_hash =
    SHA3-256(
        0x10 ||
        CanonicalEncode(ManifestV1)
    )
```

Именно это значение используется как доверенный state anchor.

---

# 24. Аутентификация Manifest

Manifest подписывается:

```text
signature =
    ML-DSA-65.Sign(
        SK_SIG,
        context =
            "edu-vault-manifest-v1",
        message =
            CanonicalEncode(ManifestV1)
    )
```

На диске сохраняются:

```text
ManifestV1
Signature
```

Проверка:

```text
ManifestV1
Signature
PK_SIG
    │
    ▼
ML-DSA-65.Verify
    │
    ▼
valid / invalid
```

Только после успешной проверки подписи содержимое Manifest может использоваться дальше.

---

# 25. Защита от rollback

Одной подписи недостаточно против возврата к ранее корректно подписанному состоянию.

Пример:

```text
generation = 15
      ↓
атакующий заменяет всё хранилище
      ↓
старое состояние generation = 10
```

Подпись поколения `10` математически остаётся корректной.

Поэтому после каждой подтверждённой транзакции:

```text
generation := generation + 1
```

В доверенной области хранится:

```text
trusted_generation
trusted_manifest_hash
```

---

# 26. Защита от fork одного поколения

Проверка только:

```text
Manifest.generation ==
    trusted_generation
```

недостаточна в случае существования двух различных корректно подписанных Manifest с одним generation.

Поэтому дополнительно обязательно:

```text
SHA3-256(
    0x10 ||
    CanonicalEncode(Manifest)
)
==
trusted_manifest_hash
```

Следовательно, доверенная область указывает не просто на номер поколения, а на конкретное принятое состояние.

---

# 27. Проверка текущего состояния

При открытии хранилища выполняется следующая последовательность.

## Шаг 1. Загрузка TrustedState

Получаются:

```text
storage_uuid
crypto_suite_id
trusted_generation
trusted_manifest_hash

PK_SIG
PK_KEM
SK_KEM
```

---

## Шаг 2. Загрузка Manifest и Signature

Из недоверенной директории загружаются:

```text
Manifest
Signature
```

---

## Шаг 3. Проверка формата

Проверяются:

```text
Manifest.format_version
Manifest.crypto_suite_id
Manifest.storage_uuid
```

Они должны соответствовать доверенной конфигурации.

---

## Шаг 4. Проверка key identifiers

Вычисляются:

```text
SHA3-256(0x12 || PK_KEM)

SHA3-256(0x13 || PK_SIG)
```

и сравниваются с:

```text
Manifest.kem_key_id
Manifest.sig_key_id
```

---

## Шаг 5. Проверка ML-DSA

Выполняется проверка подписи Manifest.

При ошибке хранилище считается недоверенным.

---

## Шаг 6. Проверка generation

Требуется:

```text
Manifest.generation ==
    trusted_generation
```

---

## Шаг 7. Проверка конкретного Manifest

Вычисляется:

```text
manifest_hash =
    SHA3-256(
        0x10 ||
        CanonicalEncode(Manifest)
    )
```

Требуется:

```text
manifest_hash ==
    trusted_manifest_hash
```

---

## Шаг 8. Проверка CT_KEM

Вычисляется:

```text
SHA3-256(
    0x11 ||
    CT_KEM
)
```

Результат должен совпадать с:

```text
Manifest.kem_ct_hash
```

---

## Шаг 9. Проверка объектов

Все encrypted objects:

1. разбираются каноническим parser;
2. проверяются на соответствие `storage_uuid`;
3. проверяются на соответствие `format_version`;
4. проверяются на соответствие `crypto_suite_id`;
5. проверяются на уникальность `file_id`;
6. сортируются по `file_id`.

---

## Шаг 10. Проверка file_count

Требуется:

```text
actual_file_count ==
    Manifest.file_count
```

---

## Шаг 11. Проверка Merkle Root

Для всех объектов пересчитываются:

```text
Leaf_i
```

и полный:

```text
merkle_root
```

Требуется:

```text
computed_merkle_root ==
    Manifest.merkle_root
```

Только после выполнения всех перечисленных проверок состояние считается текущим и доверенным.

---

# 28. Crash-safe commit protocol

Каждая операция изменения хранилища выполняется как транзакция.

Поколения являются логически immutable.

Новое состояние создаётся отдельно от текущего.

Пусть текущее доверенное поколение:

```text
N
```

Тогда транзакция создаёт:

```text
N + 1
```

---

## Шаг 1. Проверка текущего состояния

Перед изменением выполняется полная проверка поколения `N`.

---

## Шаг 2. Построение нового состояния

Создаётся временное состояние:

```text
generation = N + 1
```

Все изменения выполняются только внутри нового snapshot.

Состояние `N` не изменяется.

---

## Шаг 3. Построение Merkle Tree

Вычисляется новый:

```text
merkle_root
```

---

## Шаг 4. Создание Manifest

Создаётся:

```text
Manifest(N + 1)
```

---

## Шаг 5. Подпись Manifest

Вычисляется:

```text
Signature(N + 1)
```

---

## Шаг 6. Durable write

На недоверенный диск записываются:

```text
objects
Manifest
Signature
```

После записи выполняются необходимые операции синхронизации:

```text
fsync(files)
fsync(directory)
```

или эквивалентные механизмы конкретной платформы.

---

## Шаг 7. Публикация snapshot

Временное поколение атомарно переводится в завершённое состояние.

Например:

```text
generation_N+1.tmp
        ↓ atomic rename
generation_N+1
```

После этого выполняется синхронизация родительской директории.

---

## Шаг 8. Обновление TrustedState

Только после гарантированной записи поколения `N+1` обновляется:

```text
trusted_generation = N + 1

trusted_manifest_hash =
    SHA3-256(
        0x10 ||
        CanonicalEncode(
            Manifest(N+1)
        )
    )
```

Обновление TrustedState также должно быть атомарным.

---

## Шаг 9. Garbage collection

Только после успешного обновления TrustedState старое поколение может быть удалено.

Удаление старых поколений является отдельной операцией и не влияет на криптографическую корректность уже выполненного commit.

---

# 29. Поведение при crash

Если процесс завершился до обновления TrustedState:

```text
trusted_generation = N
```

и состояние `N+1` считается незавершённым или orphan snapshot.

При следующем запуске используется поколение `N`.

Если TrustedState уже обновлён до:

```text
N + 1
```

то новое поколение к этому моменту уже должно быть полностью записано и синхронизировано.

Это исключает состояние, при котором доверенная область указывает на ещё не сохранённый snapshot.

---

# 30. Рекомендуемая структура хранилища

Логическая структура может иметь вид:

```text
vault/
│
├── kem.ct
│
├── generations/
│   │
│   ├── 0000000000000000/
│   │   ├── objects/
│   │   ├── manifest.bin
│   │   └── manifest.sig
│   │
│   ├── 0000000000000001/
│   │   ├── objects/
│   │   ├── manifest.bin
│   │   └── manifest.sig
│   │
│   └── ...
│
└── optional_cache/
```

Merkle Tree может сохраняться как cache для ускорения.

Сохранённый Merkle Tree не считается доверенным.

Криптографически доверенным является только root после проверки Manifest и TrustedState.

---

# 31. Начальное пустое состояние

После `vault init` создаётся:

```text
generation = 0
file_count = 0
merkle_root = EMPTY_ROOT
```

Формируется:

```text
Manifest(0)
Signature(0)
```

и в доверенной области сохраняется:

```text
trusted_generation = 0
trusted_manifest_hash =
    SHA3-256(
        0x10 ||
        CanonicalEncode(Manifest(0))
    )
```

---

# 32. Добавление файла как транзакция

Команда:

```text
vault add <file>
```

выполняет:

```text
1. verify current state

2. generate unique file_id

3. generate DEK

4. generate nonce

5. encode filename + file_data

6. AES-GCM encrypt

7. AES-KW wrap DEK

8. build EncryptedFileV1

9. create generation N+1

10. sort objects by file_id

11. rebuild Merkle Tree

12. create Manifest(N+1)

13. ML-DSA sign Manifest

14. durable write

15. atomically update TrustedState
```

---

# 33. Удаление файла как транзакция

Команда:

```text
vault remove <file_id>
```

выполняет:

```text
1. verify current state

2. construct new object set
   without selected file_id

3. generation := N + 1

4. rebuild Merkle Tree

5. create Manifest

6. sign Manifest

7. durable write

8. update TrustedState
```

Криптографическое удаление старых ciphertext не гарантируется.

Физическое уничтожение старых данных зависит от файловой системы и носителя.

---

# 34. Операции чтения

Команды:

```text
vault list
vault extract
vault remove
```

не должны работать с непроверенным состоянием.

В рамках одного процесса результат полной проверки может кэшироваться до первого изменения состояния.

После любой транзакции состояние должно быть проверено или считаться доверенным только через успешно завершённый commit protocol.

---

# 35. Итоговая архитектура

```text
                  ДОВЕРЕННАЯ ОБЛАСТЬ
        ┌─────────────────────────────────┐
        │ SK_KEM                          │
        │ PK_KEM                          │
        │ SK_SIG                          │
        │ PK_SIG                          │
        │                                 │
        │ storage_uuid                    │
        │ crypto_suite_id                 │
        │ trusted_generation              │
        │ trusted_manifest_hash           │
        └────────────────┬────────────────┘
                         │
                         │
                         ▼
                  ML-KEM-768
              SK_KEM + CT_KEM
                         │
                         ▼
                     K_MLKEM
                         │
                         ▼
                  HKDF-SHA3-256
                         │
                         ▼
                        KEK
                         │
                    AES-256-KW
                         │
             ┌───────────┼───────────┐
             ▼           ▼           ▼
           DEK_1       DEK_2       DEK_N
             │           │           │
         AES-GCM     AES-GCM     AES-GCM
             │           │           │
             ▼           ▼           ▼
        Encrypted    Encrypted    Encrypted
          File 1       File 2       File N
             │           │           │
             └───────────┼───────────┘
                         │
                         ▼
                    SHA3-256
                  domain-separated
                         │
                         ▼
                    Merkle Tree
                         │
                         ▼
                    Merkle Root
                         │
                         │
CT_KEM ── SHA3 ──► kem_ct_hash
                         │
PK_KEM ── SHA3 ──► kem_key_id
                         │
PK_SIG ── SHA3 ──► sig_key_id
                         │
                         ▼
                     Manifest
                         │
                         ▼
                 ML-DSA-65 Sign
                         │
                         ▼
                    Signature
                         │
                         ▼
                  manifest_hash
                         │
                         ▼
                TrustedState anchor
```

---

# 36. Модель атакующего

Предполагается, что атакующий получает полный контроль над недоверенным файловым хранилищем.

Он может:

- читать все сохранённые данные;
- копировать всё хранилище;
- изменять любые байты;
- удалять файлы;
- добавлять собственные файлы;
- заменять один encrypted object другим;
- переименовывать объекты;
- изменять сохранённый Merkle Tree;
- изменять Manifest;
- изменять Signature;
- изменять `CT_KEM`;
- заменять целое поколение;
- восстанавливать старые корректные копии;
- создавать несколько файловых представлений одного поколения;
- анализировать систему с использованием классического или квантового компьютера.

При этом атакующий не имеет доступа к доверенному хранилищу.

Он не получает:

```text
SK_KEM
SK_SIG
TrustedState
```

и не способен изменять:

```text
trusted_generation
trusted_manifest_hash
trusted public keys
storage_uuid
```

Атакующий также не контролирует процесс программы в момент, когда секреты находятся в оперативной памяти.

---

# 37. Что защищает система

## Кража файлового хранилища

Атакующий может получить:

```text
CT_KEM
wrapped_DEK
ciphertext
GCM tag
Manifest
Signature
Merkle cache
```

но не получает:

```text
SK_KEM
```

Следовательно, он не способен получить корректный `K_MLKEM`, KEK и DEK.

---

## Изменение ciphertext

Обнаруживается:

```text
SHA3/Merkle Tree
```

при проверке состояния.

Кроме того, при расшифровании изменение обнаруживается:

```text
AES-GCM authentication
```

---

## Изменение nonce

Nonce входит в canonical encrypted object.

Следовательно, изменение nonce меняет:

```text
Merkle leaf
Merkle root
```

Дополнительно изменённый nonce приводит к неуспешной AES-GCM verification.

---

## Изменение wrapped_DEK

Изменяется:

```text
Merkle leaf
Merkle root
```

Кроме того, неправильный DEK не позволит успешно пройти AES-GCM verification.

---

## Замена encrypted object

Объект содержит:

```text
storage_uuid
file_id
```

и входит в Merkle Tree.

Подмена изменяет Merkle Root.

---

## Удаление объекта

Изменяются:

```text
file_count
merkle_root
```

Атакующий не может подписать новый Manifest.

---

## Добавление собственного объекта

Изменяются:

```text
file_count
merkle_root
```

Без `SK_SIG` сформировать новое корректно подписанное состояние невозможно.

---

## Подмена Merkle Root

Новый Root требует нового Manifest.

Новый Manifest требует корректной ML-DSA signature.

---

## Подмена Manifest

Manifest защищён одновременно:

```text
ML-DSA signature
+
trusted_manifest_hash
```

---

## Подмена публичного ключа подписи

`PK_SIG` находится в доверенной области.

Manifest также содержит:

```text
sig_key_id
```

Поэтому пара:

```text
attacker_PK_SIG
attacker_signature
```

не может быть незаметно принята системой.

---

## Подмена ML-KEM public key

Manifest содержит:

```text
kem_key_id
```

который сравнивается с доверенным `PK_KEM`.

---

## Подмена CT_KEM

Manifest содержит:

```text
kem_ct_hash
```

Поэтому изменение:

```text
CT_KEM → CT_KEM'
```

обнаруживается до ML-KEM decapsulation.

---

## Rollback к старой корректной копии

Обнаруживается сравнением:

```text
Manifest.generation
```

с:

```text
trusted_generation
```

и:

```text
manifest_hash
```

с:

```text
trusted_manifest_hash
```

---

## Fork одного generation

Если существуют:

```text
Manifest_A:
generation = N
root = A
```

и:

```text
Manifest_B:
generation = N
root = B
```

принят может быть только тот Manifest, чей hash совпадает с:

```text
trusted_manifest_hash
```

---

## Crash во время транзакции

Незавершённое поколение не становится доверенным, пока TrustedState не обновлён.

TrustedState обновляется только после durable write нового поколения.

---

# 38. Постквантовая защита

Для защиты ключевого материала используется:

```text
ML-KEM-768
```

Для аутентификации состояния:

```text
ML-DSA-65
```

Проект не заявляет, что все используемые примитивы имеют один и тот же формальный уровень постквантовой стойкости.

Формулировка проекта:

**постквантовая защита ключевого материала и цифровой подписи состояния хранилища**.

---

# 39. Что система намеренно не защищает

Проект не заявляет защиту в следующих случаях.

## Компрометация SK_KEM

Если атакующий получает:

```text
SK_KEM
```

он способен восстановить ключевой материал и расшифровать DEK.

---

## Компрометация SK_SIG

Если атакующий получает:

```text
SK_SIG
```

он способен подписывать произвольные состояния.

---

## Rollback доверенной области

Если атакующий способен одновременно откатить:

```text
TrustedState
```

вместе с файловым хранилищем, предлагаемая rollback-защита перестаёт работать.

Такой сценарий находится вне threat model.

---

## Компрометация работающего процесса

Во время работы в RAM могут временно присутствовать:

```text
SK_KEM
SK_SIG
K_MLKEM
KEK
DEK
plaintext
```

В зависимости от GPU-режима часть этих значений также может временно находиться в GPU memory.

---

## Уничтожение данных

Криптография может обнаружить отсутствие или повреждение данных, но не может восстановить уничтоженный файл без резервной копии.

---

## Аппаратные атаки

Вне модели проекта находятся:

- physical attacks;
- side-channel attacks;
- fault injection;
- cold-boot attacks;
- DMA attacks;
- атаки на устройство хранения ключей.

---

## Компрометация CSPRNG

Проект предполагает корректность криптографического генератора случайных чисел.

---

## Полное сокрытие метаданных

Проект не скрывает полностью:

- количество encrypted objects;
- размеры ciphertext;
- размер всего хранилища;
- номера generation;
- факт изменения состояния;
- временные характеристики операций;
- паттерны доступа на уровне файловой системы.

Имена исходных файлов при этом находятся внутри AES-GCM ciphertext.

---

## Безопасное физическое удаление

Удаление encrypted object не гарантирует физического стирания старых блоков SSD/HDD.

---

# 40. Криптографические инварианты

Реализация должна обеспечивать следующие свойства.

```text
1. Один DEK используется только
   для одного AES-GCM encryption.

2. file_id уникален внутри vault.

3. Все структуры имеют
   только одну canonical encoding.

4. Merkle leaves всегда сортируются
   по file_id.

5. CT_KEM всегда проверяется
   относительно signed Manifest.

6. Manifest всегда проверяется
   относительно trusted_manifest_hash.

7. generation изменяется
   только через commit protocol.

8. TrustedState обновляется
   только после durable write snapshot.

9. plaintext никогда не возвращается,
   если GCM authentication failed.

10. неподдерживаемая версия формата
    не интерпретируется эвристически.
```

---

# 41. GPU-часть проекта

GPU не является доверенным хранилищем и не является отдельным механизмом защиты.

GPU используется исключительно как вычислительный ускоритель.

На NVIDIA RTX 3050 с архитектурой SM 86 исследуются:

```text
SHA3-256

Merkle Tree construction

Merkle Tree verification

ML-KEM-768:
    KeyGen
    Encaps
    Decaps

ML-DSA-65:
    KeyGen
    Sign
    Verify
```

с использованием NVIDIA CUDA/cuPQC.

AES-256-GCM, AES-256-KW и KDF выполняются на CPU.

---

# 42. Требование эквивалентности CPU и GPU

GPU-реализация не должна изменять криптографическую семантику системы.

Для детерминированных операций требуется:

```text
CPU result ==
GPU result
```

байт-в-байт.

Это относится, например, к:

```text
SHA3-256
Merkle Tree construction
Merkle Root
Merkle proof verification
ML-DSA verification result
```

Для рандомизированных операций CPU и GPU сравниваются:

- по стандартным test vectors;
- по успешной взаимной проверке результатов;
- по функциональной корректности;
- по статистически корректному выполнению batch.

Равенство случайно сгенерированных ciphertext или signatures между независимыми запусками не требуется.

---

# 43. Работа с секретами на GPU

GPU не считается отдельной доверенной зоной.

Если для benchmark или реализации ML-KEM/ML-DSA секретные данные передаются в GPU memory, это рассматривается как часть работающего доверенного процесса.

После завершения операции реализация должна по возможности очищать временные GPU buffers.

Полная защита VRAM от аппаратного анализа находится вне scope проекта.

---

# 44. Экспериментальная часть

Исследование отвечает на вопрос:

**При каких размерах объектов, количестве независимых операций и размере batch применение GPU обеспечивает выигрыш относительно CPU с учётом стоимости передачи данных и запуска CUDA kernels?**

---

# 45. SHA3/Merkle benchmark

Исследуются размеры файлов:

```text
1 KiB
4 KiB
64 KiB
1 MiB
16 MiB
```

Количество файлов:

```text
10
100
1 000
10 000
100 000
```

Измеряются:

```text
CPU total time

GPU kernel time

CPU → GPU transfer time

GPU → CPU transfer time

GPU total time

throughput, GB/s

speedup =
    CPU_time /
    GPU_total_time
```

---

# 46. ML-KEM benchmark

Для ML-KEM-768 исследуются:

```text
KeyGen
Encaps
Decaps
```

для batch:

```text
1
10
100
1 000
10 000
```

Измеряются:

```text
operations/s

single-operation latency

total batch time

transfer overhead

CPU/GPU speedup
```

---

# 47. ML-DSA benchmark

Для ML-DSA-65 исследуются:

```text
KeyGen
Sign
Verify
```

для batch:

```text
1
10
100
1 000
10 000
```

Измеряются:

```text
operations/s

latency

total batch time

transfer overhead

CPU/GPU speedup
```

---

# 48. Точка окупаемости GPU

Отдельно определяется минимальный размер задачи, при котором:

```text
GPU_total_time < CPU_total_time
```

с учётом:

```text
memory allocation

host-to-device transfer

kernel launch overhead

device-to-host transfer

synchronization
```

Для каждого класса операций определяется crossover point.

---

# 49. Воспроизводимость benchmark

Команда benchmark должна фиксировать:

```text
CPU model

GPU model

GPU architecture

CUDA version

cuPQC version

compiler and flags

number of operations

input sizes

batch size

number of warm-up runs

number of measured runs
```

Желательно выводить:

```text
mean
median
minimum
maximum
standard deviation
```

для серии измерений.

---

# 50. CLI-приложение

Итогом проекта является работающее CLI-приложение с командами:

```text
vault init

vault add <file>

vault extract <file_id>

vault remove <file_id>

vault list

vault verify

vault benchmark
```

---

# 51. vault init

Команда:

```text
vault init
```

выполняет:

```text
1. generate storage_uuid

2. generate ML-KEM key pair

3. generate ML-DSA key pair

4. ML-KEM Encaps

5. derive KEK

6. save CT_KEM

7. create empty Merkle Root

8. create Manifest generation 0

9. sign Manifest

10. write initial snapshot

11. initialize TrustedState
```

---

# 52. vault verify

Команда:

```text
vault verify
```

проверяет:

```text
1. canonical Manifest parsing

2. format_version

3. crypto_suite_id

4. storage_uuid

5. kem_key_id

6. sig_key_id

7. ML-DSA signature

8. generation

9. trusted_manifest_hash

10. CT_KEM hash

11. canonical object parsing

12. duplicate file_id detection

13. file_count

14. SHA3 hashes encrypted objects

15. canonical Merkle ordering

16. Merkle Root

17. соответствие вычисленного Root
    подписанному Manifest
```

Результат:

```text
VALID
```

выдаётся только при успешном прохождении всех проверок.

---

# 53. vault extract

Команда:

```text
vault extract <file_id>
```

сначала проверяет доверенность текущего состояния.

После этого:

```text
1. recover KEK

2. find authenticated object

3. AES-KW unwrap DEK

4. AES-GCM decrypt

5. verify GCM tag

6. parse FilePlaintext

7. return filename + data
```

При любой ошибке аутентификации plaintext не выдаётся.

---

# 54. vault remove

Команда:

```text
vault remove <file_id>
```

создаёт новое поколение через crash-safe commit protocol.

Текущее поколение непосредственно не модифицируется.

---

# 55. vault list

Команда:

```text
vault list
```

работает только с аутентифицированным состоянием.

Минимальный режим может выводить:

```text
file_id
ciphertext size
```

Если требуется отображение исходных имён файлов, они должны быть предварительно расшифрованы через корректный KEK/DEK и проверенный AES-GCM.

---

# 56. vault benchmark

Команда:

```text
vault benchmark
```

выполняет воспроизводимое сравнение CPU и GPU для:

```text
SHA3-256

Merkle Tree

ML-KEM-768

ML-DSA-65
```

и выводит:

```text
CPU timing
GPU kernel timing
transfer timing
GPU total timing
throughput
latency
operations/s
speedup
```

---

# 57. Критерии корректности реализации

Реализация считается криптографически корректной только если проходят тесты следующих классов.

## Positive tests

Корректное хранилище:

```text
verify == success
extract == original plaintext
```

---

## Ciphertext corruption

После изменения одного бита:

```text
ciphertext
```

должна нарушиться проверка Merkle состояния.

---

## GCM tag corruption

После изменения:

```text
gcm_tag
```

должны нарушиться:

```text
Merkle verification
```

и, при непосредственной попытке расшифрования:

```text
AES-GCM verification
```

---

## wrapped_DEK corruption

Изменение `wrapped_DEK` должно обнаруживаться Merkle Tree.

---

## CT_KEM corruption

Изменение:

```text
CT_KEM
```

должно обнаруживаться на этапе:

```text
kem_ct_hash verification
```

до использования нового CT_KEM как доверенного состояния.

---

## Manifest corruption

Изменение Manifest должно нарушать:

```text
ML-DSA verification
```

или:

```text
trusted_manifest_hash comparison
```

---

## Signature corruption

Изменение Signature должно приводить к:

```text
ML-DSA Verify == invalid
```

---

## File deletion

Удаление encrypted object должно приводить к несовпадению:

```text
file_count
```

или:

```text
merkle_root
```

---

## File insertion

Добавление постороннего encrypted object должно изменять Merkle Root или `file_count`.

---

## Object replacement

Замена одного encrypted object другим должна изменять Merkle Root.

---

## Rollback

Подмена поколения `N` на:

```text
N - k
```

должна обнаруживаться сравнением с TrustedState.

---

## Same-generation fork

Подмена Manifest другим корректно подписанным Manifest с тем же:

```text
generation
```

но другим состоянием должна обнаруживаться через:

```text
trusted_manifest_hash
```

---

## Crash tests

Должны моделироваться остановки процесса:

```text
до записи snapshot

во время записи snapshot

после snapshot fsync

до TrustedState update

после TrustedState update
```

После восстановления система должна либо видеть старое подтверждённое поколение, либо полностью подтверждённое новое поколение.

---

# 58. Основные свойства итоговой конструкции

Архитектура разделяет четыре независимые задачи.

## Конфиденциальность файла

```text
AES-256-GCM
+
individual DEK
```

---

## Защита DEK

```text
AES-256-KW
+
KEK
```

---

## Постквантовая защита KEK

```text
ML-KEM-768
+
KDF
```

---

## Глобальная целостность и актуальность состояния

```text
SHA3-256
+
Merkle Tree
+
ML-DSA-65
+
TrustedState
```

---

# 59. Финальная формулировка проекта

**В работе разрабатывается прототип защищённого файлового хранилища с иерархической системой управления ключами и криптографически аутентифицированным состоянием. Содержимое каждого файла шифруется индивидуальным одноразовым для объекта 256-битным DEK с использованием AES-256-GCM. DEK защищается с помощью AES-256-KW общим ключом KEK. KEK непосредственно на диске не хранится и восстанавливается из общего секрета ML-KEM-768 с применением криптографического KDF.**

**Для контроля состояния над канонически сериализованными и отсортированными по `file_id` encrypted objects строится domain-separated Merkle Tree на основе SHA3-256. Merkle Root вместе с номером поколения, идентификаторами криптографических ключей и хешем `CT_KEM` включается в Manifest. Canonical Manifest подписывается ML-DSA-65 с отдельным контекстом подписи.**

**Для защиты от rollback и fork-атак в отдельной доверенной области хранится не только номер последнего принятого поколения, но и SHA3-256 hash конкретного принятого Manifest. Это позволяет обнаруживать как возврат к старому корректно подписанному состоянию, так и подмену другим состоянием с тем же номером поколения.**

**Изменение хранилища выполняется посредством crash-safe commit protocol: новое поколение сначала полностью формируется, подписывается и синхронизируется на диске, и только после этого атомарно обновляется доверенный state anchor. Поэтому сбой в процессе транзакции не должен приводить к принятию частично записанного состояния.**

**Исследовательская часть работы заключается в экспериментальном сравнении CPU- и GPU-реализаций SHA3-256, построения и проверки Merkle Tree, ML-KEM-768 и ML-DSA-65, а также в определении диапазонов размера задачи и batch, при которых GPU обеспечивает выигрыш с учётом стоимости передачи данных, синхронизации и запуска CUDA kernels. GPU-реализация исследуется на NVIDIA RTX 3050 с использованием NVIDIA CUDA/cuPQC.**

**Проект не предполагает разработку собственных криптографических алгоритмов. Исследуется архитектура защищённого хранения, корректная композиция стандартизованных криптографических механизмов, защита целостности и актуальности состояния и эффективность GPU-параллелизации криптографических операций.**
