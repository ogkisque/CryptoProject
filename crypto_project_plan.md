# Тема проекта

**Разработка и экспериментальное исследование защищённого файлового хранилища с постквантовой защитой ключевого материала, контролем целостности состояния и GPU-ускорением криптографических операций**

---

# Общая цель работы

Разработать прототип защищённого файлового хранилища с иерархической системой управления ключами, обеспечивающий конфиденциальность и аутентичность файлов, постквантовую защиту ключевого материала, контроль целостности и актуальности состояния хранилища, а также возможность экспериментального исследования эффективности CPU- и GPU-реализаций криптографических операций.

Разработка выполняется поэтапно.

Каждый этап должен завершаться работоспособной версией системы.

При проектировании интерфейсов и форматов данных необходимо заранее обеспечить возможность добавления следующих этапов без существенного изменения уже реализованных компонентов.

---

# Этап 1. Минимальное криптографически корректное файловое хранилище

## Milestone 1

**Минимально работоспособное защищённое файловое хранилище с индивидуальным шифрованием файлов, иерархией ключей и постквантовой защитой KEK.**

На данном этапе должна быть получена первая полностью работоспособная версия CLI-приложения.

Она ещё не обязана обеспечивать глобальный контроль состояния всего хранилища и защиту от rollback, однако все операции шифрования, хранения и восстановления файлов должны быть криптографически корректными.

## Цель этапа

Реализовать базовый механизм безопасного хранения файлов, при котором компрометация директории хранилища не позволяет получить содержимое файлов без доступа к доверенному секретному ключу ML-KEM.

## Задачи этапа

1. Реализовать базовую структуру хранилища и доверенной области.

2. Реализовать генерацию:

```text
storage_uuid

ML-KEM-768:
    PK_KEM
    SK_KEM
```

3. Реализовать формирование ключевого материала:

```text
ML-KEM-768.Encaps
        ↓
K_MLKEM
        ↓
HKDF-SHA3-256
        ↓
KEK
```

4. Реализовать хранение `CT_KEM` в директории хранилища.

5. Реализовать генерацию индивидуального случайного:

```text
DEK_i = 256 bit
```

для каждого нового encrypted object.

6. Реализовать защиту DEK:

```text
AES-256-KW(
    KEK,
    DEK
)
```

7. Реализовать шифрование содержимого файла:

```text
AES-256-GCM
```

с параметрами:

```text
DEK      = unique per encrypted object

nonce    = random 96 bit

GCM tag  = 128 bit
```

8. Реализовать включение в AAD:

```text
format_version

crypto_suite_id

storage_uuid

file_id
```

9. Реализовать скрытие имени исходного файла внутри ciphertext.

10. Реализовать каноническое бинарное кодирование:

```text
FilePlaintext
EncryptedFile
```

11. Реализовать уникальный случайный:

```text
file_id = 128 bit
```

для каждого файла.

12. Реализовать проверку уникальности `file_id`.

13. Реализовать базовые CLI-команды:

```text
vault init

vault add <file>

vault extract <file_id>

vault remove <file_id>

vault list
```

14. Обеспечить обязательную проверку AES-GCM authentication tag до выдачи plaintext.

15. Реализовать очистку:

```text
K_MLKEM
KEK
DEK
plaintext
```

из оперативной памяти настолько, насколько это позволяет используемая программная платформа.

16. Реализовать тесты изменения:

```text
ciphertext

nonce

gcm_tag

wrapped_DEK
```

и убедиться, что модифицированные данные не могут быть корректно расшифрованы.

## Результат Milestone 1

Работающее файловое хранилище, обеспечивающее:

```text
конфиденциальность файлов

аутентичность файлов

отдельный DEK для каждого объекта

защиту DEK через KEK

постквантовую защиту KEK через ML-KEM-768

корректное использование AES-256-GCM

однозначный бинарный формат данных
```

На этом этапе уже должна быть возможна демонстрация основного цикла:

```text
vault init

vault add file.txt

vault list

vault extract <file_id>

vault remove <file_id>
```

---

# Этап 2. Глобальный контроль целостности состояния хранилища

## Milestone 2

**Криптографически аутентифицированное состояние всего файлового хранилища.**

Этап расширяет уже существующее хранилище и не изменяет базовый формат шифрования файлов.

`EncryptedFile`, AES-GCM, DEK, KEK и ML-KEM остаются без изменений.

## Цель этапа

Добавить возможность обнаружения:

```text
удаления encrypted object

добавления постороннего object

замены object

изменения metadata

изменения wrapped_DEK

изменения ciphertext
```

на уровне всего хранилища.

## Задачи этапа

1. Реализовать:

```text
SHA3-256
```

для хеширования encrypted objects.

2. Реализовать domain-separated Merkle leaves:

```text
Leaf_i =
    SHA3-256(
        0x00 ||
        CanonicalEncode(EncryptedFile)
    )
```

3. Реализовать канонический порядок объектов:

```text
sort by file_id
```

4. Реализовать построение бинарного Merkle Tree.

5. Реализовать domain separation:

```text
0x00 — leaf

0x01 — binary parent

0x02 — unpaired node

0x03 — empty tree
```

6. Реализовать однозначное поведение дерева при нечётном количестве узлов.

7. Реализовать фиксированный:

```text
EMPTY_ROOT
```

для пустого хранилища.

8. Реализовать структуру:

```text
Manifest
```

с полями:

```text
format_version

crypto_suite_id

storage_uuid

generation

file_count

merkle_root

kem_ct_hash

kem_key_id

sig_key_id
```

9. Добавить вторую постквантовую пару ключей:

```text
ML-DSA-65:

PK_SIG
SK_SIG
```

10. Реализовать подпись Manifest:

```text
ML-DSA-65
```

с отдельным контекстом:

```text
"edu-vault-manifest-v1"
```

11. Реализовать:

```text
kem_ct_hash =
    SHA3-256(
        0x11 ||
        CT_KEM
    )
```

12. Реализовать:

```text
kem_key_id
sig_key_id
```

как идентификаторы доверенных публичных ключей.

13. Реализовать команду:

```text
vault verify
```

14. Проверять при `vault verify`:

```text
Manifest format

storage_uuid

crypto_suite_id

ML-DSA signature

kem_key_id

sig_key_id

CT_KEM hash

file_count

duplicate file_id

Merkle leaves

Merkle Root
```

15. Изменить операции:

```text
vault list
vault extract
vault remove
```

так, чтобы они работали только с аутентифицированным состоянием.

## Результат Milestone 2

Система дополнительно обнаруживает любое изменение набора encrypted objects или их содержимого.

Получается цепочка:

```text
EncryptedFile
      ↓
SHA3-256
      ↓
Merkle Tree
      ↓
Merkle Root
      ↓
Manifest
      ↓
ML-DSA-65
      ↓
Signature
```

---

# Этап 3. Защита от rollback, fork и некорректного завершения транзакций

## Milestone 3

**Версионируемое хранилище с доверенным state anchor и crash-safe commit protocol.**

Этап не требует изменения формата encrypted objects или криптографической схемы файлов.

Основные изменения относятся к управлению состоянием.

## Цель этапа

Обеспечить обнаружение возврата хранилища к ранее корректному состоянию и исключить принятие частично записанного поколения после сбоя программы или системы.

## Задачи этапа

1. Реализовать:

```text
generation
```

для каждого состояния хранилища.

2. Реализовать:

```text
manifest_hash =
    SHA3-256(
        0x10 ||
        CanonicalEncode(Manifest)
    )
```

3. Расширить доверенное состояние:

```text
TrustedState {
    storage_uuid

    crypto_suite_id

    trusted_generation

    trusted_manifest_hash
}
```

4. Реализовать проверку:

```text
Manifest.generation ==
    trusted_generation
```

5. Реализовать проверку:

```text
manifest_hash ==
    trusted_manifest_hash
```

6. Обеспечить обнаружение rollback:

```text
generation N
    ↓
attacker
    ↓
generation N-k
```

7. Обеспечить обнаружение fork:

```text
Manifest A:
generation = N
root = A

Manifest B:
generation = N
root = B
```

8. Перейти к модели immutable generations.

9. Реализовать создание нового состояния:

```text
N
↓
N + 1
```

без изменения поколения `N`.

10. Реализовать crash-safe commit protocol:

```text
build snapshot N+1

write objects

write Manifest

write Signature

fsync files

fsync directory

publish snapshot

update TrustedState
```

11. Обеспечить атомарное обновление TrustedState.

12. Реализовать восстановление после crash.

13. Реализовать удаление устаревших поколений как отдельный garbage-collection этап.

14. Добавить тесты crash recovery.

15. Проверить поведение при сбоях:

```text
до записи snapshot

во время записи snapshot

после snapshot fsync

до TrustedState update

после TrustedState update
```

## Результат Milestone 3

Система обеспечивает:

```text
integrity

authenticity

rollback detection

same-generation fork detection

crash consistency
```

После этого базовую криптографическую архитектуру защищённого хранилища можно считать завершённой.

---

# Этап 4. Подготовка вычислительного ядра к CPU/GPU реализации

## Milestone 4

**Разделение функциональной логики и вычислительных backend для последующего GPU-ускорения.**

Этот этап должен в основном затрагивать внутреннюю организацию программы, но не формат хранилища и не криптографический протокол.

## Цель этапа

Подготовить архитектуру программного обеспечения так, чтобы CPU- и GPU-реализации криптографических операций могли использоваться взаимозаменяемо.

## Задачи этапа

1. Выделить интерфейс backend для:

```text
SHA3-256

Merkle Tree

ML-KEM-768

ML-DSA-65
```

2. Реализовать эталонный CPU backend.

3. Зафиксировать единый бинарный API для:

```text
hash input

Merkle leaves

Merkle root

ML-KEM buffers

ML-DSA buffers
```

4. Исключить зависимость формата хранилища от конкретного backend.

5. Реализовать тесты:

```text
CPU backend result ==
reference result
```

6. Подготовить batch API для независимых операций:

```text
SHA3 batch

ML-KEM batch

ML-DSA batch
```

7. Разделить измерение:

```text
algorithm time

serialization time

filesystem time

memory-copy time
```

8. Подготовить benchmark framework.

## Результат Milestone 4

Функциональная часть приложения остаётся неизменной, а вычислительные операции могут выполняться через различные backend.

Например:

```text
Vault logic
    │
    ▼
Crypto backend interface
    │
    ├── CPU backend
    │
    └── GPU backend
```

---

# Этап 5. GPU-ускорение SHA3 и Merkle Tree

## Milestone 5

**GPU-реализация операций контроля целостности.**

Это наиболее естественный первый этап GPU-ускорения, поскольку SHA3-хеширование большого количества независимых объектов хорошо допускает пакетный параллелизм.

## Цель этапа

Исследовать эффективность применения GPU для:

```text
SHA3-256

Merkle Tree construction

Merkle Tree verification
```

## Задачи этапа

1. Реализовать GPU backend SHA3-256.

2. Реализовать batch hashing encrypted objects.

3. Реализовать GPU-вычисление Merkle Tree.

4. Проверить байтовую эквивалентность CPU и GPU:

```text
CPU Merkle Root ==
GPU Merkle Root
```

5. Измерить:

```text
CPU total time

GPU kernel time

CPU → GPU transfer

GPU → CPU transfer

GPU total time

throughput

speedup
```

6. Исследовать размеры файлов:

```text
1 KiB
4 KiB
64 KiB
1 MiB
16 MiB
```

7. Исследовать количество объектов:

```text
10
100
1 000
10 000
100 000
```

8. Определить crossover point:

```text
GPU_total_time <
CPU_total_time
```

## Результат Milestone 5

Работающее хранилище получает альтернативный GPU backend для контроля целостности без изменения криптографического формата данных.

---

# Этап 6. GPU-ускорение постквантовых алгоритмов

## Milestone 6

**GPU backend для ML-KEM-768 и ML-DSA-65.**

## Цель этапа

Экспериментально определить, при каких размерах batch применение GPU эффективно для постквантовых операций.

## Задачи этапа

1. Реализовать GPU backend ML-KEM-768 для:

```text
KeyGen

Encaps

Decaps
```

2. Реализовать GPU backend ML-DSA-65 для:

```text
KeyGen

Sign

Verify
```

3. Использовать NVIDIA CUDA/cuPQC.

4. Проверить совместимость CPU и GPU реализаций.

5. Для детерминированных операций обеспечить:

```text
CPU result ==
GPU result
```

6. Для рандомизированных операций проверять:

```text
correct decapsulation

correct signature verification

standard test vectors

cross-backend compatibility
```

7. Исследовать batch:

```text
1
10
100
1 000
10 000
```

8. Измерить:

```text
operations/s

latency

kernel time

transfer time

total batch time

CPU/GPU speedup
```

9. Определить минимальный batch, начиная с которого GPU обеспечивает преимущество.

## Результат Milestone 6

Полностью реализована экспериментальная часть постквантового GPU-ускорения.

При этом формат хранилища, Manifest, Merkle Tree и ключевая архитектура не изменяются.

---

# Этап 7. Комплексное экспериментальное исследование

## Milestone 7

**Получение итоговых экспериментальных результатов и сравнительного анализа CPU/GPU.**

## Цель этапа

Определить практические границы применимости GPU-ускорения в разработанной архитектуре.

## Задачи этапа

1. Создать воспроизводимый benchmark suite.

2. Фиксировать:

```text
CPU model

GPU model

GPU architecture

CUDA version

cuPQC version

compiler version

compiler flags

batch size

input size

number of runs
```

3. Проводить warm-up перед измерениями.

4. Выполнять серию повторных измерений.

5. Вычислять:

```text
mean

median

minimum

maximum

standard deviation
```

6. Сравнить CPU и GPU для:

```text
SHA3-256

Merkle Tree

ML-KEM-768

ML-DSA-65
```

7. Отдельно учитывать:

```text
kernel execution time

host-to-device transfer

device-to-host transfer

synchronization

memory allocation

total execution time
```

8. Определить crossover points для каждого класса операций.

9. Проанализировать влияние:

```text
file size

number of objects

batch size

transfer overhead

kernel launch overhead
```

10. Сформулировать области, в которых:

```text
CPU preferable

GPU preferable
```

с точки зрения измеренной производительности.

## Результат Milestone 7

Получены экспериментальные данные, позволяющие определить условия, при которых GPU-параллелизация криптографических операций оправдана с учётом всех накладных расходов.

---

# Итоговая последовательность milestones

```text
Milestone 1
Минимальное криптографически корректное
файловое хранилище
        │
        ▼
Milestone 2
Merkle Tree + ML-DSA +
глобальная целостность состояния
        │
        ▼
Milestone 3
Rollback protection +
TrustedState +
crash-safe transactions
        │
        ▼
Milestone 4
Абстракция CPU/GPU backend +
benchmark infrastructure
        │
        ▼
Milestone 5
GPU SHA3 / Merkle
        │
        ▼
Milestone 6
GPU ML-KEM / ML-DSA
        │
        ▼
Milestone 7
Комплексное экспериментальное
исследование
```

---

# Принцип архитектурной совместимости этапов

Чтобы переход между milestones не требовал существенной переработки предыдущей реализации, уже на первом этапе необходимо зафиксировать следующие архитектурные решения:

```text
CanonicalEncode(...)

EncryptedFileV1

format_version

crypto_suite_id

storage_uuid

file_id

CryptoBackend interface

TrustedStorage interface

StorageBackend interface
```

При этом отдельные возможности могут первоначально не использоваться полностью.

Например, на первом этапе:

```text
generation
Manifest
Merkle Tree
ML-DSA
TrustedState
GPU backend
```

ещё могут отсутствовать, однако `EncryptedFileV1` и криптографическая иерархия ключей уже должны иметь окончательный формат.

Следующие этапы должны преимущественно добавлять новые уровни вокруг существующего encrypted object:

```text
EncryptedFile
      │
      ▼
Merkle Tree
      │
      ▼
Manifest
      │
      ▼
TrustedState
```

а GPU-ускорение должно добавляться заменой вычислительного backend:

```text
CPU backend
      ↓
GPU backend
```

без изменения криптографического протокола или формата данных.

Такой порядок позволяет использовать каждый milestone как отдельную работоспособную контрольную точку проекта и минимизирует объём переработки при переходе к следующему этапу.
