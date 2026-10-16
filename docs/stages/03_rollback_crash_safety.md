# Этап 3: rollback, fork и crash-safe транзакции

**Статус:** ✅ готово (2026-10-16)  ·  **Где:** CPU  ·  **ТЗ:** план → Этап 3, `crypto_project.md` §25–§34

## Цель

Добавить к хранилищу версионирование с доверенным state anchor (`trusted_generation` + `trusted_manifest_hash`) и сделать каждое изменение crash-safe транзакцией над immutable поколениями.

## Файлы

| Интерфейс | Реализация |
|---|---|
| `storage/storage_backend.hpp` | `src/storage/generation_storage.cpp` (новый backend, FlatStorage остаётся для тестов M1/M2) |
| `storage/crash_injection.hpp` | `src/storage/crash_injection.cpp` |
| `vault/commit.hpp` | `src/vault/commit.cpp` |
| `vault/state_verifier.hpp` | шаги 7–8 (`Generation`, `ManifestHash`) |
| `src/cli/commands.cpp` | `vault gc` |

## План работ

### 3.1 GenerationStorage
- [x] Раскладка из `docs/format_v1.md` §10: `generations/%016x/`, а незавершённое поколение — `%016x.tmp/`.
- [x] `begin_snapshot(N+1, N)`: создать `.tmp/objects/`. `put_object` пишет и fsync-ит файл. `remove_object` отмечает объект в множестве исключений. `sync()` линкует (L-1) все объекты базы, которых нет среди удалённых и перезаписанных, затем fsync файлов, `objects/` и `.tmp/`. `publish()` делает `rename(.tmp → final)` и `fsync(generations/)`.
- [x] Деструктор writer без `publish()` вызывает `abort()`, то есть удаляет `.tmp`.
- [x] `list_generations` пропускает `.tmp` и имена, не подходящие под шаблон. `list_incomplete_snapshots` возвращает только `.tmp`.

### 3.2 Commit protocol (§28)
- [x] `CommitProtocol::commit(current, changes)` — порядок вызовов фиксирован, crash-точки стоят в местах, отмеченных `[C]`:
  1. `[C:BeforeSnapshotWrite]`
  2. `begin_snapshot(N+1, N)`; `put_object` для добавленных объектов. После половины объектов (или после первого) — `[C:DuringSnapshotWrite]`.
  3. Построить новый отсортированный набор, листья (переиспользовать `current.leaves` для неизменённых объектов) и root.
  4. `Manifest(N+1)`, затем `sign`, затем `put_manifest`.
  5. `sync()` → `[C:AfterSnapshotFsync]` → `publish()` → `[C:AfterPublishBeforeTrusted]`.
  6. `trusted.update_state({N+1, manifest_hash})`: внутри — tmp + fsync, затем `[C:DuringTrustedUpdate]`, затем rename и fsync(dir).
  7. `[C:AfterTrustedUpdate]`.
- [x] `commit_initial`: то же самое для поколения 0 без базы. В `Vault::init` TrustedState создаётся только после publish поколения 0. Порядок init: trusted-ключи и state пишутся последними. Если `init` упал посередине, повторный `init` должен суметь продолжить или явно сообщить о частичной инициализации — способ выбрать и описать здесь.
- [x] `garbage_collect`: удалить все поколения `< trusted_generation`, а также все `.tmp`. Поколения `> trusted_generation` (опубликованные, но не подтверждённые после crash) — это orphan'ы, удалять и их.
- [x] `Vault` переходит с прямых записей на `CommitProtocol`. После commit `VerifiedState` заменяется результатом commit, и повторная проверка не нужна (§34).

### 3.3 Verifier
- [x] Читать `read_snapshot(trusted_generation)`, а не «последнее» поколение. Наличие поколений новее trusted не ошибка: это orphan, о нём выводится предупреждение.
- [x] Шаг 7: `manifest.generation == trusted_generation`. Шаг 8: `manifest_hash == trusted_manifest_hash`.

### 3.3a Блокировка
- [x] Эксклюзивный `flock` на `vault/.lock` на всё время транзакции (open → commit). Два параллельных `vault add` иначе построят два разных поколения N+1, и одно потеряется (в этом случае обнаружится через fork-проверку, но данные пропадут).

### 3.4 Тесты
- [x] **Rollback:** сохранить копию всего `vault/` на поколении k, сделать ещё несколько транзакций, вернуть копию → `Generation`. Вариант: подменить только `generations/` → то же.
- [x] **Fork:** имея `SK_SIG` (тестовый доступ), подписать второй Manifest с тем же generation и другим root, положить его вместе с подходящим набором объектов → `ManifestHash`.
- [x] **Crash** (`tests/crash/`): для каждой `CrashPoint` форкнуть процесс `vault add` с `VAULT_CRASH_POINT=<p>`, убедиться, что код выхода 86, затем `vault verify` должен вернуть VALID, а `vault list` показать
  - старое поколение N — для всех точек до `AfterPublishBeforeTrusted` включительно и для `DuringTrustedUpdate`;
  - новое поколение N+1 — для `AfterTrustedUpdate`.
- [x] После crash `vault gc` чистит `.tmp` и orphan, и состояние остаётся VALID.
- [x] Отдельно: `rename` атомарен и ровно один из `trusted_state.bin` / `trusted_state.bin.tmp` валиден — тест с усечённым tmp.

## Тонкие места

* `fsync` директории после `rename` обязателен (ext4 без него может «потерять» rename при потере питания). Crash-тесты на уровне процесса этого не проверяют: ограничение описать в отчёте (power-loss тестирование вне рамок, можно упомянуть `dm-flakey`/`LazyFS`).
* TrustedState — локальный файл. В реальной системе это TPM NV counter или HSM; в отчёте упомянуть, что это модель.
* Без hardlink каждый commit копирует O(N · размер). С hardlink — O(N) операций с метаданными, это тоже стоит упомянуть в отчёте.

## Критерии готовности

- [x] Rollback, fork и crash-тесты по всем 6 точкам проходят.
- [x] Удаление файла не трогает поколение N (тест: хеши всех файлов поколения N до и после совпадают).

## Журнал прогресса

| Дата | Что сделано |
|---|---|
| 2026-10-16 | Этап 3 завершён: `GenerationStorage`, `CommitProtocol` (все 6 crash-точек), шаги 7–8 verifier'а, `flock`, `vault gc`. 126 тестов проходят (Release и ASan/UBSan). Детали ниже. |

### Заметки и отклонения

* **Vault перешёл на `GenerationStorage`** (единственная фабрика `make_storage` в `vault.cpp`). `FlatStorage` остался в коде, но не используется.
* **Раскладка:** `vault/kem.ct`, `vault/.lock`, `vault/generations/<%016x>/{objects/, manifest.bin, manifest.sig}`. Неизменённые объекты — hardlink (L-1), с откатом на копию+fsync (`link_or_copy`). Файлы объектов никогда не переписываются на месте.
* **Изменения интерфейсов `commit.hpp`:** `commit(VerifiedState& current, changes)` обновляет `current` на месте только после успешного обновления trusted state (при исключении `current` не меняется); `commit_initial` получает ключи явно (доверенной области на этот момент ещё нет): `(uuid, kem_ct, kem_pk, SigKeyPair)`. В `CommitResult` добавлен только `new_generation`/`new_manifest_hash`/`profile`, как и было.
* **Orphan'ы и commit.** Перед записью `commit` удаляет поколения `> N` и `*.tmp` — это неподтверждённые следы прежнего crash, и их номер нужен новому поколению (иначе `vault add` после crash в точке `before-trusted-update` упирался бы в `AlreadyExists`). Это не GC: поколения `< N` commit никогда не трогает (Q2). `vault gc` удаляет всё, кроме trusted-поколения, плюс все `.tmp`.
* **Rollback даёт `Generation`, а не `LoadSnapshot`.** Если поколения `trusted_generation` нет на диске, а все имеющиеся старше — verifier сообщает `Generation` ("rollback: ..."). `LoadSnapshot` остаётся для случая, когда поколений нет вовсе или формат повреждён. Подмена номера каталога ловится шагом 7 (`manifest.generation != trusted_generation`).
* **Orphan'ы новее trusted не ошибка:** `VerifyReport::warnings`, `vault verify` печатает их в stderr как `warning: ...` и всё равно выводит `VALID`.
* **Блокировка:** `flock(LOCK_EX)` на `vault/.lock` берётся не на весь срок жизни `Vault`, а на каждую транзакцию (`add`/`remove`/`gc`): «актуализация → commit». Если trusted state ушёл вперёд (другой процесс или хэндл успел закоммитить), состояние перечитывается и перепроверяется, затем строится N+1. Блокировка блокирующая: параллельные `vault add` выстраиваются в очередь, а не падают (тест: 8 параллельных CLI `add` → 8 файлов, generation 8). Читатели (`list`, `verify`) блокировку не берут: одновременный `gc` может сделать их проверку ложно неудачной — повторить команду.
* **Crash-тесты** (`tests/crash/crash_test.cpp`) гоняют CLI с `VAULT_CRASH_POINT`: для `add` и `remove` по 6 точкам проверяют код 86, `vault verify` == VALID, старое/новое поколение, `gc` и повторную работу; отдельно — остаток `trusted_state.bin.tmp` (в т.ч. усечённый) и неполный `init`.
* **Неполный `init`** (процесс убит между созданием `vault/` и trusted state): повторный `init` отвечает `AlreadyExists` с пояснением «incomplete initialization» — каталог нужно удалить вручную. При обычной ошибке внутри `init` созданные каталоги удаляются автоматически.
* **Тесты прежних этапов** обновлены под новую раскладку (`generations/<N>/...`). Тесты, подменяющие Manifest настоящим ключом, дополнительно подгоняют anchor в trusted state (иначе сработал бы шаг 8 `ManifestHash`, а проверялись шаги содержимого).
* **Ограничения (для отчёта):** (1) crash-тесты работают на уровне процесса и не проверяют потерю питания — для этого нужны `dm-flakey`/`LazyFS`; fsync родительских каталогов после rename реализован, но не проверяется; (2) TrustedState — локальный файл, в реальной системе это TPM NV counter/HSM; (3) без hardlink commit копировал бы O(N·размер), с hardlink — O(N) операций с метаданными.
