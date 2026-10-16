# Этап 3: rollback, fork и crash-safe транзакции

**Статус:** ☐ не начат  ·  **Где:** CPU  ·  **ТЗ:** план → Этап 3, `crypto_project.md` §25–§34

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
- [ ] Раскладка из `docs/format_v1.md` §10: `generations/%016x/`, а незавершённое поколение — `%016x.tmp/`.
- [ ] `begin_snapshot(N+1, N)`: создать `.tmp/objects/`. `put_object` пишет и fsync-ит файл. `remove_object` отмечает объект в множестве исключений. `sync()` линкует (L-1) все объекты базы, которых нет среди удалённых и перезаписанных, затем fsync файлов, `objects/` и `.tmp/`. `publish()` делает `rename(.tmp → final)` и `fsync(generations/)`.
- [ ] Деструктор writer без `publish()` вызывает `abort()`, то есть удаляет `.tmp`.
- [ ] `list_generations` пропускает `.tmp` и имена, не подходящие под шаблон. `list_incomplete_snapshots` возвращает только `.tmp`.

### 3.2 Commit protocol (§28)
- [ ] `CommitProtocol::commit(current, changes)` — порядок вызовов фиксирован, crash-точки стоят в местах, отмеченных `[C]`:
  1. `[C:BeforeSnapshotWrite]`
  2. `begin_snapshot(N+1, N)`; `put_object` для добавленных объектов. После половины объектов (или после первого) — `[C:DuringSnapshotWrite]`.
  3. Построить новый отсортированный набор, листья (переиспользовать `current.leaves` для неизменённых объектов) и root.
  4. `Manifest(N+1)`, затем `sign`, затем `put_manifest`.
  5. `sync()` → `[C:AfterSnapshotFsync]` → `publish()` → `[C:AfterPublishBeforeTrusted]`.
  6. `trusted.update_state({N+1, manifest_hash})`: внутри — tmp + fsync, затем `[C:DuringTrustedUpdate]`, затем rename и fsync(dir).
  7. `[C:AfterTrustedUpdate]`.
- [ ] `commit_initial`: то же самое для поколения 0 без базы. В `Vault::init` TrustedState создаётся только после publish поколения 0. Порядок init: trusted-ключи и state пишутся последними. Если `init` упал посередине, повторный `init` должен суметь продолжить или явно сообщить о частичной инициализации — способ выбрать и описать здесь.
- [ ] `garbage_collect`: удалить все поколения `< trusted_generation`, а также все `.tmp`. Поколения `> trusted_generation` (опубликованные, но не подтверждённые после crash) — это orphan'ы, удалять и их.
- [ ] `Vault` переходит с прямых записей на `CommitProtocol`. После commit `VerifiedState` заменяется результатом commit, и повторная проверка не нужна (§34).

### 3.3 Verifier
- [ ] Читать `read_snapshot(trusted_generation)`, а не «последнее» поколение. Наличие поколений новее trusted не ошибка: это orphan, о нём выводится предупреждение.
- [ ] Шаг 7: `manifest.generation == trusted_generation`. Шаг 8: `manifest_hash == trusted_manifest_hash`.

### 3.4 Тесты
- [ ] **Rollback:** сохранить копию всего `vault/` на поколении k, сделать ещё несколько транзакций, вернуть копию → `Generation`. Вариант: подменить только `generations/` → то же.
- [ ] **Fork:** имея `SK_SIG` (тестовый доступ), подписать второй Manifest с тем же generation и другим root, положить его вместе с подходящим набором объектов → `ManifestHash`.
- [ ] **Crash** (`tests/crash/`): для каждой `CrashPoint` форкнуть процесс `vault add` с `VAULT_CRASH_POINT=<p>`, убедиться, что код выхода 86, затем `vault verify` должен вернуть VALID, а `vault list` показать
  - старое поколение N — для всех точек до `AfterPublishBeforeTrusted` включительно и для `DuringTrustedUpdate`;
  - новое поколение N+1 — для `AfterTrustedUpdate`.
- [ ] После crash `vault gc` чистит `.tmp` и orphan, и состояние остаётся VALID.
- [ ] Отдельно: `rename` атомарен и ровно один из `trusted_state.bin` / `trusted_state.bin.tmp` валиден — тест с усечённым tmp.

## Тонкие места

* `fsync` директории после `rename` обязателен (ext4 без него может «потерять» rename при потере питания). Crash-тесты на уровне процесса этого не проверяют: ограничение описать в отчёте (power-loss тестирование вне рамок, можно упомянуть `dm-flakey`/`LazyFS`).
* TrustedState — локальный файл. В реальной системе это TPM NV counter или HSM; в отчёте упомянуть, что это модель.
* Без hardlink каждый commit копирует O(N · размер). С hardlink — O(N) операций с метаданными, это тоже стоит упомянуть в отчёте.

## Критерии готовности

- [ ] Rollback, fork и crash-тесты по всем 6 точкам проходят.
- [ ] Удаление файла не трогает поколение N (тест: хеши всех файлов поколения N до и после совпадают).

## Журнал прогресса

| Дата | Что сделано |
|---|---|
