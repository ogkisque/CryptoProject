# Этап 6: GPU backend для ML-KEM-768 и ML-DSA-65

**Статус:** ☐ не начат  ·  **Где:** **GPU-машина**  ·  **ТЗ:** план → Этап 6, `crypto_project.md` §42–§43, §46–§47

## Цель

Сделать реализации `IKemBackend` и `ISigBackend` на cuPQC, проверить их совместимость с CPU (liboqs) и определить минимальный batch, начиная с которого GPU выгоднее.

## Файлы

```
cuda/src/gpu_kem_backend.cu
cuda/src/gpu_sig_backend.cu
tests/gpu/gpu_pqc_test.cpp
```

## План работ

### 6.0 Разведка API cuPQC (обязательно до кода)
Ответить на вопросы и записать ответы в журнал этого файла:
- [ ] Какие параметры поддерживаются (ML-KEM-768 и ML-DSA-65 точно есть в cuPQC; проверить версию SDK).
- [ ] Модель вызова: device-side API (свой `__global__` kernel вызывает `cupqc::...` с workspace и shared memory) или host API. Сколько shared memory и потоков нужно на одну операцию, сколько операций помещается в блок.
- [ ] **Источник случайности:** cuPQC принимает entropy/seed от вызывающей стороны или генерирует сам (cuRAND)? Если принимает — можно передать те же seed, что и liboqs, и сравнивать keygen/encaps **байт-в-байт** (сильнее, чем требует §42).
- [ ] **ML-DSA context string:** поддерживается ли `ctx`? Если нет — формировать `M' = 0x00 || len(ctx) || ctx || M` вручную и вызывать «internal» sign/verify, если он доступен. Если нельзя ни так, ни так — GPU ML-DSA используется только в benchmark'е с пустым ctx, а в vault — CPU. Это обязательно оговорить в отчёте.
- [ ] Детерминированная подпись (rnd = 0^32) — доступна ли.

### 6.1 ML-KEM-768
- [ ] `keygen_batch`, `encaps_batch`, `decaps_batch` на плоских буферах `KemBatch` (единый API из M4). Одиночные `keygen/encaps/decaps` = batch из 1.
- [ ] Entropy: генерируется на CPU (`RAND_bytes`) и передаётся H2D. Время генерации entropy учитывается отдельно или включается в total — выбрать и описать.
- [ ] **Секреты на GPU (§43):** после операции — `cudaMemsetAsync(0)` для буферов `secret_keys` и `shared_secrets` и workspace, затем `cudaFree` (или возврат в пул уже обнулённым).

### 6.2 ML-DSA-65
- [ ] `keygen_batch`, `sign_batch`, `verify_batch` на `SigBatch` (сообщения фиксированной длины 168 байт, как Manifest).
- [ ] Обнуление `secret_keys` и workspace после sign/keygen.

### 6.3 Совместимость (§42, план Этапа 6 п.4–6)
- [ ] ACVP-векторы на GPU (keyGen, encapDecap, sigGen, sigVer).
- [ ] Перекрёстные проверки:
  - GPU encaps → CPU decaps, и наоборот: общий секрет совпадает;
  - GPU sign → CPU verify, CPU sign → GPU verify: валидно; испорченная подпись невалидна на обоих;
  - при seed-API: keygen/encaps/детерминированный sign совпадают байт-в-байт.
- [ ] `vault init/add/verify --backend gpu`: хранилище, созданное на GPU, открывается на CPU, и наоборот.

### 6.4 Измерения
- [ ] batch {1, 10, 100, 1000, 10000} × {KeyGen, Encaps, Decaps, KeyGen, Sign, Verify} × {cpu, cpu-mt, gpu}.
- [ ] Метрики: ops/s, latency (batch = 1 — single-op latency), total, kernel, transfer, speedup.
- [ ] Минимальный выгодный batch для каждой операции (предварительно; полный анализ — в M7).

## Тонкие места

* В vault в одной операции участвует ровно одна PQC-операция (1 sign или 1 decaps). На batch = 1 GPU почти наверняка проиграет, это нормально. Смысл GPU для PQC здесь — серверный сценарий: много хранилищ или пользователей, пакетная проверка. Так и сформулировать в отчёте.
* Время ML-DSA sign недетерминировано (rejection sampling). Отсюда разброс по потокам warp'а (divergence) — одна из возможных причин плохого масштабирования на GPU.

## Критерии готовности

- [ ] Все перекрёстные тесты проходят.
- [ ] CSV PQC-матрицы сохранён в `bench/results/`.
- [ ] Ответы на вопросы 6.0 записаны в журнал.

## Журнал прогресса

| Дата | Что сделано |
|---|---|
