# Этап 6: GPU-backend для ML-KEM-768 и ML-DSA-65

**Статус:** часть А ✅ готова (2026-10-16); часть Б ☐ — сборка и запуск на GPU-машине автором  ·  **Где:** часть А — на этой машине (без CUDA, код не компилируется), часть Б — сборка и запуск на GPU-машине автором (`docs/gpu_workflow.md`)  ·  **ТЗ:** план → Этап 6, `crypto_project.md` §42–§43, §46–§47

## Цель

Реализовать `IKemBackend` и `ISigBackend` на cuPQC, проверить совместимость с CPU (liboqs) и найти минимальный batch, с которого GPU выгоднее. Своих реализаций ML-KEM/ML-DSA нет: работает cuPQC, поэтому самый большой риск — **неверные предположения о его API**. SDK здесь нет, поэтому API берётся из публичной документации NVIDIA, а все неочевидные места явно помечаются `// UNVERIFIED(cuPQC): ...`. При ошибке на GPU-машине сразу видно, какое предположение не подтвердилось.

## Файлы

```
cuda/src/gpu_kem_backend.cu
cuda/src/gpu_sig_backend.cu
cuda/host/pqc_batch_plan.{hpp,cpp}   # C++ без CUDA API: чанки batch'а по VRAM
cuda/host/pqc_runner.hpp             # граница «логика / CUDA»: IMlKemRunner, IMlDsaRunner
cuda/host/pqc_backends.{hpp,cpp}     # IKemBackend/ISigBackend поверх runner'а: размеры, порции, калибровка ctx ML-DSA
cuda/src/gpu_pqc_common.hpp          # guard вызовов cuPQC, библиотечные буферы с обнулением, таймер, dynamic smem
tests/unit/gpu_pqc_logic_test.cpp    # «фальшивый cuPQC» на liboqs (три гипотезы о context string)
tests/unit/pqc_batch_plan_test.cpp   # всегда
tests/gpu/gpu_pqc_test.cpp           # на устройстве; GTEST_SKIP без GPU
```

## Часть А — на этой машине (до запуска)

### 6.A0 Разведка API cuPQC по публичной документации (до кода)
Ответить и записать ответы в журнал этого файла **со ссылкой на место в документации**. То, что из документации не ясно, записать как предположение, а в коде пометить `UNVERIFIED`:
- [x] Версия SDK. Есть ли ML-KEM-768 и ML-DSA-65.
- [x] Модель вызова: device-side API (свой `__global__` вызывает `cupqc::...` с workspace и shared memory) или host API. Сколько shared memory и потоков нужно на операцию, сколько операций помещается в блок.
- [x] **Источник случайности:** принимает ли cuPQC entropy/seed от вызывающего? Если да — keygen/encaps сравниваются с liboqs **байт-в-байт** на одних seed (тест сильнее, чем требует §42). Если нет — только взаимная проверка.
- [x] **Context string ML-DSA.** Если `ctx` не поддерживается — собирать `M' = 0x00 || len(ctx) || ctx || M` вручную и вызывать «internal» sign/verify, если он есть. Если нет ни того, ни другого — GPU ML-DSA только в benchmark'е с пустым ctx, а в vault используется CPU. Обязательно оговорить в отчёте.
- [x] Детерминированная подпись (rnd = 0^32) — есть ли.
- [x] Требования к сборке: RDC, LTO, флаги, порядок линковки → `cmake/Cuda.cmake`.

### 6.A1 Host-часть
- [x] `pqc_batch_plan`: разбиение batch'а на порции по VRAM, `blockDim`/shared memory по ответам 6.A0. Тесты на граничные batch (1, 10000, не кратные размеру блока).
- [x] Entropy генерируется на CPU (`RAND_bytes`) и копируется H2D. Решить и записать, входит ли её генерация в total (рекомендация: не входит, но измеряется отдельно).

### 6.A2 Device-код (вслепую, здесь не компилируется)
- [x] `gpu_kem_backend.cu`: `keygen_batch`, `encaps_batch`, `decaps_batch` на плоских буферах `KemBatch` (`docs/format_v1.md` §15). Одиночные операции = batch из 1.
- [x] `gpu_sig_backend.cu`: `keygen_batch`, `sign_batch`, `verify_batch` на `SigBatch` (сообщения по 168 байт, как Manifest).
- [x] **Секреты на GPU (§43):** после операции — `cudaMemsetAsync(0)` для `secret_keys`, `shared_secrets` и workspace, затем освобождение (или возврат в пул уже обнулённым).
- [x] Тайминг по фазам, как в этапе 5; ошибки через `CUDA_CHECK`. Коды возврата cuPQC (если есть) проверяются и попадают в текст ошибки.
- [x] Если cuPQC не найден при сборке, KEM/DSA GPU-backend'ы дают `BackendUnavailable`, а SHA3/Merkle на GPU работают (`VAULT_HAS_CUPQC`).

### 6.A3 Тесты для запуска
- [x] `tests/gpu/gpu_pqc_test.cpp`:
  - ACVP-векторы на GPU (keyGen и encapDecap ML-KEM; keyGen, sigGen и sigVer ML-DSA) — те же файлы, что для CPU (`tests/vectors/`);
  - перекрёстные проверки: GPU encaps → CPU decaps и наоборот; GPU sign → CPU verify и наоборот; испорченная подпись невалидна на обоих;
  - при seed-API: keygen, encaps и детерминированный sign совпадают с CPU байт-в-байт;
  - vault: хранилище, созданное с `--backend gpu`, открывается на CPU, и наоборот.
  - Без устройства — `GTEST_SKIP`.
- [x] Benchmark уже проверяет результаты GPU через reference (ревью этапа 4): ключи работают, decaps reference = секреты backend'а, подписи проходят reference verify.

## Часть Б — на GPU-машине (собирает и запускает автор)

- `gpu_run_all.sh --quick`: сборка с cuPQC, `ctest -L gpu` (ACVP, перекрёстные проверки). Ошибки присылаются; по ним пересматриваются помеченные `UNVERIFIED` места, итерация повторяется.
- Когда быстрый прогон зелёный — полный: матрица PQC из `full.json`, batch {1, 10, 100, 1000, 10000} × 6 операций × {cpu, cpu-mt, gpu}.
- В журнал: какие предположения 6.A0 подтвердились, какие нет и что изменено.

## Тонкие места

* В vault на одну операцию приходится ровно одна PQC-операция (1 sign или 1 decaps). На batch = 1 GPU почти наверняка проиграет, это нормально. Смысл GPU для PQC здесь — серверный сценарий: много хранилищ или пользователей, пакетная проверка. Так и сформулировать в отчёте.
* Время ML-DSA sign недетерминировано (rejection sampling): divergence в warp'е — возможная причина плохого масштабирования.

## Критерии готовности части А

- [x] Ответы 6.A0 записаны со ссылками на документацию; предположения помечены `UNVERIFIED`.
- [x] `pqc_batch_plan_test` зелёный здесь; сборка без CUDA не сломана.

## Критерии готовности части Б

- [ ] На GPU-машине: сборка с cuPQC проходит, `ctest -L gpu` зелёный (ACVP + перекрёстные проверки), данные PQC-матрицы получены.

## Журнал прогресса

| Дата | Что сделано |
|---|---|
| 2026-10-16 | План переписан под модель «один запуск на GPU» (ревью этапа 4) |
| 2026-10-16 | План пересмотрен: SDK и CUDA здесь не ставятся; API cuPQC — по публичной документации с пометками `UNVERIFIED`; сборка и запуск — на GPU-машине автором (`docs/gpu_workflow.md`) |
| 2026-10-16 | **Часть А готова.** 6.A0 выполнена по документации и официальным примерам cuPQC; код написан без компиляции с cuPQC. Детали ниже. |

### Ревью (2026-10-16)

**Сверка с первоисточниками.** Ревьюер независимо скачал официальные примеры [`example_ml_kem.cu`, `example_ml_dsa.cu`, `Makefile`](https://github.com/NVIDIA/cuPQC/tree/main/examples/public_key) и страницу [Getting Started](https://docs.nvidia.com/cuda/cupqc/introduction/getting_started.html) и сверил:
- порядок аргументов всех шести `execute` (keygen/encaps/decaps, keygen/sign/verify) — совпадает;
- шаг подписи `(signature_size + 7) / 8 * 8` и `bool` для результата verify — совпадает;
- `make_workspace` / `get_entropy` / `destroy_workspace` / `release_entropy` — совпадает;
- CMake: `find_package(cupqc)` с `CMAKE_PREFIX_PATH=<SDK>/cmake`, цель `cupqc-pk_static`; заголовок `pk.hpp` в `include/cupqc`, commondx в `include` — совпадает;
- в примерах shared memory статическая (`__shared__ smem[shared_memory_size]`, ML-DSA-44); наш вариант с динамической shared memory и opt-in работает и для > 48 КиБ, это корректное обобщение.

**Логика калибровки context string проверена рассуждением.** Подпись cuPQC над `X = 00 00 || M`:
- если cuPQC подписывает вход как M' (internal), liboqs примет её как pure-подпись `M` с пустым ctx → `Internal`;
- если cuPQC сам оборачивает вход (pure, пустой ctx), liboqs примет её как подпись `X` → `PureEmptyContext`;
- обратное направление (liboqs-подпись с manifest-ctx → GPU verify) и отказ на испорченной подписи проверяются отдельно.

Ошибок в криптографической логике и в обнулении секретов не найдено: порядок деструкторов `BufGuard` / `LibWorkspace` / `LibEntropy` корректен, синхронизация stream'а перед обнулением и освобождением есть и на пути исключения.

| # | Находка | Исправление |
|---|---|---|
| R1 | **Флаги LTO не в задокументированной форме.** NVIDIA везде собирает cuPQC как `nvcc -dlto -arch=sm_XY` (Getting Started, Makefile примеров). У нас `-dlto` смешивался с `--generate-code=arch=compute_86,code=[compute_86,sm_86]`, который CMake генерирует из `CUDA_ARCHITECTURES`; такая комбинация не задокументирована и — самое вероятное место сбоя device-link | при cuPQC `CUDA_ARCHITECTURES OFF`, компиляция и device-link получают ровно `-arch=sm_${VAULT_CUDA_ARCH} -dlto` (или `-arch=native` при `VAULT_CUDA_ARCH=native`). Без cuPQC (этап 5) — как раньше. Синтаксис `Cuda.cmake` проверен `cmake -P` |
| R2 | Все H2D/D2H шли через `cudaMemcpy2DAsync`, даже когда шаг равен ширине (ключи, шифртексты, секреты). 2D-копия pageable-памяти с тысячами коротких строк может быть заметно медленнее 1D и исказила бы `h2d_ms`/`d2h_ms` в PQC-матрице | при `pitch == width` — обычная `cudaMemcpyAsync`; 2D только там, где padding действительно есть (подписи 3309 → 3312, сообщения M') |
| R3 | В encaps и sign `get_entropy` вызывался после постановки H2D-копий в stream, а `LibEntropy::acquire` синхронизирует stream — `entropy_ms` включал время копирования | entropy готовится до H2D |
| R4 | Калибровка ML-DSA выполняется при первом sign/verify; при `warmup_runs: 0` она (CPU keygen + GPU sign/verify) попадала бы в первый замер | benchmark перед замерами ML-DSA делает одну неизмеряемую проверку (заведомо неверная подпись) — калибровка проходит вне замера |

**Принято как есть (для отчёта):**
* `pool_buffers: true` не убирает аллокации cuPQC: workspace и entropy выделяет сама библиотека на каждый вызов (`make_workspace` / `get_entropy`), они входят в `alloc_ms` / `entropy_ms` и при пуле.
* `.cu` компилируются как C++20 (std::span в заголовках проекта), а NVIDIA собирает примеры с `-std=c++17`. Если `pk.hpp` не соберётся в C++20 — это первая ошибка, которую стоит прислать; лечится выносом PQC-kernel'ов в отдельный TU без заголовков проекта.

Итого тестов: 225, Release и ASan/UBSan зелёные, `scripts/check_cuda_syntax.sh` — ok.

### 6.A0. Разведка API cuPQC (по публичной документации)

Источники: [Requirements](https://docs.nvidia.com/cuda/cupqc/introduction/requirements.html), [Getting Started](https://docs.nvidia.com/cuda/cupqc/introduction/getting_started.html), [cuPQC-PK Features](https://docs.nvidia.com/cuda/cupqc/libraries/cupqc_pk/cupqc_pk_feature.html), [Operators](https://docs.nvidia.com/cuda/cupqc/libraries/cupqc_pk/api/operators.html), [Traits](https://docs.nvidia.com/cuda/cupqc/libraries/cupqc_pk/api/traits.html), [Device Functions](https://docs.nvidia.com/cuda/cupqc/libraries/cupqc_pk/api/device.html), [Host Functions](https://docs.nvidia.com/cuda/cupqc/libraries/cupqc_pk/api/host.html), [Release Notes](https://docs.nvidia.com/cuda/cupqc/additional/release_notes.html), а также официальные примеры [`examples/public_key/example_ml_kem.cu`, `example_ml_dsa.cu` и `Makefile`](https://github.com/NVIDIA/cuPQC/tree/main/examples/public_key) (NVIDIA/cuPQC, Apache-2.0) — по ним сверены порядок аргументов и раскладка буферов.

| Вопрос | Ответ | Подтверждение |
|---|---|---|
| Версия SDK; есть ли ML-KEM-768 и ML-DSA-65 | Библиотека называется **cuPQC-PK** (переименована в 0.4.1; ML-KEM и ML-DSA, FIPS 203/204). Конкретная версия SDK неизвестна — её покажет `RUN_SUMMARY`/`SystemInfo` на GPU-машине. Алиасы `ML_KEM_768()` (SecurityCategory 3) и `ML_DSA_65()` (категория 3) есть | Operators, Release Notes |
| Требования | **CUDA Toolkit и nvcc ≥ 12.8**, C++17+, GCC ≥ 7, GPU SM 80/86/87/89/90 (**SM 86 поддержан**), CMake ≥ 3.20 | Requirements |
| Модель вызова | **Device-side библиотека**: свой `__global__` вызывает `Descriptor().execute(...)`; дескриптор собирается `ML_KEM_768() + Function<function::Keygen>() + Block() + BlockDim<128>()`; режим `Block` — **одна операция на CUDA-блок**; `BlockDim` ∈ {32, 64, 128, 256}, по умолчанию 128; `Y = Z = 1` | Operators, Getting Started |
| Память на операцию | Traits `PK::shared_memory_size` (**статически неизвестна — зависит от алгоритма; ML-DSA-65 может превышать 48 КиБ**), `PK::workspace_size` (глобальная память, 8-байтовое выравнивание), `PK::entropy_size`; размеры ключей/шифртекстов/подписей — `public_key_size`, `secret_key_size`, `ciphertext_size`, `shared_secret_size`, `signature_size`. Все буферы выравнены на 8; `signature_size` ML-DSA **не кратен 8** — подписи нужно класть с шагом `(size + 7) / 8 * 8` | Traits, Device Functions |
| Сколько операций в блоке / в grid | Одна на блок; grid = число операций порции (≤ 2³¹ − 1) | примеры: `<<<batch, BlockDim>>>` |
| Сигнатуры execute | Keygen `(pk, sk, entropy, workspace, smem)`; Encaps `(ct, ss, pk, entropy, workspace, smem)`; Decaps `(ss, ct, sk, workspace, smem)`; Sign `(sig, msg, msg_len, sk, entropy, workspace, smem)`; Verify `-> bool (msg, msg_len, sig, pk, workspace, smem)`. Кодов ошибок нет: все `void`, Verify возвращает `bool` | Device Functions |
| Host-функции | `make_workspace<PK>(batch, stream)`, `get_entropy<PK>(batch, stream)`, `destroy_workspace`, `release_entropy`; при ошибке выделения — исключение | Host Functions |
| **Источник случайности** | `get_entropy<PK>(batch)` **сама заполняет** буфер криптостойкой случайностью. **API для пользовательского seed в документации нет.** Но буфер — обычная device-память `uint8_t*`, 8-байтовое выравнивание | Host Functions, Device Functions |
| **Context string ML-DSA** | **В сигнатурах Sign/Verify параметра ctx нет**; документация не говорит, что именно подписывается (pure с пустым ctx или Sign_internal над переданным сообщением) | Device Functions, Features |
| Детерминированная подпись (rnd = 0^32) | Отдельного режима нет; rnd приходит через entropy-буфер | предположение |
| Сборка | `nvcc -std=c++17 -dlto -arch=sm_XY -I<SDK>/include/cupqc -I<SDK>/include -L<SDK>/lib -lcupqc-pk`; CMake: `find_package(cupqc)` с `CMAKE_PREFIX_PATH=<SDK>/cmake`, цель **`cupqc-pk_static`**; требуется `commondx` (в `<SDK>/include`). `-rdc` в документации не упомянут, **нужен `-dlto` (LTO)** | Getting Started, Makefile примеров |

**Решения по неясным местам (все помечены `UNVERIFIED(cuPQC)` в коде):**
1. *Context string.* Гипотезы: **H1** — cuPQC подписывает переданное сообщение как M' (ML-DSA.Sign_internal); **H2** — cuPQC сам подписывает «pure» с пустым ctx. Код **не угадывает, а определяет это при первом использовании** (`calibrate()` в `pqc_backends.cpp`): подписывает X = `00 00 || M` и смотрит, какой проверкой liboqs подпись проходит (`verify(M, ctx="")` → H1, `verify(X, ctx="")` → H2, иначе подписи несовместимы); затем проверяет обратное направление (подпись liboqs → cuPQC verify) и отвержение порченой подписи. При H1 контекст реализуется сборкой `M' = 0x00 || len(ctx) || ctx || M` — полная совместимость с FIPS 204. При H2 GPU работает только с пустым ctx: **batch с ctx → `BackendUnavailable`** (benchmark помечает точку `skipped: not supported by backend`, либо запустить с `"mldsa_context": "empty"`), **одиночные sign/verify с ctx (vault: одна подпись на команду) идут на CPU** — об этом нужно сказать в отчёте. При несовместимости (Unusable) то же самое.
2. *Entropy и seed.* Документация seed не предусматривает, поэтому детерминированный режим (ACVP, CPU==GPU байт-в-байт) строится на **предположении**, что байты entropy — это ровно FIPS-входы (ML-KEM keygen `d‖z` = 64 байта, encaps `m` = 32, ML-DSA keygen `ξ` = 32, sign `rnd` = 32): entropy-буфер подменяется собственным device-буфером с seed'ом. Разрешено **только если `entropy_size` равен длине seed** (`supports_seeds()`), иначе seeded-операции отказывают с `BackendUnavailable`. `tests/gpu/gpu_pqc_test.cpp` сверяет с ACVP; если не совпало — тест **пропускается с причиной** (`ASSUMPTION REFUTED`), а ключи/подписи всё равно проверяются перекрёстно с liboqs. Результат пишется в свойства теста (`entropy_layout_matches_*`) и в журнал части Б.
3. *Форматы.* cuPQC использует стандартные размеры; это закреплено `static_assert` на `public_key_size`/`secret_key_size`/`ciphertext_size`/`signature_size` против констант проекта — несовпадение останавливает сборку с понятным сообщением. Совпадение байтов ключей/шифртекстов/подписей с liboqs проверяют перекрёстные тесты (GPU→CPU и CPU→GPU).
4. *Shared memory.* ML-DSA-65 может требовать > 48 КиБ на блок, поэтому используется **динамическая** shared memory (`extern __shared__`, размер — в launch, `cudaFuncSetAttribute(MaxDynamicSharedMemorySize)` при > 48 КиБ). Если `shared_memory_size` больше лимита устройства, backend бросает `BackendUnavailable` с обоими числами. На SM 86 лимит opt-in ≈ 99 КиБ.
5. *Сборка.* `-dlto` добавлен в компиляцию и в device-link (`$<DEVICE_LINK:-dlto>`); `Cuda.cmake` ищет пакет `cupqc` (цель `cupqc-pk_static`) и запасной путь `include/cupqc` + `include` + `-lcupqc-pk`. **Неподтверждённое:** совместимость `-dlto` с `CUDA_SEPARABLE_COMPILATION` и `CUDA_ARCHITECTURES=86` (CMake генерирует `-gencode arch=compute_86,code=[compute_86,sm_86]`, а примеры cuPQC собираются с `-arch=native`); при ошибке device-link — `-DVAULT_CUDA_ARCH=native`. C++: примеры используют C++17, а проект компилирует `.cu` как C++20 (из-за `std::span`): совместимость `pk.hpp` с C++20 тоже не проверена.

### Часть А: что сделано

* **Архитектура.** Переносимая логика отделена от CUDA границей `IMlKemRunner`/`IMlDsaRunner` (одна порция над плотными host-буферами). `cuda/host/pqc_backends.cpp` (собирается всегда): проверка размеров, порционирование (`plan_pqc_chunks`), калибровка ctx, сборка M', fallback одиночных операций, отказы вместо молчаливых подмен. `cuda/src/gpu_{kem,sig}_backend.cu` — runner'ы на cuPQC: сигнатуры `execute` и раскладка буферов — по официальным примерам; padding подписей и сообщений до 8 байт выполняется `cudaMemcpy2DAsync` (на host остаются плотные 3309 байт).
* **Проверено здесь (225 тестов, Release и ASan/UBSan):** `gpu_pqc_logic_test` гоняет backend'ы на «фальшивом cuPQC» (runner'ы поверх liboqs, реализующие каждую из трёх гипотез: Internal, Pure, Garbage) — калибровка определяет режим верно, подписи совместимы с liboqs в обе стороны (с ctx и без), детерминированная подпись и keygen по seed совпадают с CPU байт-в-байт, порции собираются в правильном порядке и размере, испорченные данные отвергаются, при H2/H3 batch отказывает, а одиночные операции работают через CPU. Мутации (потерянный префикс ctx; смещение seed'ов в порции) тесты ловят.
* **Синтаксис `.cu`:** `scripts/check_cuda_syntax.sh` проходит; для него `tools/fakecuda/pk.hpp` повторяет задокументированную поверхность cuPQC (дескрипторы, execute с документированными сигнатурами, host-функции) — так вызовы сверены с документацией, но это не настоящий `pk.hpp`.
* **Секреты на GPU (§43):** `secret_keys`, `shared_secrets`, entropy-буферы и библиотечный workspace обнуляются `cudaMemsetAsync(0)` и синхронизируются **до** освобождения (RAII `BufGuard`/`LibWorkspace`/`LibEntropy` — в том числе при исключении); при `pool_buffers` секретные буферы возвращаются в пул уже обнулёнными. Обнуление на устройстве нельзя проверить из host-тестов — это проверяется только чтением кода и логов.
* **Тайминг:** добавлено поле `TimingBreakdown::entropy_ms` (генерация entropy внутри cuPQC, `get_entropy`) — входит в total, но показывается отдельно (CSV/JSON: `entropy_median_ms`/`entropy_mean_ms`, `entropy_ms`). Библиотечный `make_workspace` учитывается в `alloc_ms`.
* **Пулирование:** `pool_buffers` относится к собственным device-буферам; workspace и entropy выделяются библиотекой на каждую операцию всегда.
* **Benchmark:** ошибка `BackendUnavailable` внутри точки — это `skipped` с причиной, а не ошибка прогона; добавлена опция конфига `"mldsa_context": "manifest" | "empty"`.
* **Не проверяется GPU-тестом, но стоит знать:** cuPQC, судя по документации, **не заявляет проверку входных ключей** (в отличие от liboqs: `EKCHECK`/`DKCHECK` в ACVP) — в vault ключи берутся из доверенной области, и GPU-тест этих проверок нет.

**Места `UNVERIFIED(cuPQC)`** (куда смотреть при ошибках на GPU-машине): (1) режим ctx и совместимость подписей — калибровка; (2) раскладка entropy и seeded-режим; (3) `-dlto` + `CUDA_SEPARABLE_COMPILATION` + архитектура, C++20 для `pk.hpp`; (4) размер shared memory ML-DSA-65 vs лимит устройства; (5) предположение, что `execute` разрешает произвольное (не кратное размеру блока) выравнивание сообщений — сообщения кладутся с шагом, кратным 8; (6) все потоки блока Verify получают одно и то же значение (как в официальном примере, результат пишут все потоки).

### Первый запуск на GPU-машине (2026-10-21)

GPU ML-KEM/ML-DSA **не проверены**: CMake не нашёл cuPQC из-за относительного `CUPQC_ROOT` (см. журнал этапа 5, G1), и были собраны заглушки. Ни одно предположение 6.A0 (режим context string, раскладка entropy, shared memory ML-DSA-65, `-dlto` с device-link) пока не подтверждено и не опровергнуто. Нужен повторный запуск с исправленным скриптом.

