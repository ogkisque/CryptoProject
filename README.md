# CryptoProject — edu-vault

Учебный проект по защите информации: прототип защищённого файлового хранилища с постквантовой защитой ключевого материала и экспериментальное сравнение CPU и GPU (CUDA/cuPQC).

- Файлы шифруются **AES-256-GCM**, у каждого свой DEK; DEK оборачивается **AES-256-KW** ключом KEK.
- KEK выводится **HKDF-SHA3-256** из общего секрета **ML-KEM-768**.
- Состояние хранилища аутентифицируется **SHA3-256 Merkle Tree**, Manifest и подписью **ML-DSA-65**.
- Rollback и fork обнаруживаются по доверенному state anchor; изменения проходят через **crash-safe commit** над неизменяемыми поколениями.
- SHA3/Merkle, ML-KEM и ML-DSA имеют взаимозаменяемые backend'ы `cpu`, `cpu-mt` и `gpu`; формат хранилища от backend'а не зависит.

## Сборка и тесты

```bash
sudo apt install libssl-dev
./scripts/build_cpu.sh                                     # Release + ctest (liboqs, CLI11, GTest, nlohmann/json — FetchContent)
CUPQC_ROOT=/path/to/cupqc-sdk ./scripts/gpu_run_all.sh     # на GPU-машине: сборка с CUDA+cuPQC, тесты, benchmark, анализ, архив
```

## Использование

```bash
vault --vault ./vault --trusted ./trusted init
vault add report.pdf                 # печатает file_id
vault list --names
vault extract <file_id> -o out.pdf
vault remove <file_id>
vault verify                         # VALID или INVALID: <шаг проверки> (код 2)
vault gc                             # удалить старые поколения
vault --backend cpu-mt --threads 8 verify
vault benchmark --config bench/configs/full.json --csv r.csv --json r.json
```

## Документы

| Документ | Что |
|---|---|
| `crypto_project.md`, `crypto_project_plan.md` | ТЗ и план этапов |
| `AGENTS.md` | устройство проекта, статус и журнал работ |
| `docs/format_v1.md` | байтовые форматы и решения по неоднозначностям ТЗ |
| `docs/stages/01…07_*.md` | планы, ревью и журналы этапов |
| `docs/gpu_workflow.md`, `docs/gpu_machine.md` | как собирать и запускать GPU-часть |
| **`docs/report/README.md`** | **итоговый отчёт об исследовании CPU и GPU**; данные и графики — `docs/report/results/` |
