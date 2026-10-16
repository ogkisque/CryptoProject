# Заглушки CUDA для синтаксической проверки

`scripts/check_cuda_syntax.sh` прогоняет `cuda/src/*.cu` через `clang` (режимы `--cuda-host-only` и
`--cuda-device-only`) с этими заглушками вместо CUDA Toolkit. Так на машине разработки (CUDA здесь не
ставится, `docs/gpu_workflow.md`) ловятся опечатки, неверные имена и вызовы host-функций из device-кода.

Ограничения: это **не nvcc**. Не проверяются PTX, регистры/shared memory, ограничения конкретной версии
nvcc, `cmake/Cuda.cmake`, вызовы cuPQC. При добавлении новых вызовов CUDA runtime их нужно объявить в
`cuda_runtime.h`. Известная помеха: clang 14 не собирает `<chrono>` из libstdc++ 13 (ошибка про
`hh_mm_ss::_S_fractional_width`) — скрипт её отфильтровывает.
