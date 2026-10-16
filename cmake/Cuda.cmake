# GPU-часть (этапы 5-6). Подключается только при VAULT_ENABLE_CUDA=ON и только на машине с CUDA Toolkit >= 12.
# ВНИМАНИЕ: файл не проверялся на машине разработки (CUDA здесь не ставится, docs/gpu_workflow.md);
# все места, зависящие от конкретной установки, помечены UNVERIFIED.
#
# Рассчитано на: CUDA Toolkit 12.x (проверка: find_package(CUDAToolkit 12.0)), архитектура SM 86 (RTX 3050),
# nvcc с поддержкой C++17. cuPQC SDK (этап 6) опционален: без него GPU ML-KEM/ML-DSA недоступны,
# SHA3/Merkle на GPU собираются и работают.

find_package(CUDAToolkit 12.0 REQUIRED)

# CUDA-исходники добавляются прямо в цель (vault_core), см. комментарий в корневом CMakeLists.txt.
function(vault_attach_cuda target)
  file(GLOB _gpu_cu  CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/cuda/src/*.cu)
  file(GLOB _gpu_cpp CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/cuda/src/*.cpp)
  if(NOT _gpu_cu)
    message(FATAL_ERROR "VAULT_ENABLE_CUDA=ON, но cuda/src/*.cu не найдены")
  endif()

  # --- cuPQC (этап 6): без него собираем заглушки gpu_pqc_stub.cpp ---
  # UNVERIFIED(cuPQC): имя CMake-пакета/цели и имена заголовков/библиотеки берутся из документации SDK.
  set(_have_cupqc OFF)
  # Реализации GPU ML-KEM/ML-DSA появляются на этапе 6. Пока их нет, cuPQC не включаем даже при заданном
  # CUPQC_ROOT: иначе заглушки gpu_pqc_stub.cpp выключатся, а реализаций не будет -> ошибка линковки.
  set(_pqc_sources_present OFF)
  if(EXISTS ${CMAKE_SOURCE_DIR}/cuda/src/gpu_kem_backend.cu AND EXISTS ${CMAKE_SOURCE_DIR}/cuda/src/gpu_sig_backend.cu)
    set(_pqc_sources_present ON)
  elseif(CUPQC_ROOT)
    message(WARNING "CUPQC_ROOT задан, но cuda/src/gpu_{kem,sig}_backend.cu ещё нет (этап 6): cuPQC не подключается")
  endif()
  if(CUPQC_ROOT AND _pqc_sources_present)
    find_package(cupqc CONFIG QUIET HINTS ${CUPQC_ROOT} PATH_SUFFIXES lib/cmake/cupqc)  # UNVERIFIED(cuPQC)
    if(cupqc_FOUND)
      set(_have_cupqc ON)
      target_link_libraries(${target} PRIVATE cupqc::cupqc)  # UNVERIFIED(cuPQC): имя цели
    else()
      find_path(CUPQC_INCLUDE_DIR NAMES cupqc.hpp HINTS ${CUPQC_ROOT} PATH_SUFFIXES include)
      find_library(CUPQC_LIBRARY NAMES cupqc cupqc_static HINTS ${CUPQC_ROOT} PATH_SUFFIXES lib lib64)
      if(CUPQC_INCLUDE_DIR AND CUPQC_LIBRARY)
        set(_have_cupqc ON)
        target_include_directories(${target} PRIVATE ${CUPQC_INCLUDE_DIR})
        target_link_libraries(${target} PRIVATE ${CUPQC_LIBRARY})
      endif()
    endif()
  endif()
  if(_have_cupqc)
    message(STATUS "cuPQC: найден, GPU ML-KEM/ML-DSA включены")
    target_compile_definitions(${target} PUBLIC VAULT_HAS_CUPQC=1)
  else()
    message(WARNING "cuPQC не найден (CUPQC_ROOT='${CUPQC_ROOT}'): GPU ML-KEM/ML-DSA недоступны; SHA3/Merkle на GPU собираются")
    list(FILTER _gpu_cu EXCLUDE REGEX ".*/gpu_(kem|sig)_backend\\.cu$")
  endif()

  target_sources(${target} PRIVATE ${_gpu_cu} ${_gpu_cpp})
  target_include_directories(${target} PRIVATE ${CMAKE_SOURCE_DIR}/cuda)
  # UNVERIFIED(nvcc): C++20 для .cu нужен из-за std::span в публичных заголовках; требует nvcc >= 12.0 и хост-
  # компилятор, поддерживаемый этой версией CUDA (GCC 13 официально — с CUDA 12.4+; иначе -ccbin gcc-12).
  # UNVERIFIED(nvcc): CUDA_SEPARABLE_COMPILATION в смешанной статической библиотеке — device-link выполнится
  # при линковке исполняемых файлов (CUDA_RESOLVE_DEVICE_SYMBOLS).
  set_target_properties(${target} PROPERTIES
    CUDA_STANDARD 20                   # заголовки проекта используют std::span (C++20); nvcc 12.x его поддерживает
    CUDA_STANDARD_REQUIRED ON
    CUDA_ARCHITECTURES "${VAULT_CUDA_ARCH}"
    CUDA_SEPARABLE_COMPILATION ON      # cuPQC требует relocatable device code (UNVERIFIED(cuPQC))
    CUDA_RESOLVE_DEVICE_SYMBOLS ON)
  target_compile_options(${target} PRIVATE
    $<$<COMPILE_LANGUAGE:CUDA>:--expt-relaxed-constexpr -lineinfo>)
  # Регистры и spill'ы каждого kernel'а в лог сборки: это главный риск производительности «потока на объект»
  # (состояние Keccak с динамической индексацией уходит в local memory), а проверить его можно только по build.log.
  if(VAULT_CUDA_PTXAS_VERBOSE)
    target_compile_options(${target} PRIVATE $<$<COMPILE_LANGUAGE:CUDA>:-Xptxas=-v>)
  endif()
  target_link_libraries(${target} PUBLIC CUDA::cudart)
endfunction()
