# GPU-часть (этапы 5-6). Подключается только при VAULT_ENABLE_CUDA=ON и только на машине с CUDA Toolkit >= 12.
# ВНИМАНИЕ: файл не проверялся на машине разработки (CUDA здесь не ставится, docs/gpu_workflow.md);
# все места, зависящие от конкретной установки, помечены UNVERIFIED.
#
# Рассчитано на: CUDA Toolkit 12.x (SHA3/Merkle: >= 12.0; cuPQC: >= 12.8), архитектура SM 86 (RTX 3050), nvcc с
# поддержкой C++20 для .cu (заголовки проекта используют std::span). cuPQC SDK (этап 6) опционален: без него GPU ML-KEM/ML-DSA недоступны,
# SHA3/Merkle на GPU собираются и работают.

find_package(CUDAToolkit 12.0 REQUIRED)

# find_package(cupqc) учитывает CUPQC_ROOT как <Package>_ROOT (без этого CMake >= 3.27 предупреждает CMP0144).
if(POLICY CMP0144)
  cmake_policy(SET CMP0144 NEW)
endif()

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
  if(CUPQC_ROOT)
    # Относительный путь из командной строки зависит от каталога запуска — приводим к абсолютному сразу,
    # чтобы диагностика ниже показывала, где именно искали (первый запуск на GPU-машине: SDK не нашёлся из-за
    # относительного CUPQC_ROOT, а сборка молча прошла без cuPQC).
    get_filename_component(CUPQC_ROOT "${CUPQC_ROOT}" ABSOLUTE)
  endif()
  if(CUPQC_ROOT AND _pqc_sources_present)
    # Требования cuPQC-PK (docs.nvidia.com/cuda/cupqc/introduction/requirements.html): CUDA Toolkit и nvcc >= 12.8,
    # GPU SM 80/86/87/89/90, C++17+.
    if(CUDAToolkit_VERSION VERSION_LESS 12.8)
      message(WARNING "cuPQC требует CUDA Toolkit >= 12.8 (найден ${CUDAToolkit_VERSION}): GPU ML-KEM/ML-DSA отключены")
    else()
      # Основной путь — как Makefile официальных примеров NVIDIA: -I<SDK>/include/cupqc -I<SDK>/include (commondx)
      # и <SDK>/lib/libcupqc-pk.a. find_package(cupqc) НЕ вызывается первым: в cuPQC SDK 0.6.0 его конфиг падает
      # фатальной ошибкой CMake (cupqc-static-targets-release.cmake ссылается на не созданные цели
      # cupqc-hash_static / cupqc-ntt_static; второй запуск на GPU-машине, CMake 3.28), и QUIET её не гасит.
      find_library(_cupqc_pk_lib NAMES cupqc-pk HINTS ${CUPQC_ROOT}/lib ${CUPQC_ROOT}/lib64 NO_DEFAULT_PATH NO_CACHE)
      if(_cupqc_pk_lib AND EXISTS ${CUPQC_ROOT}/include/cupqc/pk.hpp)
        set(_have_cupqc ON)
        target_link_libraries(${target} PRIVATE ${_cupqc_pk_lib})
        message(STATUS "cuPQC: ${_cupqc_pk_lib} (подключение как в Makefile примеров NVIDIA)")
      elseif(EXISTS ${CUPQC_ROOT}/cmake/cupqc-config.cmake)
        # Запасной путь — CMake-пакет SDK (Getting Started): только если раскладка нестандартная.
        find_package(cupqc CONFIG QUIET HINTS ${CUPQC_ROOT}/cmake ${CUPQC_ROOT} PATH_SUFFIXES cmake)
        if(cupqc_FOUND AND TARGET cupqc-pk_static)
          set(_have_cupqc ON)
          target_link_libraries(${target} PRIVATE cupqc-pk_static)
          message(STATUS "cuPQC: CMake-пакет SDK, цель cupqc-pk_static")
        endif()
      endif()
      if(_have_cupqc)
        # pk.hpp лежит в include/cupqc, а зависимость commondx — в include (по Getting Started).
        target_include_directories(${target} PRIVATE ${CUPQC_ROOT}/include/cupqc ${CUPQC_ROOT}/include)
        # Флаги LTO (-dlto -arch=sm_XY) выставляются ниже, после set_target_properties.
      endif()
    endif()
  endif()
  if(_have_cupqc)
    message(STATUS "cuPQC: найден, GPU ML-KEM/ML-DSA включены")
    target_compile_definitions(${target} PUBLIC VAULT_HAS_CUPQC=1)
  else()
    # Диагностика: что из ожидаемой раскладки SDK (Getting Started) есть на диске.
    set(_diag "")
    if(CUPQC_ROOT)
      foreach(_p "" "/cmake" "/include/cupqc/pk.hpp" "/include/commondx" "/lib/libcupqc-pk.a")
        if(EXISTS "${CUPQC_ROOT}${_p}")
          string(APPEND _diag "\n    есть:  ${CUPQC_ROOT}${_p}")
        else()
          string(APPEND _diag "\n    НЕТ:   ${CUPQC_ROOT}${_p}")
        endif()
      endforeach()
    endif()
    message(WARNING "cuPQC не найден (CUPQC_ROOT='${CUPQC_ROOT}'): GPU ML-KEM/ML-DSA недоступны; SHA3/Merkle на GPU собираются${_diag}")
    list(FILTER _gpu_cu EXCLUDE REGEX ".*/gpu_(kem|sig)_backend\\.cu$")
  endif()
  # Машиночитаемый маркер для scripts/gpu_run_all.sh: успешная сборка ещё не значит, что cuPQC подключён.
  if(_have_cupqc)
    message(STATUS "VAULT_CUPQC=ON")
  else()
    message(STATUS "VAULT_CUPQC=OFF")
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
  if(_have_cupqc)
    # cuPQC-PK собран с link-time optimization. NVIDIA документирует ровно одну форму сборки
    # (Getting Started, Makefile примеров): `nvcc -dlto -arch=sm_XY` — и при компиляции, и при device-link.
    # CUDA_ARCHITECTURES превратился бы в --generate-code=arch=compute_86,code=[compute_86,sm_86], и смешивание
    # этого с -dlto не задокументировано. Поэтому при cuPQC архитектура задаётся явно той же парой флагов, а
    # CUDA_ARCHITECTURES выключается. VAULT_CUDA_ARCH=native -> -arch=native (как в Makefile примеров).
    # UNVERIFIED(cuPQC): device-link статической библиотеки с CUDA_RESOLVE_DEVICE_SYMBOLS вместе с cupqc-pk_static.
    if(VAULT_CUDA_ARCH STREQUAL "native")
      set(_arch_flag "-arch=native")
    else()
      set(_arch_flag "-arch=sm_${VAULT_CUDA_ARCH}")
    endif()
    set_target_properties(${target} PROPERTIES CUDA_ARCHITECTURES OFF)
    target_compile_options(${target} PRIVATE $<$<COMPILE_LANGUAGE:CUDA>:${_arch_flag} -dlto>)
    target_link_options(${target} PUBLIC $<DEVICE_LINK:${_arch_flag}> $<DEVICE_LINK:-dlto>)
    message(STATUS "cuPQC: device-код собирается как в документации NVIDIA: ${_arch_flag} -dlto")
  endif()
  target_link_libraries(${target} PUBLIC CUDA::cudart)
endfunction()
