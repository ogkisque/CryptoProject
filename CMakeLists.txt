cmake_minimum_required(VERSION 3.22)
project(edu_vault VERSION 0.1.0 LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Опции
# ---------------------------------------------------------------------------
option(VAULT_ENABLE_CUDA   "Собрать GPU backend (CUDA + cuPQC)"            OFF)
option(VAULT_BUILD_TESTS   "Собрать тесты (GoogleTest)"                   ON)
option(VAULT_BUILD_BENCH   "Собрать benchmark-команду"                    ON)
option(VAULT_FETCH_DEPS    "Скачивать liboqs/CLI11/GTest через FetchContent" ON)
option(VAULT_SANITIZE      "ASan + UBSan (только CPU-сборка)"            OFF)
set(VAULT_CUDA_ARCH "86" CACHE STRING "CUDA architectures (RTX 3050 = 86)")
option(VAULT_CUDA_PTXAS_VERBOSE "Печатать регистры/spill'ы kernel'ов при сборке (-Xptxas -v)" ON)
set(CUPQC_ROOT "" CACHE PATH "Путь к распакованному cuPQC SDK")

if(VAULT_ENABLE_CUDA)
  enable_language(CUDA)  # только на GPU-машине (docs/gpu_workflow.md)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(CompilerFlags)

# ---------------------------------------------------------------------------
# Публичные интерфейсы (header-only цель — существует всегда)
# ---------------------------------------------------------------------------
add_library(vault_headers INTERFACE)
target_include_directories(vault_headers INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(vault_headers INTERFACE cxx_std_20)

# Компиляционная проверка заголовков — работает уже сейчас, без зависимостей.
add_executable(vault_header_check tests/header_check.cpp)
target_link_libraries(vault_header_check PRIVATE vault_headers vault_warnings)

# ---------------------------------------------------------------------------
# Реализация. Цели появляются по мере появления исходников (src/**/*.cpp),
# чтобы каркас конфигурировался на любом этапе.
# ---------------------------------------------------------------------------
file(GLOB_RECURSE VAULT_CORE_SOURCES CONFIGURE_DEPENDS
     ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
list(FILTER VAULT_CORE_SOURCES EXCLUDE REGEX ".*/src/cli/.*")
# Host-часть GPU (порционирование, упаковка) — обычный C++, собирается и тестируется всегда.
file(GLOB VAULT_GPU_HOST_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/cuda/host/*.cpp)
list(APPEND VAULT_CORE_SOURCES ${VAULT_GPU_HOST_SOURCES})

if(VAULT_CORE_SOURCES)
  include(Dependencies)  # OpenSSL >= 3.0, liboqs, CLI11, GTest

  find_package(Threads REQUIRED)
  # Версия сборки для SystemInfo (воспроизводимость benchmark'а).
  execute_process(COMMAND git -C ${CMAKE_CURRENT_SOURCE_DIR} describe --always --dirty --abbrev=12
                  OUTPUT_VARIABLE VAULT_GIT_COMMIT OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
  if(NOT VAULT_GIT_COMMIT)
    set(VAULT_GIT_COMMIT "unknown")
  endif()
  string(TOUPPER "${CMAKE_BUILD_TYPE}" VAULT_BUILD_TYPE_UC)
  add_library(vault_core STATIC ${VAULT_CORE_SOURCES})
  target_link_libraries(vault_core
    PUBLIC  vault_headers 
    PRIVATE vault_warnings OpenSSL::Crypto OQS::oqs nlohmann_json::nlohmann_json Threads::Threads)
  # kernels/*.cuh (общий код device/CPU) и host/launch_plan.hpp видны и тестам.
  target_include_directories(vault_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/cuda)
  target_compile_definitions(vault_core PRIVATE
    VAULT_COMPILE_FLAGS="${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${VAULT_BUILD_TYPE_UC}}"
    VAULT_BUILD_TYPE="${CMAKE_BUILD_TYPE}"
    VAULT_GIT_COMMIT="${VAULT_GIT_COMMIT}")

  if(VAULT_ENABLE_CUDA)
    # CUDA-исходники добавляются прямо в vault_core (а не отдельной библиотекой): GPU-код использует
    # VaultError и cuda/host/*.cpp из vault_core, а vault_core вызывает фабрики GPU — отдельная
    # статическая библиотека дала бы циклическую зависимость при линковке.
    include(Cuda)
    vault_attach_cuda(vault_core)
    target_compile_definitions(vault_core PUBLIC VAULT_HAS_CUDA=1)
  endif()

  file(GLOB VAULT_CLI_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/cli/*.cpp)
  if(VAULT_CLI_SOURCES)
    add_executable(vault ${VAULT_CLI_SOURCES})
    target_link_libraries(vault PRIVATE vault_core vault_warnings CLI11::CLI11)
  endif()

  if(VAULT_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
  endif()
else()
  message(STATUS "edu_vault: исходников реализации пока нет — собирается только vault_header_check")
endif()
