# GPU-часть (Milestone 5-6). Подключается только при VAULT_ENABLE_CUDA=ON
# и только на машине с CUDA Toolkit (>= 12.x) и cuPQC SDK.
#
# TODO(M5): проверить на GPU-машине точные имена CMake-пакета/целей cuPQC
# (cuPQC SDK поставляется как статическая библиотека + заголовки, требует
# relocatable device code и device LTO). Ниже — запасной ручной вариант.

enable_language(CUDA)
set(CMAKE_CUDA_STANDARD 17)
set(CMAKE_CUDA_STANDARD_REQUIRED ON)
set(CMAKE_CUDA_ARCHITECTURES ${VAULT_CUDA_ARCH})
find_package(CUDAToolkit 12.0 REQUIRED)

file(GLOB_RECURSE VAULT_GPU_SOURCES CONFIGURE_DEPENDS
     ${CMAKE_SOURCE_DIR}/cuda/src/*.cu
     ${CMAKE_SOURCE_DIR}/cuda/src/*.cpp)
if(NOT VAULT_GPU_SOURCES)
  message(FATAL_ERROR "VAULT_ENABLE_CUDA=ON, но cuda/src/ пуст")
endif()

add_library(vault_gpu STATIC ${VAULT_GPU_SOURCES})
target_include_directories(vault_gpu PUBLIC ${CMAKE_SOURCE_DIR}/include
                                     PRIVATE ${CMAKE_SOURCE_DIR}/cuda)
set_target_properties(vault_gpu PROPERTIES
  CUDA_SEPARABLE_COMPILATION ON
  CUDA_RESOLVE_DEVICE_SYMBOLS ON)
target_compile_options(vault_gpu PRIVATE
  $<$<COMPILE_LANGUAGE:CUDA>:--expt-relaxed-constexpr -lineinfo>)
target_link_libraries(vault_gpu PUBLIC CUDA::cudart)

# --- cuPQC ---
find_package(cupqc CONFIG QUIET HINTS ${CUPQC_ROOT})
if(cupqc_FOUND)
  message(STATUS "cuPQC: найден CMake-пакет")
  # TODO(M6): target_link_libraries(vault_gpu PRIVATE <cupqc target>)
else()
  find_path(CUPQC_INCLUDE_DIR NAMES cupqc.hpp HINTS ${CUPQC_ROOT} PATH_SUFFIXES include)
  find_library(CUPQC_LIBRARY NAMES cupqc cupqc_static HINTS ${CUPQC_ROOT} PATH_SUFFIXES lib lib64)
  if(CUPQC_INCLUDE_DIR AND CUPQC_LIBRARY)
    target_include_directories(vault_gpu PRIVATE ${CUPQC_INCLUDE_DIR})
    target_link_libraries(vault_gpu PRIVATE ${CUPQC_LIBRARY})
    target_compile_definitions(vault_gpu PUBLIC VAULT_HAS_CUPQC=1)
  else()
    message(WARNING "cuPQC не найден (CUPQC_ROOT=${CUPQC_ROOT}); ML-KEM/ML-DSA GPU будут недоступны")
  endif()
endif()
