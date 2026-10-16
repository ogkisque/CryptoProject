# Зависимости CPU-части.
#   OpenSSL >= 3.0 : AES-256-GCM, AES-256-KW, HKDF(SHA3-256), SHA3-256, RAND_bytes
#   liboqs         : ML-KEM-768, ML-DSA-65 (нужны *_derand и sign_with_ctx_str -> >= 0.12)
#   CLI11          : разбор аргументов
#   GoogleTest     : тесты
include(FetchContent)

find_package(OpenSSL 3.0 REQUIRED)  # apt: libssl-dev

find_package(liboqs CONFIG QUIET)
if(NOT liboqs_FOUND)
  if(NOT VAULT_FETCH_DEPS)
    message(FATAL_ERROR "liboqs не найден, а VAULT_FETCH_DEPS=OFF")
  endif()
  set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "" FORCE)
  set(OQS_USE_OPENSSL ON CACHE BOOL "" FORCE)
  set(OQS_DIST_BUILD ON CACHE BOOL "" FORCE)
  set(OQS_MINIMAL_BUILD "KEM_ml_kem_768;SIG_ml_dsa_65" CACHE STRING "" FORCE)
  FetchContent_Declare(liboqs
    GIT_REPOSITORY https://github.com/open-quantum-safe/liboqs.git
    GIT_TAG        0.14.0)  # TODO(M1): проверить наличие OQS_SIG_sign_with_ctx_str и *_derand
  FetchContent_MakeAvailable(liboqs)
  if(NOT TARGET OQS::oqs)
    add_library(OQS::oqs ALIAS oqs)
  endif()
endif()

find_package(CLI11 CONFIG QUIET)
if(NOT CLI11_FOUND)
  FetchContent_Declare(cli11
    GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
    GIT_TAG        v2.4.2)
  FetchContent_MakeAvailable(cli11)
endif()

if(VAULT_BUILD_TESTS)
  find_package(GTest CONFIG QUIET)
  if(NOT GTest_FOUND)
    FetchContent_Declare(googletest
      GIT_REPOSITORY https://github.com/google/googletest.git
      GIT_TAG        v1.14.0)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
  endif()
endif()
