# Тесты подключаются автоматически по маске. Категории:
#   unit/        — кодирование, примитивы, Merkle, домены хешей
#   integration/ — полный цикл init/add/list/extract/remove/verify
#   tamper/      — модель атакующего (§57): порча байтов, подмена, rollback, fork
#   crash/       — crash-safe commit (запуск CLI c VAULT_CRASH_POINT)
#   gpu/         — CPU == GPU (только при VAULT_ENABLE_CUDA)
include(GoogleTest)

foreach(category unit integration tamper crash)
  file(GLOB _srcs CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${category}/*.cpp)
  if(_srcs)
    add_executable(test_${category} ${_srcs})
    target_link_libraries(test_${category} PRIVATE vault_core OpenSSL::Crypto nlohmann_json::nlohmann_json GTest::gtest_main)
    target_compile_definitions(test_${category} PRIVATE
      VAULT_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
      VAULT_TEST_VECTORS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/vectors"
      VAULT_CLI_PATH="$<TARGET_FILE:vault>")
    gtest_discover_tests(test_${category} PROPERTIES LABELS ${category})
  endif()
endforeach()

if(VAULT_ENABLE_CUDA)
  file(GLOB _gpu_srcs CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/gpu/*.cpp)
  if(_gpu_srcs)
    add_executable(test_gpu ${_gpu_srcs})
    target_link_libraries(test_gpu PRIVATE vault_core GTest::gtest_main)
    gtest_discover_tests(test_gpu PROPERTIES LABELS gpu)
  endif()
endif()
