# Общие предупреждения. Подключаются как INTERFACE-цель vault_warnings.
add_library(vault_warnings INTERFACE)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(vault_warnings INTERFACE
    $<$<COMPILE_LANGUAGE:CXX>:-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wno-sign-conversion>)
endif()

if(VAULT_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

# Воспроизводимость замеров (этап 7): -march=native привязывает бинарник к CPU сборочной машины, и результаты
# нельзя повторить на другой. Release-флаги проекта — стандартные -O3 -DNDEBUG без -march (фиксируются в results.json).
if("${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_RELEASE} $ENV{CXXFLAGS}" MATCHES "-march=native")
  message(WARNING "-march=native в флагах: результаты benchmark'а будут привязаны к этому CPU (см. docs/gpu_workflow.md)")
endif()
