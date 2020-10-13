cmake_minimum_required (VERSION 3.0)
project (r2checker)

include_directories ("${CMAKE_CURRENT_SOURCE_DIR}/install/include/libr" "${CMAKE_CURRENT_SOURCE_DIR}/install/include/libr/sdb")
link_directories("${CMAKE_CURRENT_SOURCE_DIR}/install/lib")

add_executable(r2checker check.c)
target_link_libraries(r2checker r_core r_config r_bin r_flag r_anal r_asm)
