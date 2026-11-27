cmake_minimum_required(VERSION 3.17)
project(qsafe_ndk_hardening_check LANGUAGES C CXX)
include("${CMAKE_CURRENT_LIST_DIR}/../../cmake/QsafeAndroidHardening.cmake")

add_executable(check_c probe.c)
qsafe_harden_android_target(check_c)

configure_file(probe.c probe.cpp COPYONLY)
add_executable(check_cpp "${CMAKE_CURRENT_BINARY_DIR}/probe.cpp")
target_compile_definitions(check_cpp PRIVATE EXPECT_FORTIFY=3)
target_compile_options(check_cpp PRIVATE -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3)
qsafe_harden_android_target(check_cpp)
