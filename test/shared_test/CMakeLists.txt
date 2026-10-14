cmake_minimum_required(VERSION 3.16)

find_package(GTest CONFIG REQUIRED)

add_executable(shared_test main.cpp
    config_logic_test.cpp
    metacache_logic_test.cpp
    readcache_logic_test.cpp
    trace_format_test.cpp)
usvfs_set_test_properties(shared_test)
target_link_libraries(shared_test PRIVATE test_utils GTest::gtest GTest::gtest_main)
