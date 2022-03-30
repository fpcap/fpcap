# see /opt/local/share/cmake-3.16/Modules/FindGTest.cmake
find_package(benchmark QUIET)

if(NOT TARGET benchmark::benchmark)
    # Add googletest directly to our build. This defines
    # the benchmark targets.
    set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "" FORCE)
    set(BENCHMARK_USE_BUNDLED_GTEST OFF CACHE BOOL "" FORCE)
    add_subdirectory(libs/benchmark EXCLUDE_FROM_ALL)
endif()

if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/libs/PcapPlusPlus)
    message(FATAL_ERROR "[mmpr] Could not find benchmark/libs/PcapPlusPlus")
else()
    # Add PcapPP target
    add_subdirectory(libs/PcapPlusPlus)
endif()

add_executable(mmpr_benchmark
    src/main.cpp
    src/packet_reading.cpp
)
target_compile_features(mmpr_benchmark PRIVATE cxx_std_11)
target_link_libraries(mmpr_benchmark benchmark::benchmark mmpr::mmpr PcapPP pcap)

add_test(NAME mmpr_benchmark
    COMMAND mmpr_benchmark
)
