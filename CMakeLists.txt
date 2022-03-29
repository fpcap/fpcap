cmake_minimum_required(VERSION 3.11)

project(MMPR
        DESCRIPTION "Memory mapping PcapNg reader"
        VERSION 0.1.0
        LANGUAGES CXX
        )

option(MMPR_BUILD_EXAMPLES "Build examples" OFF)
option(MMPR_BUILD_BENCHMARK "Build benchmarks" OFF)
option(MMPR_BUILD_TESTS "Force tests to build" OFF)

if (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    message(STATUS "Building MMPR as main project")

    set(CMAKE_CXX_STANDARD 11)
    add_compile_options(-Wall -Wextra -pedantic)
    set(CMAKE_CXX_FLAGS "-static-libstdc++")
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
    set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g -DDEBUG")

    # Let's nicely support folders in IDEs
    set_property(GLOBAL PROPERTY USE_FOLDERS ON)
else ()
    message(STATUS "Building MMPR as library through add_subdirectory (or similar)")
endif ()

# FetchContent added in CMake 3.11, downloads missing libs during the configure step
include(FetchContent)

# Add Boost (target Boost::boost)
find_package(Boost 1.71.0 REQUIRED)
find_package(Boost 1.71.0 COMPONENTS filesystem REQUIRED)

# Add Zstd compression library
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
find_package(ZSTD 1.4.0 MODULE REQUIRED)

# Add fmt (target fmt::fmt)
if (NOT TARGET fmt)
    add_subdirectory(libs/fmt EXCLUDE_FROM_ALL)
endif ()

# MMPR library
add_subdirectory(src)

# Examples only available if this is the main app
if (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME OR MMPR_BUILD_EXAMPLES)
    # MMPR executables
    add_subdirectory(examples)
endif ()

# Testing only available if this is the main app
if (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME OR MMPR_BUILD_TESTS)
    # Add GoogleTest
    if (NOT TARGET gtest)
        add_subdirectory(libs/googletest EXCLUDE_FROM_ALL)
    endif ()

    add_executable(
            testPcapNgReader
            tests/testPcapNgReader.cpp
            include/mmpr/mmpr.h
            include/mmpr/PcapNgBlockOptionParser.h
    )
    target_link_libraries(
            testPcapNgReader
            gtest_main
    )

    include(GoogleTest)
    gtest_discover_tests(testPcapNgReader)
endif ()

# Benchmark only available if this is the main app
if (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME OR MMPR_BUILD_BENCHMARK)
    if (EXISTS libs/pcap-plus-plus)
        # PcapPlusPlus library
        add_subdirectory(libs/pcap-plus-plus EXCLUDE_FROM_ALL)

        #set(BENCHMARK_DOWNLOAD_DEPENDENCIES ON BOOL)
        add_subdirectory(libs/googlebenchmark EXCLUDE_FROM_ALL)

        file(GLOB_RECURSE benchmark_files
                "${PROJECT_SOURCE_DIR}/benchmark/*.cpp"
                )

        add_executable(mmpr-benchmarks
                ${src_files}
                ${benchmark_files}
                )

        target_include_directories(mmpr-benchmarks PUBLIC
                libs/googlebenchmark/include/
                libs/pcap-plus-plus/Pcap++/header
                ${PROJECT_SOURCE_DIR}/include
                )

        target_link_libraries(mmpr-benchmarks
                PRIVATE
                ${Boost_LIBRARIES}
                PUBLIC
                benchmark::benchmark
                PcapPP
                mmpr
                )
    else ()
        message(WARNING "Trying to build mmpr-benchmark, but could not find libs/pcap-plus-plus")
    endif ()
endif ()