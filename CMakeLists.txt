cmake_minimum_required(VERSION 3.11)

project(MMPR
        DESCRIPTION "Memory mapping PcapNg reader"
        VERSION 0.1.0
        LANGUAGES CXX
        )

option(MMPR_BUILD_EXAMPLES "Build examples" ON)
option(MMPR_BUILD_TESTS "Force tests to build" OFF)

if (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    message(STATUS "Building MMPR as main project")

    set(CMAKE_CXX_STANDARD 11)
    add_compile_options(-Wall -Wextra -pedantic -Werror)
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

# Add fmt (target fmt::fmt)
FetchContent_Declare(
        fmtlib
        GIT_REPOSITORY https://github.com/fmtlib/fmt.git
        GIT_TAG 5.3.0)
FetchContent_MakeAvailable(fmtlib)

# MMPR library
add_subdirectory(src)

# Examples only available if this is the main app
if (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME OR MMPR_BUILD_EXAMPLES)
    # MMPR executables
    add_subdirectory(examples)
endif ()

# Testing only available if this is the main app
if ((CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME OR MMPR_BUILD_TESTS) AND BUILD_TESTING)
    # Add GoogleTest
    include(FetchContent)
    FetchContent_Declare(
            googletest
            URL https://github.com/google/googletest/archive/609281088cfefc76f9d0ce82e1ff6c30cc3591e5.zip
    )
    FetchContent_MakeAvailable(googletest)

    enable_testing()

    add_executable(
            testPcapNgReader
            tests/testPcapNgReader.cpp
            include/mmpr/mmpr.h include/mmpr/PcapNgBlockOptionParser.h)
    target_link_libraries(
            testPcapNgReader
            gtest_main
    )

    include(GoogleTest)
    gtest_discover_tests(testPcapNgReader)

    add_subdirectory(tests)
endif ()
