cmake_minimum_required(VERSION 3.16)

project(mmpr VERSION 0.1.0 LANGUAGES CXX)

list(INSERT CMAKE_MODULE_PATH 0 ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

option(MMPR_BUILD_TESTS "Force tests to build" OFF)
option(MMPR_BUILD_BENCHMARK "Build benchmarks" OFF)
option(MMPR_BUILD_EXAMPLES "Build examples" OFF)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    # Enable tests and benchmarks if building as stand-alone project
    set(MMPR_BUILD_TESTS ON)
    set(MMPR_BUILD_BENCHMARK ON)
    set(MMPR_BUILD_EXAMPLES ON)
endif()

# Add Boost (target Boost::boost)
set(MIN_BOOST_VERSION 1.71)
find_package(Boost ${MIN_BOOST_VERSION} REQUIRED COMPONENTS filesystem)

# Add Zstd compression library
set(MIN_ZSTD_VERSION 1.4)
find_package(ZSTD ${MIN_ZSTD_VERSION} REQUIRED MODULE)

# mmpr library target
add_library(mmpr
    src/MMPcapNgReader.cpp
    src/PcapNgBlockOptionParser.cpp
    src/PcapNgBlockParser.cpp
    src/util.h
    src/ZstdDecompressor.cpp
    src/ZstdPcapNgReader.cpp
)

add_library(mmpr::mmpr ALIAS mmpr)

target_include_directories(mmpr
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_features(mmpr PRIVATE cxx_std_11)
target_compile_options(mmpr PRIVATE -static-libstdc++ -Wall -Wextra -pedantic)

target_link_libraries(mmpr
    PUBLIC
        Boost::filesystem
    PRIVATE
        ZSTD::ZSTD
)

# mmpr install instructions
include(GNUInstallDirs)
set(INSTALL_CONFIGDIR ${CMAKE_INSTALL_LIBDIR}/cmake/mmpr)

install(TARGETS mmpr
    EXPORT mmpr-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Export the targets to a script
install(EXPORT mmpr-targets
    FILE
        mmprTargets.cmake
    NAMESPACE
        mmpr::
    DESTINATION
        ${INSTALL_CONFIGDIR}
)

# Create a ConfigVersion.cmake file
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/mmprVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(${CMAKE_CURRENT_LIST_DIR}/cmake/mmprConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/mmprConfig.cmake
    INSTALL_DESTINATION ${INSTALL_CONFIGDIR}
)

# Install the config, config version and custom find modules
install(FILES
    ${CMAKE_CURRENT_LIST_DIR}/cmake/FindZSTD.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/mmprConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/mmprConfigVersion.cmake
    DESTINATION ${INSTALL_CONFIGDIR}
)

# Exporting from the build tree
configure_file(${CMAKE_CURRENT_LIST_DIR}/cmake/FindZSTD.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/FindZSTD.cmake
    COPYONLY)

export(EXPORT mmpr-targets
    FILE ${CMAKE_CURRENT_BINARY_DIR}/mmprTargets.cmake
    NAMESPACE mmpr::)

# Register package in the User Package Registry
export(PACKAGE mmpr)

if(MMPR_BUILD_TESTS)
    # Add tests
    enable_testing()
    add_subdirectory(tests)
endif()

if(MMPR_BUILD_BENCHMARK)
    # Add benchmarks
    add_subdirectory(benchmark)
endif()

if(MMPR_BUILD_EXAMPLES)
    # Add examples
    add_subdirectory(examples)
endif()