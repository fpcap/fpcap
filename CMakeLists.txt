cmake_minimum_required(VERSION 3.16)

project(mmpr VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    # in standalone set default settings to ON
    option(MMPR_BUILD_TESTS "Force tests to build" ON)
    option(MMPR_BUILD_EXAMPLES "Build examples" ON)
else()
    # if used as library set default settings to OFF
    option(MMPR_BUILD_TESTS "Force tests to build" OFF)
    option(MMPR_BUILD_EXAMPLES "Build examples" OFF)
endif()

# mmpr library target
file(GLOB_RECURSE MMPR_SRC_FILES src/*.cpp)
add_library(mmpr ${MMPR_SRC_FILES})
add_library(mmpr::mmpr ALIAS mmpr)

target_include_directories(mmpr
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<INSTALL_INTERFACE:include/filesystem>
        $<INSTALL_INTERFACE:include/filesystem/writing>
        $<INSTALL_INTERFACE:include/filesystem/reading>
        $<INSTALL_INTERFACE:include/pcap>
        $<INSTALL_INTERFACE:include/pcapng>
        $<INSTALL_INTERFACE:include/modified_pcap>
        $<INSTALL_INTERFACE:libs/zstd/lib>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/filesystem>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/filesystem/writing>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/filesystem/reading>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/pcap>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/pcapng>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/modified_pcap>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/libs/zstd/lib>
)

target_compile_features(mmpr PUBLIC cxx_std_17)
if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    # Visual Studio
    target_compile_options(mmpr PRIVATE /Wall)
    add_definitions(-D_AMD64_=1) # TODO possibly there is a better way to solve the "No Target Architecture" error
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    # GCC, MinGW etc.
    target_compile_options(mmpr PRIVATE -static-libstdc++ -Wall -Wextra -pedantic)
endif()

if((CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR) AND (CMAKE_BUILD_TYPE STREQUAL "Debug"))
    # If compiling as stand-alone project in debug mode set debug flag
    target_compile_options(mmpr PRIVATE -DDEBUG)
endif()

set(ZSTD_BUILD_STATIC ON)
set(ZSTD_BUILD_SHARED OFF)
set(ZSTD_LEGACY_SUPPORT OFF)
set(ZSTD_BUILD_PROGRAMS OFF)
set(ZSTD_BUILD_TESTS OFF)
add_subdirectory(libs/zstd/build/cmake)
target_link_libraries(mmpr PRIVATE libzstd_static)

if(WIN32)
    # Windows requires winsock32.h for ntohs and ntohl etc.
    target_link_libraries(mmpr PRIVATE ws2_32.lib)
endif()

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
    ${CMAKE_CURRENT_BINARY_DIR}/mmprConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/mmprConfigVersion.cmake
    DESTINATION ${INSTALL_CONFIGDIR}
)

# Exporting from the build tree
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

if(MMPR_BUILD_EXAMPLES)
    # Add examples
    add_subdirectory(examples)
endif()
