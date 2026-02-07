cmake_minimum_required(VERSION 3.16)

project(fpcap VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    # in standalone set default settings to ON
    option(FPCAP_BUILD_TESTS "Force tests to build" ON)
    option(FPCAP_BUILD_EXAMPLES "Build examples" ON)
else()
    # if used as library set default settings to OFF
    option(FPCAP_BUILD_TESTS "Force tests to build" OFF)
    option(FPCAP_BUILD_EXAMPLES "Build examples" OFF)
endif()

include(FetchContent)
FetchContent_Declare(
    zstd
    GIT_REPOSITORY https://github.com/facebook/zstd.git
    GIT_TAG        v1.5.7
    SOURCE_SUBDIR  build/cmake
)
set(ZSTD_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(ZSTD_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(ZSTD_LEGACY_SUPPORT OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_TESTS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(zstd)

# fpcap library target
file(GLOB_RECURSE FPCAP_SRC_FILES CONFIGURE_DEPENDS src/*.cpp)
add_library(fpcap ${FPCAP_SRC_FILES})
add_library(fpcap::fpcap ALIAS fpcap)

target_include_directories(fpcap
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(fpcap PRIVATE libzstd_static)

if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    # Visual Studio
    target_compile_options(fpcap PRIVATE /W4 /WX)
    add_definitions(-D_AMD64_=1) # TODO possibly there is a better way to solve the "No Target Architecture" error
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    # GCC, MinGW etc.
    target_compile_options(fpcap PRIVATE -static-libstdc++ -Wall -Wextra -pedantic)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    # Clang
    target_compile_options(fpcap PRIVATE -Wall -Wextra -pedantic)
endif()

if((CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR) AND (CMAKE_BUILD_TYPE STREQUAL "Debug"))
    # If compiling as stand-alone project in debug mode set debug flag
    target_compile_options(fpcap PRIVATE -DDEBUG)
endif()

if(WIN32)
    # Windows requires winsock32.h for ntohs and ntohl etc.
    target_link_libraries(fpcap PRIVATE ws2_32.lib)
endif()

# fpcap install instructions
include(GNUInstallDirs)
set(INSTALL_CONFIGDIR ${CMAKE_INSTALL_LIBDIR}/cmake/fpcap)

install(TARGETS fpcap
    EXPORT fpcap-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Export the targets to a script
install(EXPORT fpcap-targets
    FILE
        fpcapTargets.cmake
    NAMESPACE
        fpcap::
    DESTINATION
        ${INSTALL_CONFIGDIR}
)

# Create a ConfigVersion.cmake file
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/fpcapVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(${CMAKE_CURRENT_LIST_DIR}/cmake/fpcapConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/fpcapConfig.cmake
    INSTALL_DESTINATION ${INSTALL_CONFIGDIR}
)

# Install the config, config version and custom find modules
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/fpcapConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/fpcapConfigVersion.cmake
    DESTINATION ${INSTALL_CONFIGDIR}
)

# Exporting from the build tree
export(EXPORT fpcap-targets
    FILE ${CMAKE_CURRENT_BINARY_DIR}/fpcapTargets.cmake
    NAMESPACE fpcap::)

# Register package in the User Package Registry
export(PACKAGE fpcap)

if(FPCAP_BUILD_TESTS)
    # Add tests
    enable_testing()
    add_subdirectory(tests)
endif()

if(FPCAP_BUILD_EXAMPLES)
    # Add examples
    add_subdirectory(examples)
endif()
