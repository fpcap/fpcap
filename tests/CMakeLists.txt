if(CMAKE_PROJECT_NAME STREQUAL "fpcap")
    # Add googletest directly to our build. This defines
    # the gtest and gtest_main targets.
    add_subdirectory(libs/googletest EXCLUDE_FROM_ALL)
else()
    find_package(GTest REQUIRED)
endif()

file(GLOB_RECURSE FPCAP_TEST_SRC_FILES CONFIGURE_DEPENDS src/*.cpp src/**/*.cpp)
add_executable(fpcap_test ${FPCAP_TEST_SRC_FILES})
target_link_libraries(fpcap_test
    PUBLIC
        fpcap::fpcap
        gtest_main
        gmock
)

add_test(NAME fpcap_test
    COMMAND fpcap_test
)
