if(CMAKE_PROJECT_NAME STREQUAL "mmpr")
    # Add googletest directly to our build. This defines
    # the gtest and gtest_main targets.
    add_subdirectory(libs/googletest EXCLUDE_FROM_ALL)
else()
    find_package(GTest REQUIRED)
endif()

file(GLOB_RECURSE MMPR_TEST_SRC_FILES CONFIGURE_DEPENDS src/**/*.cpp)
add_executable(mmpr_test ${MMPR_TEST_SRC_FILES})
target_link_libraries(mmpr_test
    PUBLIC
        mmpr::mmpr
        gtest_main
        gmock
)

add_test(NAME mmpr_test
    COMMAND mmpr_test
)
