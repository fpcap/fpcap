include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.17.0
)
FetchContent_MakeAvailable(googletest)

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
