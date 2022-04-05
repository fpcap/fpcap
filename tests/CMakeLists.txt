# see /opt/local/share/cmake-3.16/Modules/FindGTest.cmake
find_package(GTest QUIET)

if(NOT GTEST_FOUND)
    # Add googletest directly to our build. This defines
    # the gtest and gtest_main targets.
    add_subdirectory(libs/googletest EXCLUDE_FROM_ALL)
endif()

# Now simply link against gtest as needed. Eg
add_executable(mmpr_test
    src/pcap/testMMPcapReader.cpp
    src/pcapng/testMMPcapNgReader.cpp
    src/pcapng/testZstdPcapNgReader.cpp
    src/main.cpp
)
target_compile_features(mmpr_test PRIVATE cxx_std_11)
target_link_libraries(mmpr_test gtest_main mmpr::mmpr)

add_test(NAME mmpr_test
    COMMAND mmpr_test
)
