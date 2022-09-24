if(CMAKE_PROJECT_NAME STREQUAL "mmpr")
    # Add googletest directly to our build. This defines
    # the gtest and gtest_main targets.
    add_subdirectory(libs/googletest EXCLUDE_FROM_ALL)
else()
    find_package(GTest REQUIRED)
endif()

# Now simply link against gtest as needed. Eg
add_executable(mmpr_test
    src/pcap/testFReadPcapReader.cpp
    src/pcap/testMMPcapReader.cpp
    src/pcap/testStreamPcapReader.cpp
    src/pcapng/testFReadPcapNgReader.cpp
    src/pcapng/testMMPcapNgReader.cpp
    src/pcapng/testTraceInterfaces.cpp
    src/pcapng/testZstdPcapNgReader.cpp
    src/main.cpp
    src/testFileReader.cpp
)
target_compile_features(mmpr_test PRIVATE cxx_std_11)
target_link_libraries(mmpr_test gtest_main mmpr::mmpr)

add_test(NAME mmpr_test
    COMMAND mmpr_test
)
