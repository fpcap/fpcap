if(CMAKE_PROJECT_NAME STREQUAL "mmpr")
    # Add googletest directly to our build. This defines
    # the gtest and gtest_main targets.
    add_subdirectory(libs/googletest EXCLUDE_FROM_ALL)
else()
    find_package(GTest REQUIRED)
endif()

# Now simply link against gtest as needed. Eg
add_executable(mmpr_test
    src/modified_pcap/testFReadModifiedPcapReader.cpp
    src/modified_pcap/testMMModifiedPcapReader.cpp
    src/modified_pcap/testZstdModifiedPcapReader.cpp
    src/pcap/testFReadPcapReader.cpp
    src/pcap/testMMPcapReader.cpp
    src/pcap/testZstdPcapReader.cpp
    src/pcapng/testFReadPcapNgReader.cpp
    src/pcapng/testMMPcapNgReader.cpp
    src/pcapng/testTraceInterfaces.cpp
    src/pcapng/testZstdPcapNgReader.cpp
    src/main.cpp
    src/testFileReader.cpp
)
target_link_libraries(mmpr_test
    PUBLIC
        mmpr::mmpr
        gtest_main
)

add_test(NAME mmpr_test
    COMMAND mmpr_test
)
