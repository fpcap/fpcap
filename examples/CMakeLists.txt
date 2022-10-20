add_executable(mmpr_example_modified_pcap_simple modified_pcap_simple.cpp)
target_link_libraries(mmpr_example_modified_pcap_simple PRIVATE mmpr)

if(MMPR_USE_ZSTD)
    add_executable(mmpr_example_pcap_decompression pcap_decompression.cpp)
    target_link_libraries(mmpr_example_pcap_decompression PRIVATE mmpr ZSTD::ZSTD)
endif()

add_executable(mmpr_example_pcapng_simple pcapng_simple.cpp)
target_link_libraries(mmpr_example_pcapng_simple PRIVATE mmpr)

add_executable(mmpr_example_pcapng_block_parser pcapng_block_parser.cpp)
target_link_libraries(mmpr_example_pcapng_block_parser PRIVATE mmpr)

if(MMPR_USE_ZSTD)
    add_executable(mmpr_example_pcapng_decompression pcapng_decompression.cpp)
    target_link_libraries(mmpr_example_pcapng_decompression PRIVATE mmpr ZSTD::ZSTD)
endif()

add_executable(mmpr_example_pcapng_metadata pcapng_metadata.cpp)
target_link_libraries(mmpr_example_pcapng_metadata PRIVATE mmpr)

add_executable(mmpr_example_pcap_simple_fread pcap_simple_fread.cpp)
target_link_libraries(mmpr_example_pcap_simple_fread PRIVATE mmpr)

add_executable(mmpr_example_pcap_simple_mm pcap_simple_mm.cpp)
target_link_libraries(mmpr_example_pcap_simple_mm PRIVATE mmpr)

add_executable(mmpr_example_pcap_writer pcap_writer.cpp)
target_link_libraries(mmpr_example_pcap_writer PRIVATE mmpr)

add_executable(mmpr_statistics_cli statistics_cli.cpp)
target_link_libraries(mmpr_statistics_cli PRIVATE mmpr)