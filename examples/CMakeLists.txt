add_executable(mmpr-example-simple example-simple.cpp)
target_link_libraries(mmpr-example-simple PRIVATE mmpr fmt::fmt)

add_executable(mmpr-example-block example-block.cpp)
target_link_libraries(mmpr-example-block PRIVATE mmpr fmt::fmt)

add_executable(mmpr-example-decompression example-decompression.cpp)
target_link_libraries(mmpr-example-decompression PRIVATE mmpr fmt::fmt ZSTD::ZSTD)

add_executable(mmpr-example-metadata example-metadata.cpp)
target_link_libraries(mmpr-example-metadata PRIVATE mmpr fmt::fmt)