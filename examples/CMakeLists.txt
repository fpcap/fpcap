add_executable(example-simple example-simple.cpp)
target_link_libraries(example-simple PRIVATE mmpr fmt::fmt)

add_executable(example-block example-block.cpp)
target_link_libraries(example-block PRIVATE mmpr fmt::fmt)

add_executable(example-decompression example-decompression.cpp)
target_link_libraries(example-decompression PRIVATE mmpr fmt::fmt ZSTD::ZSTD)