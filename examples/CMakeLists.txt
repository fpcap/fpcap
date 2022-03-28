add_executable(example-simple example-simple.cpp)
target_compile_features(example-simple PRIVATE cxx_std_11)
target_link_libraries(example-simple PRIVATE mmpr fmt::fmt)

add_executable(example-block example-block.cpp)
target_compile_features(example-block PRIVATE cxx_std_11)
target_link_libraries(example-block PRIVATE mmpr fmt::fmt)