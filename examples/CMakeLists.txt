add_executable(example-simple example-simple.cpp)
target_compile_features(example-simple PRIVATE cxx_std_11)
target_link_libraries(example-simple PRIVATE mmpr fmt::fmt)
