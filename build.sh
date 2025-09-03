#!/bin/bash

cmake -S . -B build/release -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build/release --target data

# cmake -S . -B build/examples -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release
# for target in ex01; do
#     cmake --build build/examples --target "$target"
# done

cmake -S . -B build/tests -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release
targets=(
    test_yenc
    test_wirehair
    test_logger
    test_nntp
)
for target in "${targets[@]}"; do
    cmake --build build/tests --target "$target"
done

# Build tests in Debug
# cmake -S . -B build/tests -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Debug
# cmake --build build/tests --target test_music