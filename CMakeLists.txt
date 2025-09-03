cmake_minimum_required(VERSION 3.50)
project(data)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)

# Set default build type to Release if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Set build flags for different build types
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -march=native")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG -march=native")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -march=native")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -march=native")

find_package(PkgConfig REQUIRED)
set(PKG_LIST
    apr-1
    apr-util-1
    libssl
    libcrypto
)
foreach(PKG ${PKG_LIST})
    pkg_check_modules(${PKG} REQUIRED ${PKG})
    list(APPEND COMMON_INCLUDE_DIRS ${${PKG}_INCLUDE_DIRS})
    list(APPEND COMMON_LINK_DIRS    ${${PKG}_LIBRARY_DIRS})
    list(APPEND COMMON_LINK_LIBS    ${${PKG}_LIBRARIES})
endforeach()
list(APPEND COMMON_INCLUDE_DIRS include)
list(APPEND COMMON_INCLUDE_DIRS include/wirehair)
list(APPEND COMMON_INCLUDE_DIRS include/unity)

add_executable(data
    src/main.c
    src/wirehair/WirehairCodec.cpp
    src/wirehair/WirehairTools.cpp
    src/wirehair/gf256.cpp
    src/wirehair/wirehair.cpp
    src/yenc.c
    src/apr_logger.c
)
target_include_directories(data PRIVATE ${COMMON_INCLUDE_DIRS})
target_link_directories(data PRIVATE ${COMMON_LINK_DIRS})
target_link_libraries(data PRIVATE ${COMMON_LINK_LIBS})

add_executable(test_yenc
    tests/test_yenc.c
    src/yenc.c
    src/unity/unity.c
)
add_executable(test_wirehair
    tests/test_wirehair.c
    src/unity/unity.c
    src/wirehair/WirehairCodec.cpp
    src/wirehair/WirehairTools.cpp
    src/wirehair/gf256.cpp
    src/wirehair/wirehair.cpp
)
add_executable(test_logger
    tests/test_logger.c
    src/apr_logger.c
)
set(TEST_LIST
    test_yenc
    test_wirehair
    test_logger
)
foreach(TEST ${TEST_LIST})
    target_include_directories(${TEST} PRIVATE ${COMMON_INCLUDE_DIRS})
    target_link_directories(${TEST} PRIVATE ${COMMON_LINK_DIRS})
    target_link_libraries(${TEST} PRIVATE ${COMMON_LINK_LIBS})
endforeach()
