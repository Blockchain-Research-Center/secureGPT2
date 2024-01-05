cmake_minimum_required(VERSION 3.10)

project(PrivateGPT VERSION 1.0)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_BUILD_TYPE RelWithDebInfo)

find_package(SEAL 4.1)
find_package(cppzmq REQUIRED)

if(NOT cppzmq_FOUND)
    message(FATAL_ERROR "cppzmq: not found")
else()
    message(STATUS "cppzmq: found")
endif()

add_executable(
    main
    ${CMAKE_SOURCE_DIR}/src/main.cpp
    ${CMAKE_SOURCE_DIR}/src/gelu.cpp
    ${CMAKE_SOURCE_DIR}/src/layer_norm.cpp
    ${CMAKE_SOURCE_DIR}/src/ckks_evaluator.cpp
    ${CMAKE_SOURCE_DIR}/src/softmax.cpp
    ${CMAKE_SOURCE_DIR}/src/matrix_mul.cpp
)

add_executable(
    client
    ${CMAKE_SOURCE_DIR}/src/client.cpp
    ${CMAKE_SOURCE_DIR}/src/gelu.cpp
    ${CMAKE_SOURCE_DIR}/src/layer_norm.cpp
    ${CMAKE_SOURCE_DIR}/src/ckks_evaluator.cpp
    ${CMAKE_SOURCE_DIR}/src/softmax.cpp
    ${CMAKE_SOURCE_DIR}/src/matrix_mul.cpp
)

add_executable(
    server
    ${CMAKE_SOURCE_DIR}/src/server.cpp
    ${CMAKE_SOURCE_DIR}/src/gelu.cpp
    ${CMAKE_SOURCE_DIR}/src/layer_norm.cpp
    ${CMAKE_SOURCE_DIR}/src/ckks_evaluator.cpp
    ${CMAKE_SOURCE_DIR}/src/softmax.cpp
    ${CMAKE_SOURCE_DIR}/src/matrix_mul.cpp
)

target_link_libraries(client PRIVATE libzmq-static cppzmq-static SEAL::seal)
target_link_libraries(server PRIVATE libzmq-static cppzmq-static SEAL::seal)

target_link_libraries(main PRIVATE libzmq-static cppzmq-static SEAL::seal)

# add_subdirectory(src)