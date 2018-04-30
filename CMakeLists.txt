cmake_minimum_required(VERSION 3.10)
project(switch_decrypt)

set(CMAKE_CXX_STANDARD 11)

find_package(OpenSSL REQUIRED)

add_executable(switch_decrypt main.cpp xts_crypto.cpp xts_crypto.h hex_string.cpp hex_string.h)
target_include_directories(switch_decrypt PUBLIC ${OPENSSL_LIBRARIES})
target_link_libraries(switch_decrypt ${OPENSSL_LIBRARIES})