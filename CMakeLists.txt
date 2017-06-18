cmake_minimum_required(VERSION 3.8)
project(uv_ssl_client)

set(CMAKE_CXX_STANDARD 11)

option(UV_SSL_HTTP "Build with HTTP response parsing support." ON)

function(depends_on_openssl TARGET VISIBILITY)
    if(DEFINED OPENSSL_INCLUDE_DIR)
        target_include_directories(${TARGET} ${VISIBILITY} SYSTEM "${OPENSSL_INCLUDE_DIR}")
    elseif(DEFINED OPENSSL_ROOT_DIR)
        target_include_directories(${TARGET} ${VISIBILITY} SYSTEM "${OPENSSL_ROOT_DIR}/include")
    endif()

    if(DEFINED OPENSSL_LIBRARIES)
        link_directories("${OPENSSL_LIBRARIES}")
    elseif(DEFINED OPENSSL_ROOT_DIR)
        link_directories("${OPENSSL_ROOT_DIR}/lib")
    endif()
endfunction()

add_subdirectory(ext)

set(UV_SSL_SOURCES src/client.cpp)
set(UV_SSL_DEPS uv_ssl_t ssl crypto)
if(UV_SSL_HTTP)
    list(APPEND UV_SSL_DEPS http-parser)
    list(APPEND UV_SSL_SOURCES src/http.cpp)
endif()
add_library(uv_ssl_client ${UV_SSL_SOURCES})
target_include_directories(uv_ssl_client PUBLIC include)
target_link_libraries(uv_ssl_client ${UV_SSL_DEPS})
depends_on_openssl(uv_ssl_client PRIVATE)

