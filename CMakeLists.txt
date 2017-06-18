cmake_minimum_required(VERSION 3.8)
project(uv_ssl_client)

set(CMAKE_CXX_STANDARD 11)

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

add_library(uv_ssl_client src/client.cpp)
target_include_directories(uv_ssl_client PUBLIC include)
target_link_libraries(uv_ssl_client uv_ssl_t ssl crypto)
depends_on_openssl(uv_ssl_client PRIVATE)

