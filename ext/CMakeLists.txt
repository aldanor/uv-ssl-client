find_library(LIB_UV uv)
if(NOT LIB_UV)
    message(FATAL "libuv not found")
else()
    message(STATUS "Found libuv: ${LIB_UV}")
endif()

add_library(ringbuffer
    ringbuffer/ringbuffer.c)
target_include_directories(ringbuffer PUBLIC ringbuffer)

add_library(uv_link_t
    uv_link_t/src/uv_link_t.c
    uv_link_t/src/uv_link_observer_t.c
    uv_link_t/src/uv_link_source_t.c
    uv_link_t/src/defaults.c)
target_include_directories(uv_link_t PUBLIC uv_link_t/include)
target_include_directories(uv_link_t PRIVATE uv_link_t)
target_link_libraries(uv_link_t ${LIB_UV} ringbuffer)

add_library(uv_ssl_t
    uv_ssl_t/src/uv_ssl_t.c
    uv_ssl_t/src/bio.c
    uv_ssl_t/src/link_methods.c)
target_include_directories(uv_ssl_t PUBLIC uv_ssl_t/include)
target_include_directories(uv_ssl_t PRIVATE uv_ssl_t)
target_link_libraries(uv_ssl_t uv_link_t ssl crypto)
depends_on_openssl(uv_ssl_t PRIVATE)
