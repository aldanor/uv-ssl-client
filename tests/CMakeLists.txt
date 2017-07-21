set(TESTNAME uv_ssl_client_tests)
add_executable(${TESTNAME} test_httpbin.cpp)
target_include_directories(${TESTNAME} PRIVATE catch/single_include)
target_link_libraries(${TESTNAME} uv_ssl_client)

