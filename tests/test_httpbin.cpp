#define CATCH_CONFIG_MAIN
#include <catch.hpp>

#include <algorithm>
#include <string>

#include <uv_ssl/client.h>
#include <uv_ssl/http.h>

static bool ends_with(const std::string& s, const std::string& e) {
    if (e.size() > s.size()) {
        return false;
    }
    return std::equal(e.rbegin(), e.rend(), s.rbegin());
}

static uv_ssl::http_response get(const std::string& query) {
    uv_ssl::http_client client("httpbin.org");
    auto loop = uv_loop_new();
    uv_ssl::http_response response {};
    client.on_read([loop, &response](uv_ssl::http_response r) {
        response = r;
        uv_stop(loop);
    });
    client.connect(loop);
    auto request =
        "GET " + query + " HTTP/1.1\r\n"
        "User-Agent: curl/7.51.0\r\n"
        "Host: httpbin.org\r\n"
        "Accept: */*\r\n\r\n";
    client.write(request, [](const char *err) { throw std::logic_error(err); });
    uv_run(loop, UV_RUN_DEFAULT);
    return response;
}

TEST_CASE("smoke") {
    auto r = get("/xml");
    REQUIRE(ends_with(std::string(r.buf, r.len), "</slideshow>"));
}
