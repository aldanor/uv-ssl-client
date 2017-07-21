### uv-ssl-client

`uv-ssl-client` is a lightweight wrapper around `uv_ssl_t`, `uv_link_t`
and `http-parser` libraries, providing client functionality for raw SSL
connections and HTTPS.

A few notable details:

- Pull all submodules (`git submodule update --init --recursive`) before building.
- The client is using OpenSSL for SSL/TLS functionality. The root path to OpenSSL installation can be provided via `-DOPENSSL_ROOT_DIR=...`. On macOS, it is recommended to install `openssl` through Homebrew.
- OpenSSL context mode is `SSLv23` which supports both SSL and TLS.
- TCP keep-alive is enabled by default.
- The client supports SNI; `tlsext_host_name` is always set.

#### Example

```cpp
#include <iostream>
#include <string>

#include <uv.h>
#include <uv_ssl/client.h>
#include <uv_ssl/http.h>

int main() {
    uv_ssl::http_client client("example.org");
    auto loop = uv_loop_new();
    client.on_read([loop](uv_ssl::http_response r) {
        std::cout << std::string(r.buf, r.len) << std::endl;
        uv_stop(loop);
    });
    client.connect(loop);
    auto request =
        "GET / HTTP/1.1\r\n"
        "User-Agent: curl/7.51.0\r\n"
        "Host: example.org\r\n\r\n";
    client.write(request);
    uv_run(loop, UV_RUN_DEFAULT);
    return 0;
}
```
