#ifndef UV_SSL_CLIENT_H_
#define UV_SSL_CLIENT_H_

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <stdexcept>

#include <uv.h>

namespace uv_ssl {

struct error : public std::runtime_error {
    explicit error(const char* msg);
    error(const char* func, const char *msg);
};

void ssl_shutdown();

struct client {
    using read_cb = std::function<void(const char *, size_t)>;
    
    client(const char* hostname, uint16_t port);

    explicit client(const char* hostname)
        : client(hostname, 443)
    {}

    ~client() noexcept;

    void on_read(read_cb callback);

    void connect(uv_loop_t* loop);

    void connect() {
        connect(uv_default_loop());
    }

private:
    struct impl;
    std::unique_ptr<impl> impl_;
};

}  // namespace uv_ssl

#endif  // UV_SSL_CLIENT_H_
