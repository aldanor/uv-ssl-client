#ifndef UV_SSL_HTTP_H_
#define UV_SSL_HTTP_H_

#include <cstddef>
#include <functional>
#include <memory>

#include <uv_ssl/client.h>

namespace uv_ssl {

struct http_response {
    int status;
    const char* buf;
    size_t len;

    http_response(int status, const char *buf, size_t len)
        : status(status)
        , buf(buf)
        , len(len)
    {}

    bool ok() const {
        return status == 200;
    }
};

struct http_client : public client {
    using read_cb = std::function<void(http_response)>;

    http_client(const char* hostname, uint16_t port);

    explicit http_client(const char* hostname)
        : http_client(hostname, 443)
    {}

    void on_read(read_cb callback);

    ~http_client() noexcept;

private:
    struct impl;
    std::unique_ptr<impl> impl_;
};

}  // namespace uv_ssl

#endif  // UV_SSL_HTTP_H_
