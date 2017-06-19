#include <http_parser.h>

#include <uv_ssl/http.h>

namespace uv_ssl {

struct http_client::impl {
    http_parser_settings settings {};
    http_parser parser {};
    read_cb on_read_cb = [](http_response /* response */) {};
    std::string buf {};

    impl() {
        http_parser_init(&parser, HTTP_RESPONSE);
        parser.data = this;

        http_parser_settings_init(&settings);
        settings.on_message_begin = [](http_parser* p) {
            auto* inst = static_cast<impl *>(p->data);
            inst->buf.clear();
            return 0;
        };
        settings.on_body = [](http_parser* p, const char* buf, size_t len) {
            auto* inst = static_cast<impl *>(p->data);
            inst->buf.append(buf, len);
            return 0;
        };
        settings.on_message_complete = [](http_parser* p) {
            auto* inst = static_cast<impl *>(p->data);
            inst->on_read_cb({static_cast<int>(p->status_code),
                              inst->buf.data(), inst->buf.size()});
            return 0;
        };
    }

    void feed(const char* buf, size_t len) {
        http_parser_execute(&parser, &settings, buf, len);
    }

    void on_read(read_cb callback) {
        on_read_cb = std::move(callback);
    }
};

void http_client::on_read(read_cb callback) {
    impl_->on_read(std::move(callback));
}

http_client::http_client(const char *hostname, uint16_t port)
    : client(hostname, port)
    , impl_(new impl())
{
    client::on_read([this](const char* buf, size_t len) {
        this->impl_->feed(buf, len);
    });
}

http_client::~http_client() noexcept = default;

}  // namespace uv_ssl

