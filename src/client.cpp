#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <sstream>
#include <string>

#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <uv.h>
#include <uv_link_t.h>
#include <uv_ssl_t.h>

#include <uv_ssl/client.h>

namespace uv_ssl {

static SSL_CTX* g_ssl_ctx = nullptr;

static const char* ssl_get_error() {
    uint64_t err = 0, e = 0;
    do {
        e = ERR_get_error();
        err = e != 0 ? e : err;
    } while (e != 0);
    return err != 0
           ? ERR_error_string(err, nullptr)
           : "<unknown SSL error>";
}

static void ssl_check_error() {
    if (ERR_peek_error() != 0) {
        throw error(ssl_get_error());
    }
}

static SSL* new_ssl(const char* hostname) {
    SSL* ssl = nullptr;
    try {
        if (g_ssl_ctx == nullptr) {
            SSL_library_init();
            OpenSSL_add_all_algorithms();
            OpenSSL_add_all_digests();
            SSL_load_error_strings();
            ERR_load_crypto_strings();
            g_ssl_ctx = SSL_CTX_new(SSLv23_client_method());
            if (g_ssl_ctx == nullptr) {
                throw error("SSL_CTX_new", ssl_get_error());
            }
        }
        ssl = SSL_new(g_ssl_ctx);
        if (ssl == nullptr) {
            throw error("SSL_new", ssl_get_error());
        }
        SSL_set_tlsext_host_name(ssl, hostname);
        SSL_set_connect_state(ssl);
        ssl_check_error();
    } catch (...) {
        if (ssl != nullptr) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        throw;
    }
    return ssl;
}

static addrinfo* new_addrinfo(const char* hostname, uint16_t port) {
    std::ostringstream s_port;
    s_port << port;

    addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* addr;
    int err = getaddrinfo(hostname, s_port.str().c_str(), &hints, &addr);
    if (err != 0) {
        throw error("getaddrinfo", gai_strerror(err));
    }

    return addr;
}

error::error(const char* msg)
    : std::runtime_error(msg)
{}

error::error(const char* func, const char* msg)
    : std::runtime_error(std::string(func) + "(): " + msg)
{}

void ssl_shutdown() {
    if (g_ssl_ctx != nullptr) {
        SSL_CTX_free(g_ssl_ctx);
    }
}

static uv_stream_t* as_stream(void *v) {
    return reinterpret_cast<uv_stream_t *>(v);  // NOLINT
}

static uv_link_t* as_link(void *v) {
    return reinterpret_cast<uv_link_t*>(v);  // NOLINT
}

struct write_closure {
    client::error_cb on_error;
    uv_link_observer_t* observer;

    explicit write_closure(uv_link_observer_t* obs, client::error_cb on_error)
        : on_error(std::move(on_error))
        , observer(obs)
    {}

    static bool check_err(write_closure* closure, int err) {
        if (closure != nullptr && err != 0) {
            auto on_error = closure->on_error;
            auto error_str = uv_link_strerror(as_link(closure->observer), err);
            delete closure;
            on_error(error_str);
            return false;
        }
        return true;
    }
};

struct client::impl {
    SSL *ssl = nullptr;
    struct addrinfo* addr = nullptr;
    uv_tcp_t tcp {};
    uv_connect_t req {};
    uv_link_source_t source {};
    uv_ssl_t* ssl_link = nullptr;
    uv_link_observer_t observer {};
    read_cb on_read_cb = [](const char* /* buf */, size_t /* len */) {};

    impl(const char* hostname, uint16_t port) {
        ssl = new_ssl(hostname);
        addr = new_addrinfo(hostname, port);
    }

    ~impl() noexcept {
        if (ssl != nullptr) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        if (addr != nullptr) {
            freeaddrinfo(addr);
        }
        if (ssl_link != nullptr) {
            std::free(ssl_link);
        }
    }

    impl(impl&&) noexcept = default;
    impl& operator=(impl&&) noexcept = default;

    impl(const impl&) = delete;
    impl& operator=(const impl&) = delete;

    void on_read(read_cb callback) {
        on_read_cb = std::move(callback);
    }

    void connect(uv_loop_t* loop) {
        int err = 0;

        if ((err = uv_tcp_init(loop, &tcp)) < 0) {
            throw error("uv_tcp_init", uv_err_name(err));
        } else if ((err = uv_tcp_keepalive(&tcp, 1, 180)) < 0) {
            throw error("uv_tcp_keepalive", uv_err_name(err));
        } else if ((err = uv_tcp_nodelay(&tcp, 1)) < 0) {
            throw error("uv_tcp_nodelay", uv_err_name(err));
        }

        for (auto ai = addr; ai != nullptr; ai = ai->ai_next) {
            if ((err = uv_tcp_connect(&req, &tcp, ai->ai_addr, nullptr)) >= 0) {
                break;
            }
            if (ai->ai_next == nullptr) {
                throw error("uv_tcp_connect", uv_err_name(err));
            }
        }

        if ((err = uv_link_source_init(&source, as_stream(&tcp))) != 0) {
            throw error("uv_link_source_init", uv_link_strerror(as_link(&source), err));
        }
        ssl_link = uv_ssl_create(loop, ssl, &err);
        if (ssl_link == nullptr || err != 0) {
            throw error("uv_ssl_create", "failed to initialize SSL link");
        }

        if ((err = uv_link_observer_init(&observer)) != 0) {
            throw error("uv_link_observer_init", uv_link_strerror(as_link(&observer), err));
        }
        observer.data = this;
        observer.observer_read_cb = [](uv_link_observer_t* obs, ssize_t len, const uv_buf_t* buf) {
            auto inst = reinterpret_cast<impl*>(obs->data);  // NOLINT
            if (len > 0) {
                inst->on_read_cb(buf->base, static_cast<size_t>(len));
            } else if (len < 0) {
                uv_link_close(as_link(obs), [](uv_link_t* /* link */) {});
                inst->ssl_link = nullptr;
                ssl_check_error();
            }
        };

        if ((err = uv_link_chain(as_link(&source), as_link(ssl_link))) != 0) {
            throw error("uv_link_chain", uv_link_strerror(as_link(&source), err));
        } else if ((err = uv_link_chain(as_link(ssl_link), as_link(&observer))) != 0) {
            throw error("uv_link_chain", uv_link_strerror(as_link(ssl_link), err));
        } else if ((err = uv_link_read_start(as_link(&observer))) != 0) {
            throw error("uv_link_read_start", uv_link_strerror(as_link(&observer), err));
        }

        ssl_check_error();
    }

    void write(const char* data, size_t len) {
        uv_buf_t buf = uv_buf_init(const_cast<char *>(data),  // NOLINT
                                   static_cast<unsigned int>(len));
        uv_link_write(
            as_link(&observer), &buf, 1, nullptr,
            [](uv_link_t* /* link */, int /* status */, void* /* arg */) {},
            nullptr
        );
    }

    void write(const char* data, size_t len, error_cb on_error) {
        uv_buf_t buf = uv_buf_init(const_cast<char *>(data),  // NOLINT
                                   static_cast<unsigned int>(len));
        auto* closure = new write_closure(&observer, std::move(on_error));
        int err = uv_link_write(
            as_link(&observer), &buf, 1, nullptr,
            [](uv_link_t* /* link */, int status, void* arg) {
                auto* wc = static_cast<write_closure *>(arg);
                if (!write_closure::check_err(wc, status)) {
                    delete wc;
                }
            },
            closure
        );
        write_closure::check_err(closure, err);
    }
};

client::client(const char *hostname, uint16_t port)
    : impl_(new impl(hostname, port))
{}

void client::on_read(read_cb callback) {
    impl_->on_read(std::move(callback));
}

void client::connect(uv_loop_t *loop) {
    impl_->connect(loop != nullptr ? loop : uv_default_loop());
}

client::~client() noexcept = default;

void client::write(const char *data, size_t len) {
    impl_->write(data, len);
}

void client::write(const char *data, size_t len, error_cb on_error) {
    impl_->write(data, len, std::move(on_error));
}

void client::write(const char *str) {
    write(str, std::strlen(str));
}

void client::write(const char *str, error_cb on_error) {
    write(str, std::strlen(str), std::move(on_error));
}

void client::write(const std::string &str) {
    write(str.data(), str.size());
}

void client::write(const std::string &str, error_cb on_error) {
    write(str.data(), str.size(), std::move(on_error));
}

}  // namespace uv_ssl
