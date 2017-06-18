#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <stdexcept>
#include <sstream>
#include <string>
#include <type_traits>

#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <uv.h>
#include <uv_link_t.h>
#include <uv_ssl_t.h>

#include <uv_ssl_client.h>

namespace uv_ssl {

static SSL_CTX* g_ssl_ctx = nullptr;

static const char* ssl_get_error() {
    unsigned long err = 0, e = 0;
    do {
        e = ERR_get_error();
        err = e != 0 ? e : err;
    } while (e != 0);
    return err != 0
           ? ERR_error_string(err, nullptr)
           : "<unknown SSL error>";
}

static SSL* new_ssl() {
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
        SSL_set_connect_state(ssl);
    } catch (...) {
        if (ssl != nullptr) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        throw;
    }
    return ssl;
}

enum class err_if { nonzero, negative };

template<typename E, typename F, typename... Args>
void try_call(const char *name, E&& e, err_if eif, F&& f, Args&&... args) {
    auto err = f(std::forward<Args>(args)...);
    bool fail =
        (eif == err_if::nonzero && err != 0) ||
        (eif == err_if::negative && err < 0);
    if (fail) {
        throw error(name, e(err));
    }
};

template<typename F, typename... Args>
void try_call_uv(const char *name, F&& f, Args&&... args) {
    try_call(name, uv_err_name, err_if::negative,
             std::forward<F>(f), std::forward<Args>(args)...);
};

template<typename F, typename... Args>
void try_call_uv_link(const char *name, void *link, F&& f, Args&&... args) {
    auto e = [link](int err) {
        return uv_link_strerror(static_cast<uv_link_t*>(link), err);
    };
    try_call(name, e, err_if::nonzero,
             std::forward<F>(f), std::forward<Args>(args)...);
};


static addrinfo* new_addrinfo(const char* hostname, uint16_t port) {
    std::ostringstream s_port;
    s_port << port;

    addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* addr;
    try_call("getaddrinfo", gai_strerror, err_if::nonzero,
             getaddrinfo, hostname, s_port.str().c_str(), &hints, &addr);

    return addr;
}

error::error(const char* msg)
    : std::runtime_error(msg)
{}

error::error(const char* func, const char* msg)
    : std::runtime_error(std::string(func) + "(): " + msg)
{}

void shutdown() {
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

struct client::impl {
    SSL *ssl = nullptr;
    struct addrinfo* addr = nullptr;
    uv_tcp_t tcp {};
    uv_link_source_t source {};
    uv_ssl_t* ssl_link = nullptr;
    uv_link_observer_t observer {};
    std::function<void(const char *, size_t)> on_read_cb =
        [](const char* buf, size_t len) {};

    impl(const char* hostname, uint16_t port) {
        ssl = new_ssl();
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

    void on_read(std::function<void(const char *, size_t)> callback) {
        on_read_cb = std::move(callback);
    }

    void connect(uv_loop_t* loop) {
        try_call_uv("uv_tcp_init",
                    uv_tcp_init, loop, &tcp);
        try_call_uv("uv_tcp_keepalive",
                    uv_tcp_keepalive, &tcp, 1, 180);
        try_call_uv("uv_tcp_nodelay",
                    uv_tcp_nodelay, &tcp, 1);

        for (auto ai = addr; ai != nullptr; ai = ai->ai_next) {
            try {
                uv_connect_t req {};
                try_call_uv("uv_tcp_connect",
                            uv_tcp_connect, &req, &tcp, ai->ai_addr, nullptr);
                break;
            } catch (...) {
                if (ai->ai_next == nullptr) {
                    throw;
                }
            }
        }

        int err = uv_link_source_init(&source, as_stream(&tcp));
        if (err != 0) {
            throw error("uv_link_source_init", uv_link_strerror(as_link(&source), err));
        }
        ssl_link = uv_ssl_create(loop, ssl, &err);
        if (err != 0) {
            throw error("uv_ssl_create", "failed to initialize SSL link");
        }

        err = uv_link_observer_init(&observer);
        if (err != 0) {
            throw error("uv_link_observer_init", uv_link_strerror(as_link(&observer), err));
        }
        observer.data = this;
        observer.observer_read_cb = [](uv_link_observer_t* obs, ssize_t len, const uv_buf_t* buf) {
            auto inst = reinterpret_cast<impl*>(obs->data);  // NOLINT
            if (len > 0) {
                inst->on_read_cb(buf->base, static_cast<size_t>(len));
            } else if (len < 0) {
                uv_link_close(as_link(obs), [](uv_link_t* /* link */) {});
            }
        };

        err = uv_link_chain(as_link(&source), as_link(ssl_link));
        if (err != 0) {
            throw error("uv_link_chain", uv_link_strerror(as_link(&source), err));
        }
        err = uv_link_chain(as_link(ssl_link), as_link(&observer));
        if (err != 0) {
            throw error("uv_link_chain", uv_link_strerror(as_link(ssl_link), err));
        }
        err = uv_link_read_start(as_link(&observer));
        if (err != 0) {
            throw error("uv_link_read_start", uv_link_strerror(as_link(&observer), err));
        }
    }
};

client::client(const char *hostname, uint16_t port)
    : impl_(new impl(hostname, port))
{}

void client::on_read(std::function<void(const char *, size_t)> callback) {
    impl_->on_read(std::move(callback));
}

void client::connect(uv_loop_t *loop) {
    impl_->connect(loop);
}

}  // namespace uv_ssl
