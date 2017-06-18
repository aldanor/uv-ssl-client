#include <cstdint>
#include <stdexcept>
#include <sstream>
#include <type_traits>

#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <uv.h>

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

struct client::impl {
    SSL *ssl = nullptr;
    struct addrinfo* addr = nullptr;
    uv_tcp_t handle {};

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
    }

    impl(impl&&) noexcept = default;
    impl& operator=(impl&&) noexcept = default;

    impl(const impl&) = delete;
    impl& operator=(const impl&) = delete;

    void connect(uv_loop_t* loop) {
        try_call_uv("uv_tcp_init",
                    uv_tcp_init, loop, &handle);
        try_call_uv("uv_tcp_keepalive",
                    uv_tcp_keepalive, &handle, 1, 180);
        try_call_uv("uv_tcp_nodelay",
                    uv_tcp_nodelay, &handle, 1);

        for (auto ai = addr; ai != nullptr; ai = ai->ai_next) {
            try {
                uv_connect_t request {};
                try_call_uv("uv_tcp_connect",
                            uv_tcp_connect, &request, &handle, ai->ai_addr, nullptr);
                break;
            } catch (...) {
                if (ai->ai_next == nullptr) {
                    throw;
                }
            }
        }
    }
};

client::client(const char *hostname, uint16_t port)
    : impl_(new impl(hostname, port))
{}

void client::connect(uv_loop_t *loop) {
    impl_->connect(loop);
}

}  // namespace uv_ssl

