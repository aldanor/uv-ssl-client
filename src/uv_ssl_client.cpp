#include <cstdint>
#include <stdexcept>
#include <string>

#include <openssl/ssl.h>
#include <openssl/err.h>

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
    SSL *ssl;

    explicit impl()
        : ssl(new_ssl())
    {}

    ~impl() noexcept {
        if (ssl != nullptr) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
    }

    impl(impl&&) noexcept = default;
    impl& operator=(impl&&) noexcept = default;

    impl(const impl&) = delete;
    impl& operator=(const impl&) = delete;
};

client::client(const char *hostname, uint16_t port)
    : impl_(new impl())
{}

}  // namespace uvsslc

