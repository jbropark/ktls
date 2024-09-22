#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <linux/tls.h>
#include <time.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define MIN(x, y) ((x) < (y) ? (x) : (y))

static const int SERVER_PORT = 4433;
static const int BUFFER_SIZE = 8931;

static volatile bool server_running = true;

void measure_speed(size_t bytes_sent, struct timespec start, struct timespec end)
{
    double elapsed_time_sec, elapsed_time_ms, elapsed_time_us;
    double speed_mbps;

    elapsed_time_sec = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    elapsed_time_ms = elapsed_time_sec * 1000;
    elapsed_time_us = elapsed_time_sec * 1e6;

    speed_mbps = ((bytes_sent * 8) / 1000000.0) / elapsed_time_sec;

    printf("Total data sent: %ld bytes\n", bytes_sent);
    // printf("Elapsed time: %.6f seconds\n", elapsed_time_sec);
    printf("Elapsed time: %.6f milliseconds\n", elapsed_time_ms);
    // printf("Elapsed time: %.6f microseconds\n", elapsed_time_us);
    // printf("Speed: %.6f Mbps\n", speed_mbps);
}

void enable_ktls(SSL *ssl, int socket)
{
    SSL_SESSION *session = SSL_get_session(ssl);

    int tls_version = SSL_SESSION_get_protocol_version(session);
    const SSL_CIPHER *cipher = SSL_SESSION_get0_cipher(session);
    const char *cipher_name = SSL_CIPHER_get_name(cipher);
    int cipher_id = SSL_CIPHER_get_id(cipher);

    // printf("TLS version: %d\n", tls_version); 771 = TLS_1_2
    // printf("Cipher id: %d\n", cipher_id); 50380848 = ECDHE-RSA-AES256-GCM-SHA384
    struct tls12_crypto_info_aes_gcm_256 crypto_info;
    memset(&crypto_info, 0, sizeof(crypto_info));

    crypto_info.info.version = tls_version;
    crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;

    unsigned char key[32];
    unsigned char iv[12];
    unsigned char rec_seq[80] = {0};

    memcpy(crypto_info.key, key, sizeof(crypto_info.key));
    memcpy(crypto_info.iv, iv, sizeof(crypto_info.iv));
    memcpy(crypto_info.rec_seq, rec_seq, sizeof(crypto_info.rec_seq));

    if (setsockopt(socket, SOL_TCP, TCP_ULP, "tls", sizeof("tls")) == 0)
    {
        perror("TCP ULP error");
    }
    else
    {
        printf("TCP ULP set success\n");
    }

    if (setsockopt(socket, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info)) == 0)
    {
        perror("TLS_TX set error");
    }
    else
    {
        printf("TLS_TX set success\n");
    }

    int sndbuf;
    socklen_t optlen = sizeof(sndbuf);
    if (getsockopt(socket, SOL_SOCKET, SO_SNDBUF, &sndbuf, &optlen) < 0)
    {
        perror("getsockopt failed");
        close(socket);
    }
    printf("Actual send buffer size: %d bytes\n", sndbuf);

    if (setsockopt(socket, SOL_TLS, TLS_RX, &crypto_info, sizeof(crypto_info)) == 0)
    {
        perror("TLS_RX set error");
    }
    else
    {
        printf("TLS_RX set success\n");
    }

    int option = 1;
    if (setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, &option, sizeof(int)) < 0)
    {
        perror("setsockopt(TCP_NODELAY) failed");
    }
    else
    {
        printf("TCP_NODELAY set success\n");
    }
}

int create_socket()
{
    int s;
    struct sockaddr_in addr;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(1);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(1);
    }

    if (listen(s, 10000) < 0) {
        perror("Unable to listen");
        exit(1);
    }

    return s;
}

void SSL_CTX_keylog_cb(const SSL *ssl, const char *line) {
    FILE *log_file = fopen(getenv("SSLKEYLOGFILE"), "a");
    if (log_file != NULL) {
        fprintf(log_file, "%s\n", line);
        fclose(log_file);
    } else {
        perror("Unable to open key log file");
    }
}

static SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    SSL_CTX_set_keylog_callback(ctx, SSL_CTX_keylog_cb);

    return ctx;
}

static void configure_server_context(SSL_CTX *ctx)
{
    if (SSL_CTX_use_certificate_chain_file(ctx, "./server-cert.pem") <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "./server-key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (!SSL_CTX_load_verify_locations(ctx, "./ca-cert.pem", NULL)) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 1);
}

void handle_tcp(SSL_CTX *ssl_ctx, int client_skt, size_t n_packets, char *buffer)
{
    struct timespec start, end;

    ssize_t bytes_sent = 0;

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (size_t i = 0; i < n_packets; i++) {
        ssize_t sent = send(client_skt, buffer, BUFFER_SIZE, 0);

        if (sent <= 0) {
            perror("write failed");
            break;
        }

        bytes_sent += sent;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    if (bytes_sent > 0) {
        measure_speed(bytes_sent, start, end);
    }

    close(client_skt);
}

void handle_tls(SSL_CTX *ssl_ctx, int client_skt, size_t n_packets, char *buffer)
{
    SSL *ssl = SSL_new(ssl_ctx);
    struct timespec start, end;

    if (SSL_set_fd(ssl, client_skt) == 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    printf("Client SSL connection accepted\n");
    int version = SSL_version(ssl);
    const char *version_str = SSL_get_version(ssl);

    printf("TLS Version: %s\n", version_str);

    const char *cipher_suite = SSL_get_cipher(ssl);
    printf("Cipher Suite: %s\n", cipher_suite);

    enable_ktls(ssl, client_skt);
    ssize_t bytes_sent = 0;

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (size_t i = 0; i < n_packets; i++) {
        ssize_t sent = SSL_write(ssl, buffer, BUFFER_SIZE);

        if (sent <= 0) {
            perror("write failed");
            break;
        }

        bytes_sent += sent;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    if (bytes_sent > 0) {
        measure_speed(bytes_sent, start, end);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_skt);
}

int server_skt = -1;

void quit_server(int sig)
{
    server_running = false;
    close(server_skt);
    server_skt = -1;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <n_packets>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    size_t n_packets = strtoull(argv[1], NULL, 10);

    int client_skt = -1;
    struct sockaddr_in addr;
    unsigned int addr_len = sizeof(addr);

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, quit_server);

    SSL_CTX *ssl_ctx = NULL;

    char *buffer = (char *)calloc(sizeof(char), BUFFER_SIZE);
    if (buffer == NULL) {
        perror("Memory allocation error");
        exit(EXIT_FAILURE);
    }

    printf("Server start running\n\n");

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ssl_ctx = create_context();
    SSL_CTX_set_options(ssl_ctx, SSL_OP_ENABLE_KTLS);
    SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_2_VERSION);
    configure_server_context(ssl_ctx);

    server_skt = create_socket();

    while (server_running) {
        client_skt = accept(server_skt, (struct sockaddr *)&addr, &addr_len);
        if (client_skt < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        printf("Client TCP connection accepted\n");
        printf("Client IP: %s\n", inet_ntoa(addr.sin_addr));
        pid_t pid = fork();

        if (pid < 0) {
            perror("Fork failed");
            close(client_skt);
            continue;
        }

        // Close the client socket in the server process
        if (pid != 0) {
            close(client_skt);
            continue;
        }

        // Close the server socket in the child process
        if (server_skt != -1) {
            close(server_skt);
        }

        handle_tcp(ssl_ctx, client_skt, n_packets, buffer);

        exit(0); // Child process exits
    }

    printf("Server exiting...\n");
    SSL_CTX_free(ssl_ctx);
    free(buffer);

    return 0;
}
