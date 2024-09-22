#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/sendfile.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <linux/tls.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <time.h>
#include <pthread.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_EVENTS 1024

static const int SERVER_PORT = 4433;
static const size_t BUFFER_SIZE = 1 * 1024 * 1024;

void measure_speed(size_t bytes_sent, struct timespec start, struct timespec end) {
    double elapsed_time_sec, elapsed_time_ms, elapsed_time_us;
    double speed_mbps;

    elapsed_time_sec = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    elapsed_time_ms = elapsed_time_sec * 1000;
    elapsed_time_us = elapsed_time_sec * 1e6;

    speed_mbps = ((bytes_sent * 8) / 1000000.0) / elapsed_time_sec;

    // printf("Total data sent: %zd bytes\n", bytes_sent);
    // printf("Elapsed time: %.6f seconds\n", elapsed_time_sec);
    printf("Elapsed time: %.6f milliseconds\n", elapsed_time_ms);
    // printf("Elapsed time: %.6f microseconds\n", elapsed_time_us);
    // printf("Speed: %.6f Mbps\n", speed_mbps);
}

int create_socket() {
    int s;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
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

SSL_CTX* create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        perror("Unable to create SSL context");
        exit(1);
    }

    SSL_CTX_set_keylog_callback(ctx, SSL_CTX_keylog_cb);
    return ctx;
}

static void configure_client_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_chain_file(ctx, "./client-cert.pem") <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "./client-key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (!SSL_CTX_load_verify_locations(ctx, "./ca-cert.pem", NULL)) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
}

void fix_affinity(int cpu)
{
    cpu_set_t cpuset;
    pthread_t thread;

    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);

    thread = pthread_self();

    if (pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset)) {
        perror("affinity");
    }
}

size_t validate_online(char *buf)
{
    size_t count = 0;
    for (int i = 0; i < BUFFER_SIZE; i++) {
        if (buf[i] != 0) {
            count += 1;
        }
    }
    return count;
}

struct context {
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    int sockfd;
    char *buffer;
    size_t total;
};

int context_init(struct context *ctx)
{
    ctx->ssl_ctx = NULL;
    ctx->ssl = NULL;
    ctx->sockfd = -1;
    ctx->total = 0;
    ctx->buffer = malloc(BUFFER_SIZE);
    if (ctx ->buffer == NULL) {
        return -1;
    }
    return 0;
}

int context_handshake(struct context *ctx, char *server_ip)
{
    struct sockaddr_in addr;

    ctx->sockfd = create_socket();

    addr.sin_family = AF_INET;
    inet_pton(AF_INET, server_ip, &addr.sin_addr.s_addr);
    addr.sin_port = htons(SERVER_PORT);

    if (connect(ctx->sockfd, (struct sockaddr*) &addr, sizeof(addr)) != 0) {
        perror("Unable to TCP connect to server");
        return -1;
    }

    printf("TCP connection to server successful\n");

    ctx->ssl_ctx = create_context();
    configure_client_context(ctx->ssl_ctx);
    SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_ENABLE_KTLS);

    ctx->ssl = SSL_new(ctx->ssl_ctx);
    if (SSL_set_fd(ctx->ssl, ctx->sockfd) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    SSL_set_tlsext_host_name(ctx->ssl, server_ip);
    if (!SSL_set1_host(ctx->ssl, server_ip)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (SSL_connect(ctx->ssl) != 1) {
        printf("SSL connection to server failed\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    printf("SSL connection to server successful\n\n");
    return 0;
}

int context_recv(struct context *ctx)
{
    ssize_t bytes_received = SSL_read(ctx->ssl, ctx->buffer, BUFFER_SIZE);
    if (bytes_received <= 0) {
        if (bytes_received < 0) {
            if (errno == EAGAIN) {
                return 0;
            }
            perror("recv");
        }
        return 1;
    }
    ctx->total += bytes_received;
    return 0;
}

void context_free(struct context *ctx)
{
    if (ctx->ssl != NULL) {
        SSL_shutdown(ctx->ssl);
        SSL_free(ctx->ssl);
        ctx->ssl = NULL;
    }
    if (ctx->ssl_ctx != NULL) {
        SSL_CTX_free(ctx->ssl_ctx);
        ctx->ssl_ctx = NULL;
    }

    if (ctx->sockfd != -1) {
        close(ctx->sockfd);
        ctx->sockfd = -1;
    }

    free(ctx->buffer);
    ctx->buffer = NULL;
    
    ctx->total = 0;
}


void handle_connection(char *server_ip) {
    int client_skt = -1;
    struct sockaddr_in addr;

    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

    char *buffer = malloc(BUFFER_SIZE);
    if (buffer == NULL) {
        perror("Failed to allocate memory for buffer");
        exit(1);
    }

    ssize_t bytes_received = 0;
    size_t total_bytes_received = 0;

    ssl_ctx = create_context();
    configure_client_context(ssl_ctx);
    SSL_CTX_set_options(ssl_ctx, SSL_OP_ENABLE_KTLS);
    client_skt = create_socket();

    addr.sin_family = AF_INET;
    inet_pton(AF_INET, server_ip, &addr.sin_addr.s_addr);
    addr.sin_port = htons(SERVER_PORT);

    if (connect(client_skt, (struct sockaddr*) &addr, sizeof(addr)) != 0) {
        perror("Unable to TCP connect to server");
        goto exit;
    } else {
        printf("TCP connection to server successful\n");
    }

    ssl = SSL_new(ssl_ctx);
    if (SSL_set_fd(ssl, client_skt) <= 0) {
        ERR_print_errors_fp(stderr);
        goto exit;
    }

    SSL_set_tlsext_host_name(ssl, server_ip);
    if (!SSL_set1_host(ssl, server_ip)) {
        ERR_print_errors_fp(stderr);
        goto exit;
    }

    if (SSL_connect(ssl) == 1) {
        printf("SSL connection to server successful\n\n");

        memset(buffer, 0, BUFFER_SIZE);
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        while ((bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE)) > 0) {
            /*
            size_t count = validate_online(buffer);
            if (count) {
                printf("Invalid count: %lu\n", count);
            }
            */
            total_bytes_received += bytes_received;
        }
        clock_gettime(CLOCK_MONOTONIC, &end);

        if (bytes_received < 0) {
            ERR_print_errors_fp(stderr);
        } else {
            printf("Total bytes received : %ld\n", total_bytes_received);
            measure_speed(total_bytes_received, start, end);
        }

        goto exit;
    } else {
        printf("SSL connection to server failed\n");
        ERR_print_errors_fp(stderr);
    }

exit:
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    SSL_CTX_free(ssl_ctx);

    if (client_skt != -1) {
        close(client_skt);
    }

    free(buffer);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <server_ip> <number_of_connections>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *server_ip = argv[1];
    int num_connections = atoi(argv[2]);

    fix_affinity(0);

    /*
    for (int i = 0; i < num_connections; i++) {
        pid_t pid = fork();

        if (pid < 0) {
            perror("Unable to fork");
            exit(EXIT_FAILURE);
        } else if (pid == 0) {  // Child process
            handle_connection(server_ip);
            exit(0);  // Child process exits
        }
    }

    // Parent process waits for all child processes to finish
    for (int i = 0; i < num_connections; i++) {
        wait(NULL);
    }
    */

    int epoll_fd = -1;
    struct context *ctxs = malloc(sizeof(struct context) * num_connections);
    if (ctxs == NULL) {
        perror("malloc ctxs");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < num_connections; i++) {
        if (context_init(&ctxs[i])) {
            perror("context_init");
            exit(EXIT_FAILURE);
        }
    }

    epoll_fd = epoll_create(MAX_EVENTS);
    if (epoll_fd < 0) {
        perror("epoll_create");
        exit(EXIT_FAILURE);
    }

    struct epoll_event event;
    event.events = EPOLLIN | EPOLLRDHUP;

    for (int i = 0; i < num_connections; i++) {
        if (context_handshake(&ctxs[i], server_ip)) {
            perror("context_handshake");
            exit(EXIT_FAILURE);
        }

        int flags = fcntl(ctxs[i].sockfd, F_GETFL, 0);
        fcntl(ctxs[i].sockfd, F_SETFL, flags | O_NONBLOCK);

        event.data.ptr = &ctxs[i];
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ctxs[i].sockfd, &event) < 0) {
            perror("epoll_ctl");
            exit(EXIT_FAILURE);
        }
    }

    struct epoll_event events[MAX_EVENTS];
    int event_count = 0;
    int timeout = 5000;
    int remain = num_connections;

    while (remain > 0) {
        event_count = epoll_wait(epoll_fd, events, MAX_EVENTS, timeout);

        if (event_count < 0) {
            perror("epoll_wait");
            break;
        }
        
        for (int i = 0; i < event_count; i++) {
            struct context *ctx = (struct context*)events[i].data.ptr;
            if (ctx == NULL) {
                continue;
            }
            if (ctx->buffer == NULL) {
                continue;
            }
            if (context_recv(ctx)) {
                printf("Finished\n");
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, ctx->sockfd, NULL);
                context_free(ctx);
                remain--;
            }
        }
    }

    free(ctxs);
    close(epoll_fd);

    return 0;
}
