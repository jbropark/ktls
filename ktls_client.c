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
#include <time.h>
#include <pthread.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

static const size_t BUFFER_SIZE = 1 * 1024 * 1024;

struct targ {
    char *server_ip;
    int port;
    int affinity;
};

void measure_speed(size_t bytes_sent, struct timespec start, struct timespec end) {
    double elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    double bitrate = ((bytes_sent * 8) / 1e9) / elapsed_time;

    printf("Received: %ld bytes, %.4f seconds, %.1f Gbps\n", bytes_sent, elapsed_time, bitrate);
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

int fix_affinity(int cpu)
{
    cpu_set_t cpuset;

    if (cpu < 0) {
        printf("No affinity\n");
        return 0;
    }

    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);

    pthread_t thread = pthread_self();

    if (pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset)) {
        perror("affinity");
        return -1;
    }

    printf("Fix affinity: %d\n", cpu);

    return 0;
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


void* handle_tcp(void *arg) {
    char *server_ip = ((struct targ*)arg)->server_ip;
    int port = ((struct targ*)arg)->port;
    int affinity = ((struct targ*)arg)->affinity;
    int client_skt = -1;
    struct sockaddr_in addr;

    fix_affinity(affinity);

    char *buffer = malloc(BUFFER_SIZE);
    if (buffer == NULL) {
        perror("Failed to allocate memory for buffer");
        exit(1);
    }

    ssize_t bytes_received = 0;
    size_t total_bytes_received = 0;

    client_skt = create_socket();

    addr.sin_family = AF_INET;
    inet_pton(AF_INET, server_ip, &addr.sin_addr.s_addr);
    addr.sin_port = htons(port);

    if (connect(client_skt, (struct sockaddr*) &addr, sizeof(addr)) != 0) {
        perror("Unable to TCP connect to server");
        goto exit_tcp;
    } else {
        printf("TCP connection to server successful\n");
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    while ((bytes_received = read(client_skt, buffer, BUFFER_SIZE)) > 0) {
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

exit_tcp:
    if (client_skt != -1) {
        close(client_skt);
    }

    free(buffer);
    return NULL;
}

void* handle_tls(void *arg) {
    char *server_ip = ((struct targ*)arg)->server_ip;
    int port = ((struct targ*)arg)->port;
    int affinity = ((struct targ*)arg)->affinity;
    int client_skt = -1;
    struct sockaddr_in addr;
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

    fix_affinity(affinity);

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
    addr.sin_port = htons(port);

    if (connect(client_skt, (struct sockaddr*) &addr, sizeof(addr)) != 0) {
        perror("Unable to TCP connect to server");
        goto exit_tls;
    } else {
        printf("TCP connection to server successful\n");
    }

    ssl = SSL_new(ssl_ctx);
    if (SSL_set_fd(ssl, client_skt) <= 0) {
        ERR_print_errors_fp(stderr);
        goto exit_tls;
    }

    SSL_set_tlsext_host_name(ssl, server_ip);
    if (!SSL_set1_host(ssl, server_ip)) {
        ERR_print_errors_fp(stderr);
        goto exit_tls;
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
    } else {
        printf("SSL connection to server failed\n");
        ERR_print_errors_fp(stderr);
    }

exit_tls:
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    SSL_CTX_free(ssl_ctx);

    if (client_skt != -1) {
        close(client_skt);
    }

    free(buffer);
    return NULL;
}

void help(char *name)
{
    fprintf(stderr, "Usage: %s <host> -h -p port -s\n", name);
}

int main(int argc, char* argv[])
{
    char *server_ip = NULL;
    int port = 12345;
    int opt_ok = 1;
    int tls = 0;
    int connections = 1;
    int affinity = -1;
    int opt;

    while((opt = getopt(argc, argv, "hsp:n:a:")) != -1) {
        switch(opt) {
            case 'h':
                opt_ok = 0;
                break;
            case 's':
                tls = 1;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'a':
                affinity = atoi(optarg);
                break;
            case 'n':
                connections = atoi(optarg);
                break;
        }
    }

    if (opt_ok != 1) {
        help(argv[0]);
        exit(0);
    }

    if (optind < argc) {
        server_ip = argv[optind];
    } else {
        help(argv[0]);
        exit(EXIT_FAILURE);
    }

    printf("Connect to %s:%d (%s)\n", server_ip, port, tls ? "TLS" : "TCP");
    pthread_t *tids = malloc(sizeof(pthread_t) * connections);
    struct targ *targs = malloc(sizeof(struct targ) * connections);
    for (int i = 0; i < connections; i++) {
        targs[i].server_ip = server_ip;
        targs[i].port = port;
        targs[i].affinity = affinity;
        if (tls) {
            pthread_create(&tids[i], NULL, handle_tls, &targs[i]);
        } else {
            pthread_create(&tids[i], NULL, handle_tcp, &targs[i]);
        }
    }

    for (int i = 0; i < connections; i++) {
        pthread_join(tids[i], NULL);
    }

    return 0;
}
