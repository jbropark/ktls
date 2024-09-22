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

#include <openssl/ssl.h>
#include <openssl/err.h>

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
	struct sockaddr_in addr;
	
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

void handle_connection(char *server_ip) {
	int client_skt = -1;
	struct sockaddr_in addr;
	unsigned int addr_len = sizeof(addr);

	SSL_CTX *ssl_ctx = NULL;
	SSL *ssl = NULL;

	char *buffer = malloc(BUFFER_SIZE);
	if (!buffer) {
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
			// printf("Bytes received this chunk: %ld\n", bytes_received);
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

	if (client_skt != -1)
		close(client_skt);

	free(buffer);
}

int main(int argc, char* argv[]) {
	if (argc != 3) {
		fprintf(stderr, "Usage: %s <server_ip> <number_of_connections>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	char *server_ip = argv[1];
	int num_connections = atoi(argv[2]);

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

	return 0;
}
