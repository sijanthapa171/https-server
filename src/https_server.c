#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define BACKLOG 16
#define READ_BUF_SIZE 8192

static volatile sig_atomic_t keep_running = 1;

static void handle_sigint(int signum) {
	(void)signum;
	keep_running = 0;
}

static void die(const char *msg) {
	perror(msg);
	exit(EXIT_FAILURE);
}

static int create_listen_socket(const char *ip, uint16_t port) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) die("socket");

	int opt = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
		die("setsockopt SO_REUSEADDR");

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) die("inet_pton");

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) die("bind");
	if (listen(fd, BACKLOG) < 0) die("listen");
	return fd;
}

static SSL_CTX *create_ssl_ctx(const char *cert_path, const char *key_path) {
	const SSL_METHOD *method = TLS_server_method();
	SSL_CTX *ctx = SSL_CTX_new(method);
	if (!ctx) die("SSL_CTX_new");

	SSL_CTX_set_ecdh_auto(ctx, 1);

	if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		die("SSL_CTX_use_certificate_file");
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		die("SSL_CTX_use_PrivateKey_file");
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr, "Private key does not match the certificate public key\n");
		exit(EXIT_FAILURE);
	}

	return ctx;
}

static void respond_hello(SSL *ssl) {
	const char *body = "Hello, HTTPS!\n";
	char response[256];
	snprintf(response, sizeof(response),
			 "HTTP/1.1 200 OK\r\n"
			 "Content-Type: text/plain; charset=utf-8\r\n"
			 "Content-Length: %zu\r\n"
			 "Connection: close\r\n"
			 "\r\n%s",
			 strlen(body), body);
	SSL_write(ssl, response, (int)strlen(response));
}

static void handle_client(int client_fd, SSL_CTX *ctx) {
	/* Detect plain HTTP on this TLS port and respond clearly */
	{
		char peek[16];
		ssize_t n = recv(client_fd, peek, sizeof(peek), MSG_PEEK);
		if (n > 0) {
			if ((n >= 3 && (!memcmp(peek, "GET", 3) || !memcmp(peek, "POS", 3) || !memcmp(peek, "HEA", 3))) ||
			    (n >= 4 && (!memcmp(peek, "PUT ", 4) || !memcmp(peek, "PRI ", 4))) ||
			    (n >= 1 && (peek[0] == 'O' || peek[0] == 'D' || peek[0] == 'T' || peek[0] == 'C'))) {
				const char *plain =
					"HTTP/1.1 400 Bad Request\r\n"
					"Content-Type: text/plain; charset=utf-8\r\n"
					"Connection: close\r\n"
					"Content-Length: 44\r\n"
					"\r\n"
					"This is an HTTPS port. Use https:// instead.\n";
				(void)send(client_fd, plain, strlen(plain), 0);
				close(client_fd);
				return;
			}
		}
	}

	SSL *ssl = SSL_new(ctx);
	if (!ssl) {
		close(client_fd);
		return;
	}
	SSL_set_fd(ssl, client_fd);
	if (SSL_accept(ssl) <= 0) {
		fprintf(stderr, "TLS handshake failed\n");
		SSL_shutdown(ssl);
		SSL_free(ssl);
		close(client_fd);
		return;
	}

	char buf[READ_BUF_SIZE];
	int n = SSL_read(ssl, buf, sizeof(buf) - 1);
	if (n > 0) {
		buf[n] = '\0';
		respond_hello(ssl);
	}

	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(client_fd);
}

int main(int argc, char **argv) {
	if (argc < 5) {
		fprintf(stderr, "Usage: %s <bind_ip> <port> <cert.pem> <key.pem>\n", argv[0]);
		return EXIT_FAILURE;
	}

	const char *bind_ip = argv[1];
	uint16_t port = (uint16_t)atoi(argv[2]);
	const char *cert_path = argv[3];
	const char *key_path = argv[4];

	signal(SIGINT, handle_sigint);

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();

	int listen_fd = create_listen_socket(bind_ip, port);
	SSL_CTX *ctx = create_ssl_ctx(cert_path, key_path);

	printf("HTTPS server listening on %s:%u\n", bind_ip, (unsigned)port);
	while (keep_running) {
		struct sockaddr_in peer;
		socklen_t peer_len = sizeof(peer);
		int client_fd = accept(listen_fd, (struct sockaddr *)&peer, &peer_len);
		if (client_fd < 0) {
			if (errno == EINTR && !keep_running) break;
			perror("accept");
			continue;
		}
		handle_client(client_fd, ctx);
	}

	SSL_CTX_free(ctx);
	EVP_cleanup();
	close(listen_fd);
	printf("Server stopped.\n");
	return EXIT_SUCCESS;
}


