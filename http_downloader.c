#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <ctype.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

char **returnArgs(int argc, char *argv[]);
char **parseHostName(const char *URL);

int createTCPConnection(char **parsedURL);
SSL_CTX *createTLSContext(void);
SSL *createTLSConnection(SSL_CTX *ctx, int socket, const char *host);

int sendHTTPRequest(SSL *ssl, const char *method, const char *host, const char *path, const char *extra_headers);
char *receiveHTTP(SSL *ssl, size_t *out_len);
long parseContentLength(const char *headers, size_t header_len);

int saveBufferToFile(const char *buf, size_t len, const char *filename);
int saveHTTPBodyToFile(const char *response, size_t response_len, const char *filename);

void closeConnection(SSL *ssl, int socket);

// Info thread is given: thread #, byte range, parsed URL, and TLS context
typedef struct {
    int index;              // thread #
    long start;
    long end;
    char *host;
    char *path;
    char *port;
    SSL_CTX *ctx;           // TLS
} PartTask;

void *downloadPart(void *arg);
int stitchPartsToOutput(const char *out_file, int n_parts);

int main(int argc, char *argv[]) {
    char **args = returnArgs(argc, argv);

    int n_parts = atoi(args[1]);
    

    // Parse URL
    char **parts = parseHostName(args[0]);
    if (!parts[0]) { fprintf(stderr, "Failed to parse URL\n"); return EXIT_FAILURE; }

    printf("Host: %s\n", parts[0]);
    printf("Path: %s\n", parts[1]);
    printf("Port: %s\n", parts[2]);

    // Create TLS context
    SSL_CTX *ctx = createTLSContext();

    // Creates TCP / TLS connection
    int sock = createTCPConnection(parts);
    SSL *ssl = createTLSConnection(ctx, sock, parts[0]);

    // Asks if server accepts ranges and length of object
    sendHTTPRequest(ssl, "HEAD", parts[0], parts[1], NULL);

    const char *body = NULL;
    size_t head_len = 0;
    char *head_resp = receiveHTTP(ssl, &head_len);
    
    
    size_t hdr_end = 0;
    for (size_t i = 0; i + 3 < head_len; i++) {
        if (head_resp[i] == '\r' && head_resp[i+1] == '\n' && head_resp[i+2] == '\r' && head_resp[i+3] == '\n') {
            body = head_resp + i + 4;
            hdr_end = i + 4;
            break;
        }
    }


    long content_length = parseContentLength(head_resp, hdr_end);

    free(head_resp);
    closeConnection(ssl, sock);

    long base = content_length / n_parts;
    long rem  = content_length % n_parts;

    // Allocate memory for thread tasks and thread IDs
    PartTask *tasks   = calloc(n_parts, sizeof(PartTask));
    pthread_t *threads = calloc(n_parts, sizeof(pthread_t));


    long offset = 0;
    for (int i = 0; i < n_parts; i++) {     // Defines the struct each thread uses
        long size = base + (i == n_parts - 1 ? rem : 0);
        tasks[i].index = i + 1;
        tasks[i].start = offset;
        tasks[i].end   = offset + size - 1;
        tasks[i].host  = parts[0];
        tasks[i].path  = parts[1];
        tasks[i].port  = parts[2];
        tasks[i].ctx   = ctx;
        offset += size;
    }

    // creates the threads and assigns them their portion of the object
    for (int i = 0; i < n_parts; i++) {
        pthread_create(&threads[i], NULL, downloadPart, &tasks[i]);
    }

    // Joins threads together
    for (int i = 0; i < n_parts; i++) {
        pthread_join(threads[i], NULL);
    }


    stitchPartsToOutput(args[2], n_parts);


    printf("Written to %s\n", args[2]);

    free(tasks);
    free(threads);
    SSL_CTX_free(ctx);
    return 0;
}


char **returnArgs(int argc, char *argv[]) { // returns: args[url, parts, output]
    static char *rtn[3] = {" ", " ", " "};

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-u") == 0) {
            rtn[0] = argv[i + 1];
        }
        else if (strcmp(argv[i], "-n") == 0) {
            rtn[1] = argv[i + 1];
        }
        else if (strcmp(argv[i], "-o") == 0) {
            rtn[2] = argv[i + 1];
        }
    }

    return rtn;
}


char **parseHostName(const char *URL) {     // returns: [host, path, port]
    static char *rtn[3] = {"", "", ""};
    rtn[2] = "443";

    char *URLCopy = strdup(URL);

    // parse host
    char *host = strstr(URLCopy, "://");
    if (host) {
        host += 3; 
    } else {
        host = URLCopy;
    }

    char *path = strchr(host, '/');
    if (path) {
        *path = '\0';
        rtn[1] = path + 1;
    } else {
        rtn[1] = "";
    }

    // parse port
    char *port = strchr(host, ':');
    if (port) {
        *port = '\0';
        rtn[2] = port + 1;
    }

    rtn[0] = host;
    return rtn;
}


int createTCPConnection(char **parsedURL) {     // DNS lookup, open socket, connect to server
    const char *host = parsedURL[0];
    const char *port = parsedURL[2];

    struct addrinfo hints, *res;    // DNS lookup
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(host, port, &hints, &res);
        
    int client_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol); // Open Socket

    connect(client_socket, res->ai_addr, res->ai_addrlen);

    freeaddrinfo(res);
    return client_socket;
}


SSL_CTX *createTLSContext(void) {   // Creates TLS Context and verifies certificates
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    return ctx;
}


SSL *createTLSConnection(SSL_CTX *ctx, int socket, const char *host){   // Wraps tcp in TLS and verifies certificates
    if (!ctx) return NULL;

    SSL *ssl = SSL_new(ctx);
    SSL_set_tlsext_host_name(ssl, host);
    SSL_set_fd(ssl, socket);
    SSL_connect(ssl);

    return ssl;
}

int sendHTTPRequest(SSL *ssl, const char *method, const char *host, const char *path, const char *extra_headers) {
// Sends HTTP request to get info on object being retrieved: object length and ranges
    char req[4096];
    int req_len = snprintf(req, sizeof(req),
        "%s /%s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "%s%s\r\n",
        method, path, host,
        (extra_headers ? extra_headers : ""),
        (extra_headers ? "\r\n" : ""));

    int sent = 0;
    while (sent < req_len) {
        int n = SSL_write(ssl, req + sent, req_len - sent);
        if (n <= 0) {   // Stop inifinte loop
            return -1;
        }
        sent += n;
    }
    return 0;
}

char *receiveHTTP(SSL *ssl, size_t *out_len) {  // Receives info sendHTTPRequest() asked for
    if (!ssl) return NULL;
    const int bufsize = 4096;
    char buf[4096];
    char *response = NULL;
    size_t total = 0;
    int n;
    for (;;) {
        n = SSL_read(ssl, buf, bufsize);
        if (n > 0) {
            char *newresp = realloc(response, total + n);
            if (!newresp) { free(response); return NULL; }
            response = newresp;
            memcpy(response + total, buf, n);
            total += n;
        } else if (n == 0) {     // Stop inifinte loop
            break;
        } else {
            return NULL;
        }
    }
    if (out_len) *out_len = total;
    return response;
}

static int startsWith(const char *s, const char *prefix) {
    // Help parse HTTP responses in case of different capitalization
    while (*prefix && *s) {
        if (tolower((unsigned char)*s) != tolower((unsigned char)*prefix)) return 0;
        s++; prefix++;
    }
    return *prefix == '\0';
}


long parseContentLength(const char *headers, size_t header_len) {   // Parses length of object to be downloaded from response
    size_t i = 0;
    while (i < header_len) {

        size_t line_start = i;
        while (i < header_len && !(headers[i] == '\r' && (i + 1) < header_len && headers[i + 1] == '\n')) {
            i++;
        }
        size_t line_end = i;

        if ((i + 1) < header_len) i += 2;

        size_t line_len = line_end - line_start;
        if (line_len >= 16) {
            if (startsWith(headers + line_start, "Content-Length:")) {
                const char *p = headers + line_start + 15;

                while (p < headers + line_end && (*p == ' ' || *p == '\t')) {
                    p++;
                }
                long value = 0;
                while (p < headers + line_end && *p >= '0' && *p <= '9') {
                    value = value * 10 + (*p - '0');
                    p++;
                }

                return value;
            }
        }
    }
    return -1;
}

int saveBufferToFile(const char *buf, size_t len, const char *filename) {   // prints object parts to file
    FILE *fp = fopen(filename, "wb");
    if (!fp) return -1;
    size_t w = fwrite(buf, 1, len, fp);
    fclose(fp);
    return (w == len) ? 0 : -1;
}

int saveHTTPBodyToFile(const char *response, size_t response_len, const char *filename) {   // prints object segment to own file
    if (!response || !filename) return -1;

    // Gets rid of headers
    const char *body = NULL;
    for (size_t i = 0; i + 3 < response_len; i++) {
        if (response[i] == '\r' && response[i+1] == '\n' && response[i+2] == '\r' && response[i+3] == '\n') {
            body = response + i + 4;
            break;
        }
    }
    if (!body) return -1;

    FILE *fp = fopen(filename, "wb");
    if (!fp) return -1;

    size_t header_len = (size_t)(body - response);
    size_t body_len = response_len - header_len;

    fwrite(body, 1, body_len, fp);

    fclose(fp);
    return 0;
}

void *downloadPart(void *arg) {        // Each thread calls this and makes Range request for their assigned byte range
    PartTask *t = (PartTask *)arg;

    int sock = createTCPConnection((char **)( (char*[]){ t->host, t->path, t->port } ));
    SSL *ssl = createTLSConnection(t->ctx, sock, t->host);


    char rangeHdr[128];
    snprintf(rangeHdr, sizeof(rangeHdr), "Range: bytes=%ld-%ld\r\n", t->start, t->end);

    sendHTTPRequest(ssl, "GET", t->host, t->path, rangeHdr);

    size_t resp_len = 0;
    char *resp = receiveHTTP(ssl, &resp_len);


    size_t hdr_end = 0;
    for (size_t i = 0; i + 3 < resp_len; i++) {
        if (resp[i] == '\r' && resp[i+1] == '\n' && resp[i+2] == '\r' && resp[i+3] == '\n') { hdr_end = i + 4; break; }
    }


    size_t body_len = resp_len - hdr_end;
    const char *body = resp + hdr_end;

    char fname[64];
    snprintf(fname, sizeof(fname), "part_%d", t->index);

    saveBufferToFile(body, body_len, fname);

    free(resp);
    closeConnection(ssl, sock);
    pthread_exit(NULL);
}

int stitchPartsToOutput(const char *out_file, int n_parts) {     // Combines all parts into full object and prints to output
    FILE *out = fopen(out_file, "wb");
    if (!out) return -1;

    char buf[8192];
    for (int i = 1; i <= n_parts; i++) {
        char fname[64];
        snprintf(fname, sizeof(fname), "part_%d", i);
        FILE *in = fopen(fname, "rb");
        if (!in) { fclose(out); return -1; }
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
            if (fwrite(buf, 1, n, out) != n) { fclose(in); fclose(out); return -1; }
        }
        fclose(in);
    }
    fclose(out);
    return 0;
}


void closeConnection(SSL *ssl, int socket){     // Shuts down TLS and TCP socket
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (socket >= 0) {
        close(socket);
    }
}