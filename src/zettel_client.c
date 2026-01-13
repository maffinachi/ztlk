#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <time.h>
#include <uuid/uuid.h>

#define BUFFER_SIZE 16384

static int sock = -1;
static char last_challenge[256];

static char *bin_to_b64(const unsigned char *bin, size_t binlen) {
    size_t b64len = sodium_base64_ENCODED_LEN(binlen, sodium_base64_VARIANT_ORIGINAL);
    char *b64 = malloc(b64len);
    sodium_bin2base64(b64, b64len, bin, binlen, sodium_base64_VARIANT_ORIGINAL);
    return b64;
}
static int b64_to_bin(const char *b64, unsigned char *out, size_t outlen) {
    size_t decoded_len = 0;
    if (sodium_base642bin(out, outlen, b64, strlen(b64), NULL, &decoded_len, NULL, sodium_base64_VARIANT_ORIGINAL) != 0) return -1;
    return (int)decoded_len;
}

static int connect_to(const char *host, int port) {
    if (sock != -1) close(sock);
    struct sockaddr_in serv;
    struct hostent *he = gethostbyname(host);
    if (!he) { printf("Unknown host\n"); return -1; }
    sock = socket(AF_INET, SOCK_STREAM, 0);
    memset(&serv,0,sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_port = htons(port);
    memcpy(&serv.sin_addr, he->h_addr, he->h_length);
    if (connect(sock, (struct sockaddr*)&serv, sizeof(serv)) < 0) {
        perror("connect");
        close(sock); sock=-1;
        return -1;
    }
    // read potential banner? not needed
    printf("Connected to %s:%d\n", host, port);
    return 0;
}

static void send_json(const char *json) {
    if (sock < 0) { printf("Not connected\n"); return; }
    char out[BUFFER_SIZE];
    int n = snprintf(out, sizeof(out), "%s\n", json);
    send(sock, out, n, 0);
}

static int recv_line(char *buf, size_t bufsize, int timeout_ms) {
    // simple blocking read until '\n' (with no timeout implemented for brevity)
    size_t pos=0;
    while (pos+1 < bufsize) {
        char c;
        ssize_t r = recv(sock, &c, 1, 0);
        if (r <= 0) return -1;
        buf[pos++] = c;
        if (c == '\n') break;
    }
    buf[pos] = 0;
    return (int)pos;
}

static void do_hello() {
    send_json("{\"type\":\"HELLO\",\"client\":\"zettel-cli\",\"version\":\"0.1\"}");
    // wait CHALLENGE
    char line[BUFFER_SIZE];
    if (recv_line(line, sizeof(line), 0) <= 0) { printf("No response\n"); return; }
    if (strstr(line, "\"type\":\"CHALLENGE\"")) {
        char *p = strstr(line, "\"nonce\":\"");
        if (p) {
            p += 9;
            char nonce[256];
            sscanf(p, "%255[^\"]", nonce);
            strncpy(last_challenge, nonce, sizeof(last_challenge)-1);
            printf("Challenge: %s\n", last_challenge);
            return;
        }
    }
    printf("Unexpected: %s\n", line);
}

static int read_privkey_file(const char *path, unsigned char *sk) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror("open privkey"); return -1; }
    size_t r = fread(sk, 1, crypto_sign_SECRETKEYBYTES, f);
    fclose(f);
    if (r != crypto_sign_SECRETKEYBYTES) return -1;
    return 0;
}
static int read_pubkey_file(const char *path, unsigned char *pk) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror("open pubkey"); return -1; }
    size_t r = fread(pk, 1, crypto_sign_PUBLICKEYBYTES, f);
    fclose(f);
    if (r != crypto_sign_PUBLICKEYBYTES) return -1;
    return 0;
}

static void do_auth(const char *nick, const char *token, const char *privkey_path, const char *pubkey_path) {
    if (sock < 0) { printf("Not connected\n"); return; }
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    if (read_privkey_file(privkey_path, sk) != 0) { printf("Cannot read privkey\n"); return; }
    if (read_pubkey_file(pubkey_path, pk) != 0) { printf("Cannot read pubkey\n"); return; }
    // sign nonce
    unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, NULL, (unsigned char*)last_challenge, strlen(last_challenge), sk);
    char *sig_b64 = bin_to_b64(sig, crypto_sign_BYTES);
    char *pub_b64 = bin_to_b64(pk, crypto_sign_PUBLICKEYBYTES);
    char json[2048];
    snprintf(json, sizeof(json), "{\"type\":\"AUTH\",\"nick\":\"%s\",\"token\":\"%s\",\"pubkey\":\"%s\",\"sig\":\"%s\"}", nick, token, pub_b64, sig_b64);
    send_json(json);
    free(sig_b64);
    free(pub_b64);
    // wait response
    char line[BUFFER_SIZE];
    if (recv_line(line, sizeof(line), 0) <= 0) { printf("No response\n"); return; }
    printf("Server: %s\n", line);
}

static void do_post(const char *title, const char *body, const char *parent, const char *privkey_path, const char *pubkey_path, const char *nick) {
    if (sock < 0) { printf("Not connected\n"); return; }
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    if (read_privkey_file(privkey_path, sk) != 0) { printf("Cannot read privkey\n"); return; }
    if (read_pubkey_file(pubkey_path, pk) != 0) { printf("Cannot read pubkey\n"); return; }
    // id uuid
    uuid_t u;
    char id[40];
    uuid_generate_random(u);
    uuid_unparse_lower(u, id);
    // ts
    time_t ts = time(NULL);
    // body base64
    char *body_b64 = NULL;
    body_b64 = bin_to_b64((const unsigned char*)body, strlen(body));
    // canonical string for signing
    char canon[16384];
    snprintf(canon, sizeof(canon), "%s|%s|%s|%s|%ld", id, title, body_b64, parent?parent:"", ts);
    unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, NULL, (unsigned char*)canon, strlen(canon), sk);
    char *sig_b64 = bin_to_b64(sig, crypto_sign_BYTES);
    char *pub_b64 = bin_to_b64(pk, crypto_sign_PUBLICKEYBYTES);
    char json[16384];
    snprintf(json, sizeof(json),
        "{\"type\":\"POST_NOTE\",\"id\":\"%s\",\"nick\":\"%s\",\"title\":\"%s\",\"body_b64\":\"%s\",\"parent\":\"%s\",\"ts\":%ld,\"sig\":\"%s\",\"pubkey\":\"%s\"}",
        id, nick, title, body_b64, parent?parent:"", ts, sig_b64, pub_b64);
    send_json(json);
    free(body_b64);
    free(sig_b64);
    free(pub_b64);
    // await ack or note broadcast (could be async)
    char line[BUFFER_SIZE];
    if (recv_line(line, sizeof(line), 0) > 0) {
        printf("Server: %s\n", line);
    }
}

static void repl() {
    char line[8192];
    char cmd[128], arg1[1024], arg2[4096];
    char nick[128] = {0}, token[256] = {0}, privkey[512] = {0}, pubkey[512] = {0};
    printf("Commands:\n  /connect host port\n  /hello\n  /auth nick token privkey_file pubkey_file\n  /post \"title\" \"body\" [parent]\n  /fetch nick:<nick>\n  /quit\n");
    while (1) {
        printf("> ");
        if (!fgets(line, sizeof(line), stdin)) break;
        line[strcspn(line, "\n")] = 0;
        if (sscanf(line, "/connect %127s %d", arg1, (int[]){0}[0])==1) {
            // sscanf hack not ideal, parse differently
        }
        if (strncmp(line, "/connect ", 9) == 0) {
            char host[256]; int port;
            if (sscanf(line+9, "%255s %d", host, &port) >= 1) {
                if (port==0) port = 9009;
                connect_to(host, port);
            } else printf("Usage: /connect host port\n");
            continue;
        }
        if (strcmp(line, "/hello") == 0) {
            do_hello(); continue;
        }
        if (strncmp(line, "/auth ", 6) == 0) {
            // /auth nick token privkey pubkey
            if (sscanf(line+6, "%127s %255s %511s %511s", nick, token, privkey, pubkey) < 4) {
                printf("Usage: /auth nick token privkey_path pubkey_path\n"); continue;
            }
            do_auth(nick, token, privkey, pubkey);
            continue;
        }
        if (strncmp(line, "/post ", 6) == 0) {
            // parse "/post \"Title\" \"Body\" [parent]"
            char title[512], body[4096], parent[128];
            title[0]=body[0]=parent[0]=0;
            // naive parse with quotes
            const char *p = line+6;
            if (*p=='"') {
                p++;
                const char *q = strchr(p, '"');
                if (q) {
                    size_t L = q - p;
                    strncpy(title, p, L); title[L]=0;
                    p = q+1;
                } else { printf("Bad format\n"); continue; }
            } else { printf("Title must be quoted\n"); continue; }
            while (*p==' ') p++;
            if (*p=='"') {
                p++; const char *q = strchr(p, '"');
                if (q) {
                    size_t L = q-p; strncpy(body, p, L); body[L]=0; p=q+1;
                } else { printf("Bad format\n"); continue; }
            } else { printf("Body must be quoted\n"); continue; }
            while (*p==' ') p++;
            if (*p) {
                sscanf(p, "%127s", parent);
            }
            do_post(title, body, parent[0]?parent:NULL, privkey, pubkey, nick);
            continue;
        }
        if (strncmp(line, "/fetch ", 7) == 0) {
            char arg[256];
            if (sscanf(line+7, "%255s", arg)==1) {
                char json[512];
                snprintf(json, sizeof(json), "{\"type\":\"FETCH\",\"thread\":\"%s\"}", arg);
                send_json(json);
                // read result(s)
                char rbuf[BUFFER_SIZE];
                while (recv_line(rbuf, sizeof(rbuf), 0) > 0) {
                    printf("%s\n", rbuf);
                    // break if we want single response; for demo break after first non-empty
                    break;
                }
            } else printf("Usage: /fetch nick:<nick>\n");
            continue;
        }
        if (strcmp(line, "/quit")==0) break;
        // default: show help
        printf("unknown command\n");
    }
}

int main(int argc, char **argv) {
    if (sodium_init() < 0) { fprintf(stderr, "libsodium init failed\n"); return 1; }
    repl();
    if (sock != -1) close(sock);
    return 0;
}
