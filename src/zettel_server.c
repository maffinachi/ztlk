#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sodium.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <dirent.h>
#include <time.h>

#define PORT_DEFAULT 9009
#define MAX_CLIENTS 256
#define BUFFER_SIZE 16384
#define DATA_DIR "data"

typedef struct {
    int fd;
    char addr[64];
    int authenticated;
    char nick[128];
    char pending_nonce[128];
    char buf[BUFFER_SIZE];
    size_t buflen;
} client_t;

client_t clients[MAX_CLIENTS];

typedef struct note_index_entry {
    char id[64];
    time_t ts;
    struct note_index_entry *next;
} note_index_entry_t;

typedef struct {
    char nick[128];
    note_index_entry_t *head;
} manifest_t;

#define MAX_MANIFESTS 1024
manifest_t manifests[MAX_MANIFESTS];
int manifests_count = 0;

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void init_clients() {
    for (int i=0;i<MAX_CLIENTS;i++) clients[i].fd = -1;
}

static int add_client(int fd, struct sockaddr_in *addr) {
    for (int i=0;i<MAX_CLIENTS;i++) {
        if (clients[i].fd == -1) {
            clients[i].fd = fd;
            snprintf(clients[i].addr, sizeof(clients[i].addr), "%s:%d",
                     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
            clients[i].authenticated = 0;
            clients[i].pending_nonce[0]=0;
            clients[i].buflen=0;
            clients[i].nick[0]=0;
            return i;
        }
    }
    return -1;
}

static void remove_client(int idx) {
    if (clients[idx].fd != -1) {
        close(clients[idx].fd);
        clients[idx].fd = -1;
    }
}

static void send_json(int fd, const char *json) {
    if (fd < 0) return;
    // Messages are newline terminated
    char out[BUFFER_SIZE];
    int n = snprintf(out, sizeof(out), "%s\n", json);
    ssize_t w = send(fd, out, n, 0);
    (void)w;
}

static void broadcast_note_to_subscribers(const char *note_json) {
    // naive: broadcast to all authenticated clients
    for (int i=0;i<MAX_CLIENTS;i++) {
        if (clients[i].fd != -1 && clients[i].authenticated) {
            send_json(clients[i].fd, note_json);
        }
    }
}

/* util: base64 helpers via libsodium */
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

/* generate random nonce */
static void gen_nonce(char *buf, size_t len) {
    unsigned char r[32];
    randombytes_buf(r, sizeof(r));
    char *b64 = bin_to_b64(r, sizeof(r));
    strncpy(buf, b64, len-1);
    buf[len-1]=0;
    free(b64);
}

/* storage helpers */
static void ensure_data_dir() {
    struct stat st;
    if (stat(DATA_DIR, &st) == -1) {
        mkdir(DATA_DIR, 0700);
    }
}

static manifest_t *find_manifest(const char *nick) {
    for (int i=0;i<manifests_count;i++) {
        if (strcmp(manifests[i].nick, nick) == 0) return &manifests[i];
    }
    return NULL;
}

static manifest_t *ensure_manifest(const char *nick) {
    manifest_t *m = find_manifest(nick);
    if (m) return m;
    if (manifests_count >= MAX_MANIFESTS) return NULL;
    strncpy(manifests[manifests_count].nick, nick, sizeof(manifests[manifests_count].nick)-1);
    manifests[manifests_count].head = NULL;
    manifests_count++;
    return &manifests[manifests_count-1];
}

static void add_note_index(const char *nick, const char *id, time_t ts) {
    manifest_t *m = ensure_manifest(nick);
    if (!m) return;
    note_index_entry_t *e = malloc(sizeof(note_index_entry_t));
    strncpy(e->id, id, sizeof(e->id)-1);
    e->ts = ts;
    e->next = m->head;
    m->head = e;
}

/* load existing data on startup */
static void load_existing_data() {
    ensure_data_dir();
    DIR *d = opendir(DATA_DIR);
    if (!d) return;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0]=='.') continue;
        // ent is user dir
        char userdir[512];
        snprintf(userdir, sizeof(userdir), DATA_DIR"/%s", ent->d_name);
        struct stat st;
        if (stat(userdir, &st) == -1 || !S_ISDIR(st.st_mode)) continue;
        // scan files
        DIR *ud = opendir(userdir);
        if (!ud) continue;
        struct dirent *f;
        while ((f = readdir(ud)) != NULL) {
            if (f->d_name[0]=='.') continue;
            // treat file as note JSON; get mtime
            char fpath[1024];
            snprintf(fpath, sizeof(fpath), "%s/%s", userdir, f->d_name);
            struct stat fst;
            if (stat(fpath, &fst)==0) {
                // id = filename without extension
                char id[128];
                strncpy(id, f->d_name, sizeof(id)-1);
                // strip suffix .json if present
                char *p = strstr(id, ".json");
                if (p) *p=0;
                add_note_index(ent->d_name, id, fst.st_mtime);
            }
        }
        closedir(ud);
    }
    closedir(d);
}

/* save note JSON to disk */
static int save_note_to_disk(const char *nick, const char *id, const char *json) {
    ensure_data_dir();
    char userdir[512];
    snprintf(userdir, sizeof(userdir), DATA_DIR"/%s", nick);
    struct stat st;
    if (stat(userdir, &st) == -1) {
        if (mkdir(userdir, 0700) == -1) return -1;
    }
    char fpath[1024];
    snprintf(fpath, sizeof(fpath), "%s/%s.json", userdir, id);
    FILE *f = fopen(fpath, "w");
    if (!f) return -1;
    fputs(json, f);
    fclose(f);
    time_t now = time(NULL);
    add_note_index(nick, id, now);
    return 0;
}

/* placeholder token verification
   In real system replace this function with actual TON contract call / node RPC verification.
   The user described that token is derived from pubkey and time into a static hash stored in contract.
   Here we implement a local rule for testing:
     token == base64( SHA256( pubkey_base64 ":" issue_time ) )
   For production: implement verify_token_on_chain(token, pubkey_b64) calling your TON node/contract.
*/
static int verify_token_on_chain(const char *token_b64, const char *pubkey_b64) {
    // demo: compute sha256(pubkey_b64) and compare base64
    unsigned char hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash, (const unsigned char*)pubkey_b64, strlen(pubkey_b64));
    char *computed = bin_to_b64(hash, crypto_hash_sha256_BYTES);
    int ok = (strcmp(computed, token_b64)==0);
    free(computed);
    return ok;
}

/* verify ed25519 signature given pubkey (base64) */
static int verify_sig_b64(const char *msg, const char *sig_b64, const char *pubkey_b64) {
    unsigned char sig[crypto_sign_BYTES];
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    if (b64_to_bin(sig_b64, sig, sizeof(sig)) != crypto_sign_BYTES) return 0;
    if (b64_to_bin(pubkey_b64, pk, sizeof(pk)) != crypto_sign_PUBLICKEYBYTES) return 0;
    if (crypto_sign_verify_detached(sig, (const unsigned char*)msg, strlen(msg), pk) != 0) return 0;
    return 1;
}

/* handle a single JSON line as text (no JSON parser used — naive parsing) */
static void handle_message(int idx, const char *line) {
    client_t *c = &clients[idx];
    // naive detection of type field
    if (strstr(line, "\"type\":\"HELLO\"")) {
        // reply CHALLENGE with nonce
        gen_nonce(c->pending_nonce, sizeof(c->pending_nonce));
        char json[512];
        snprintf(json, sizeof(json), "{\"type\":\"CHALLENGE\",\"nonce\":\"%s\"}", c->pending_nonce);
        send_json(c->fd, json);
        return;
    }
    if (strstr(line, "\"type\":\"AUTH\"")) {
        // extract fields nick, token, pubkey, sig
        char nick[128]={0}, token[256]={0}, pubkey[512]={0}, sig[512]={0};
        // naive extraction with strstr + sscanf
        char *p;
        if ((p = strstr(line, "\"nick\":\""))) {
            p+=8; sscanf(p, "%127[^\"]", nick);
        }
        if ((p = strstr(line, "\"token\":\""))) {
            p+=9; sscanf(p, "%255[^\"]", token);
        }
        if ((p = strstr(line, "\"pubkey\":\""))) {
            p+=10; sscanf(p, "%511[^\"]", pubkey);
        }
        if ((p = strstr(line, "\"sig\":\""))) {
            p+=7; sscanf(p, "%511[^\"]", sig);
        }
        // verify signature over nonce
        if (!verify_sig_b64(c->pending_nonce, sig, pubkey)) {
            send_json(c->fd, "{\"type\":\"AUTH_FAIL\",\"reason\":\"signature verification failed\"}");
            return;
        }
        // verify token
        if (!verify_token_on_chain(token, pubkey)) {
            send_json(c->fd, "{\"type\":\"AUTH_FAIL\",\"reason\":\"token invalid\"}");
            return;
        }
        // good — authenticate
        c->authenticated = 1;
        strncpy(c->nick, nick, sizeof(c->nick)-1);
        char resp[256];
        snprintf(resp, sizeof(resp), "{\"type\":\"AUTH_OK\",\"nick\":\"%s\"}", nick);
        send_json(c->fd, resp);
        return;
    }
    if (!c->authenticated) {
        send_json(c->fd, "{\"type\":\"ERROR\",\"reason\":\"not authenticated\"}");
        return;
    }
    if (strstr(line, "\"type\":\"POST_NOTE\"")) {
        // parse id, title, body_b64, parent, ts, sig
        char id[128]={0}, title[256]={0}, body_b64[4096]={0}, parent[128]={0}, sig[512]={0};
        long ts=0;
        char pubkey_b64[512] = {0};
        char *p;
        if ((p = strstr(line, "\"id\":\""))) { p+=6; sscanf(p, "%127[^\"]", id); }
        if ((p = strstr(line, "\"title\":\""))) { p+=9; sscanf(p, "%255[^\"]", title); }
        if ((p = strstr(line, "\"body_b64\":\""))) { p+=13; sscanf(p, "%4095[^\"]", body_b64); }
        if ((p = strstr(line, "\"parent\":\""))) { p+=10; sscanf(p, "%127[^\"]", parent); }
        if ((p = strstr(line, "\"ts\":"))) { p+=5; sscanf(p, "%ld", &ts); }
        if ((p = strstr(line, "\"sig\":\""))) { p+=7; sscanf(p, "%511[^\"]", sig); }
        if ((p = strstr(line, "\"pubkey\":\""))) { p+=10; sscanf(p, "%511[^\"]", pubkey_b64); }

        // verify signature over a canonical string (id|title|body_b64|parent|ts)
        char canon[8192];
        snprintf(canon, sizeof(canon), "%s|%s|%s|%s|%ld", id, title, body_b64, parent, ts);
        if (!verify_sig_b64(canon, sig, pubkey_b64)) {
            send_json(c->fd, "{\"type\":\"ERROR\",\"reason\":\"note signature invalid\"}");
            return;
        }
        // save note JSON (we store original line)
        if (save_note_to_disk(c->nick, id, line) != 0) {
            send_json(c->fd, "{\"type\":\"ERROR\",\"reason\":\"save failed\"}");
            return;
        }
        // ack and broadcast NOTE to subscribers
        char ack[256];
        snprintf(ack, sizeof(ack), "{\"type\":\"NOTE_ACK\",\"id\":\"%s\"}", id);
        send_json(c->fd, ack);
        // broadcast same NOTE message to other clients
        broadcast_note_to_subscribers(line);
        return;
    }
    if (strstr(line, "\"type\":\"FETCH\"")) {
        // very naive: client requests notes for a nick/thread; we'll support fetch all notes for nick
        char thread[128]={0};
        char *p;
        if ((p = strstr(line, "\"thread\":\""))) { p+=10; sscanf(p, "%127[^\"]", thread); }
        // thread syntax: "nick:<nick>" or note id
        if (strncmp(thread, "nick:", 5)==0) {
            char *nick = thread+5;
            manifest_t *m = find_manifest(nick);
            if (!m) {
                send_json(c->fd, "{\"type\":\"MANIFEST\",\"notes\":[]}");
                return;
            }
            // build small manifest JSON: [{"id":"..","ts":..},...]
            char out[BUFFER_SIZE];
            strcpy(out, "{\"type\":\"MANIFEST\",\"notes\":[");
            note_index_entry_t *e = m->head;
            int first=1;
            while (e) {
                if (!first) strcat(out, ",");
                first=0;
                char tmp[128];
                snprintf(tmp, sizeof(tmp), "{\"id\":\"%s\",\"ts\":%ld}", e->id, (long)e->ts);
                strcat(out, tmp);
                e=e->next;
            }
            strcat(out, "]}");
            send_json(c->fd, out);
            // send note bodies too
            e = m->head;
            while (e) {
                char fpath[1024];
                snprintf(fpath, sizeof(fpath), DATA_DIR"/%s/%s.json", nick, e->id);
                FILE *f = fopen(fpath, "r");
                if (f) {
                    char buf[8192];
                    size_t r = fread(buf, 1, sizeof(buf)-1, f);
                    buf[r]=0;
                    fclose(f);
                    send_json(c->fd, buf);
                }
                e=e->next;
            }
            return;
        } else {
            send_json(c->fd, "{\"type\":\"ERROR\",\"reason\":\"unsupported fetch thread\"}");
            return;
        }
    }

    // unknown type => echo error
    send_json(c->fd, "{\"type\":\"ERROR\",\"reason\":\"unknown message\"}");
}

/* main loop */
int main(int argc, char **argv) {
    if (sodium_init() < 0) die("sodium_init");

    int port = PORT_DEFAULT;
    if (argc >= 2) port = atoi(argv[1]);

    ensure_data_dir();
    load_existing_data();

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) die("socket");
    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) die("bind");
    if (listen(listen_fd, 16) < 0) die("listen");
    set_nonblock(listen_fd);

    init_clients();

    struct pollfd pfds[MAX_CLIENTS+1];
    printf("Zettel server listening on port %d\n", port);

    while (1) {
        pfds[0].fd = listen_fd;
        pfds[0].events = POLLIN;
        int nfds = 1;
        for (int i=0;i<MAX_CLIENTS;i++) {
            if (clients[i].fd != -1) {
                pfds[nfds].fd = clients[i].fd;
                pfds[nfds].events = POLLIN;
                nfds++;
            }
        }
        int ret = poll(pfds, nfds, 1000);
        if (ret < 0) {
            if (errno == EINTR) continue;
            die("poll");
        }
        // new connections?
        if (pfds[0].revents & POLLIN) {
            struct sockaddr_in cli_addr;
            socklen_t clilen = sizeof(cli_addr);
            int fd = accept(listen_fd, (struct sockaddr*)&cli_addr, &clilen);
            if (fd >= 0) {
                set_nonblock(fd);
                int idx = add_client(fd, &cli_addr);
                if (idx >= 0) {
                    printf("client connected idx=%d fd=%d addr=%s\n", idx, fd, clients[idx].addr);
                } else {
                    printf("too many clients\n");
                    close(fd);
                }
            }
        }
        // handle clients
        int off = 1;
        for (int i=0;i<MAX_CLIENTS;i++) {
            if (clients[i].fd == -1) continue;
            int pol_index = off++;
            if (pfds[pol_index].revents & POLLIN) {
                // read available data
                char buf[4096];
                ssize_t r = recv(clients[i].fd, buf, sizeof(buf)-1, 0);
                if (r <= 0) {
                    printf("client disconnected idx=%d fd=%d\n", i, clients[i].fd);
                    remove_client(i);
                    continue;
                }
                // append to buffer and process lines
                if (clients[i].buflen + (size_t)r < sizeof(clients[i].buf)-1) {
                    memcpy(clients[i].buf + clients[i].buflen, buf, r);
                    clients[i].buflen += r;
                    clients[i].buf[clients[i].buflen]=0;
                    // process lines
                    char *line_start = clients[i].buf;
                    char *nl;
                    while ((nl = strchr(line_start, '\n')) != NULL) {
                        *nl = 0;
                        // trim \r
                        if (nl > line_start && nl[-1] == '\r') nl[-1]=0;
                        handle_message(i, line_start);
                        line_start = nl+1;
                    }
                    // shift remaining
                    size_t rem = clients[i].buf + clients[i].buflen - line_start;
                    memmove(clients[i].buf, line_start, rem);
                    clients[i].buflen = rem;
                    clients[i].buf[clients[i].buflen]=0;
                } else {
                    // buffer overflow
                    send_json(clients[i].fd, "{\"type\":\"ERROR\",\"reason\":\"message too long\"}");
                    clients[i].buflen = 0;
                }
            }
        }
    }
    return 0;
}
