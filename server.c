#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_NICK 255
#define MAX_ROOM 255
#define MAX_MSG  65535

struct Room;
struct Client;

typedef struct Client {
    int fd;
    char nick[MAX_NICK + 1];
    struct Room *room;
    struct Client *next_global;
    struct Client *next_in_room;
} Client;

typedef struct Room {
    char name[MAX_ROOM + 1];
    char password[MAX_ROOM + 1];
    Client *members;
    struct Room *next;
} Room;

static Client *clients_head = NULL;
static Client *clients_tail = NULL;
static Room   *rooms_head   = NULL;
static Room   *rooms_tail   = NULL;

static int next_rand_id = 0;

/* ============================================================
 * Utility
 * ============================================================ */
static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static void *xcalloc(size_t n, size_t s) {
    void *p = calloc(n, s);
    if (!p) die("calloc");
    return p;
}

static ssize_t read_exact(int fd, void *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = recv(fd, (uint8_t*)buf + off, n - off, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;         // real error
        }
        if (r == 0) return -1; // client closed connection
        off += r;
    }
    return off;
}

static ssize_t writen(int fd, const void *buf, size_t n) {
    const uint8_t *p = buf;
    size_t left = n;
    while (left > 0) {
        ssize_t r = write(fd, p, left);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return n - left;
        p += r;
        left -= r;
    }
    return n;
}

/* ============================================================
 * Client / Room management
 * ============================================================ */
static void remove_client(Client *c);

static void add_client(Client *c) {
    c->next_global = NULL;
    if (!clients_head) {
        clients_head = clients_tail = c;
    } else {
        clients_tail->next_global = c;
        clients_tail = c;
    }
    fprintf(stderr, "[DEBUG] add_client: fd=%d nick='%s'\n", c->fd, c->nick);
}

static Client *find_client_by_nick(const char *nick) {
    for (Client *cur = clients_head; cur; cur = cur->next_global) {
        if (strcmp(cur->nick, nick) == 0) return cur;
    }
    return NULL;
}

static Room *find_room_by_name(const char *name) {
    for (Room *r = rooms_head; r; r = r->next) {
        if (strcmp(r->name, name) == 0) return r;
    }
    return NULL;
}

static void add_room(Room *r) {
    r->next = NULL;
    if (!rooms_head) {
        rooms_head = rooms_tail = r;
    } else {
        rooms_tail->next = r;
        rooms_tail = r;
    }
    fprintf(stderr, "[DEBUG] add_room: name='%s' pass='%s'\n",
            r->name, r->password[0] ? r->password : "(none)");
}

static Room *get_or_create_room(const char *name, const char *pass) {
    Room *r = find_room_by_name(name);
    if (r) {
        fprintf(stderr, "[DEBUG] get_or_create_room: found existing room '%s'\n", name);
        return r;
    }

    r = xcalloc(1, sizeof(Room));
    strncpy(r->name, name, MAX_ROOM);
    r->name[MAX_ROOM] = '\0';

    if (pass) {
        strncpy(r->password, pass, MAX_ROOM);
        r->password[MAX_ROOM] = '\0';
    } else {
        r->password[0] = '\0';
    }

    add_room(r);
    return r;
}

/* Delete an empty room from the global room list */
static void delete_room(Room *r) {
    fprintf(stderr, "[DEBUG] delete_room: '%s'\n", r->name);

    Room **pp = &rooms_head;
    while (*pp) {
        if (*pp == r) {
            *pp = r->next;
            break;
        }
        pp = &(*pp)->next;
    }

    /* Rebuild rooms_tail */
    rooms_tail = NULL;
    for (Room *cur = rooms_head; cur; cur = cur->next) {
        if (!cur->next) rooms_tail = cur;
    }

    free(r);
}

static void room_add_client(Room *r, Client *c) {
    fprintf(stderr, "[DEBUG] room_add_client: nick='%s' → room='%s'\n",
            c->nick, r->name);
    c->next_in_room = NULL;
    if (!r->members) {
        r->members = c;
    } else {
        Client *cur = r->members;
        while (cur->next_in_room) cur = cur->next_in_room;
        cur->next_in_room = c;
    }
    c->room = r;
}

static void room_remove_client(Client *c) {
    if (!c->room) return;

    Room *r = c->room;
    fprintf(stderr, "[DEBUG] room_remove_client: nick='%s' from room='%s'\n",
            c->nick, r->name);

    Client **pp = &r->members;
    while (*pp) {
        if (*pp == c) {
            *pp = c->next_in_room;
            break;
        }
        pp = &(*pp)->next_in_room;
    }

    c->room = NULL;
    c->next_in_room = NULL;

    /* Delete room if empty */
    if (r->members == NULL) {
        delete_room(r);
    }
}

static void remove_client(Client *c) {
    fprintf(stderr, "[DEBUG] remove_client: fd=%d nick='%s'\n", c->fd, c->nick);
    room_remove_client(c);

    Client **pp = &clients_head;
    while (*pp) {
        if (*pp == c) {
            *pp = c->next_global;
            break;
        }
        pp = &(*pp)->next_global;
    }

    clients_tail = NULL;
    Client *t = clients_head;
    while (t) {
        if (!t->next_global) clients_tail = t;
        t = t->next_global;
    }

    close(c->fd);
    free(c);
}

/* ============================================================
 * BINARY PROTOCOL
 * ============================================================ */

static bool send_packet_raw(Client *c, uint8_t opcode,
                            const uint8_t *payload, uint32_t len)
{
    uint32_t be_len = htonl(len);

    uint8_t header[7];
    memcpy(header, &be_len, 4);
    header[4] = 0x04;
    header[5] = 0x17;
    header[6] = opcode;

    fprintf(stderr,
            "[DEBUG] send_packet_raw: fd=%d opcode=0x%02X len=%u\n",
            c->fd, opcode, len);

    if (writen(c->fd, header, 7) != 7)
        return false;

    if (len > 0 && payload != NULL) {
        if (writen(c->fd, payload, len) != (ssize_t)len)
            return false;
    }

    return true;
}

/* Status (0x9A): [type:1][optional text or encoded list...] */
static bool send_status(Client *c, uint8_t type, const char *text) {
    size_t tlen = text ? strlen(text) : 0;
    uint32_t len = 1 + (uint32_t)tlen;

    uint8_t *payload = xcalloc(len, 1);
    payload[0] = type;
    if (tlen > 0)
        memcpy(payload + 1, text, tlen);

    fprintf(stderr,
            "[DEBUG] send_status: fd=%d type=0x%02X text='%s'\n",
            c->fd, type, text ? text : "");

    bool ok = send_packet_raw(c, 0x9A, payload, len);
    free(payload);
    return ok;
}

static bool send_ok(Client *c) {
    return send_status(c, 0x00, NULL);
}

static bool send_error(Client *c, const char *msg) {
    return send_status(c, 0x01, msg);
}

/* Handshake response is just an OK-status with nickname text */
static bool send_handshake(Client *c) {
    fprintf(stderr, "[DEBUG] send_handshake: fd=%d nick='%s'\n", c->fd, c->nick);
    return send_status(c, 0x00, c->nick);
}

/* ============================================================
 * Room Broadcast
 * ============================================================ */

/* Room message (0x15):
 * [room_len:1][room][nick_len:1][nick][msg_len:2][msg]
 */
static bool send_room_message(Client *to, const char *room,
                              const char *nick, const char *msg)
{
    uint8_t roomlen = (uint8_t)strlen(room);
    uint8_t nicklen = (uint8_t)strlen(nick);
    uint16_t msglen = (uint16_t)strlen(msg);

    uint32_t payload_len = 1 + roomlen + 1 + nicklen + 2 + msglen;
    uint8_t *payload = xcalloc(payload_len, 1);

    size_t pos = 0;

    payload[pos++] = roomlen;
    memcpy(payload + pos, room, roomlen);
    pos += roomlen;

    payload[pos++] = nicklen;
    memcpy(payload + pos, nick, nicklen);
    pos += nicklen;

    payload[pos++] = (msglen >> 8) & 0xFF;
    payload[pos++] = msglen & 0xFF;

    memcpy(payload + pos, msg, msglen);

    fprintf(stderr,
            "[DEBUG] send_room_message: to_fd=%d room='%s' from='%s' msg='%s'\n",
            to->fd, room, nick, msg);

    bool ok = send_packet_raw(to, 0x15, payload, payload_len);
    free(payload);
    return ok;
}

/* ============================================================
 * Direct Message (DM) to client (opcode 0x12)
 * ============================================================ */
/* DM packet format (0x12), server->client:
 * [sender_len:1][sender][msg_len:2][msg]
 */
static bool send_dm_packet(Client *to, const char *from_nick,
                           const char *msg)
{
    uint8_t nlen = (uint8_t)strlen(from_nick);
    uint16_t mlen = (uint16_t)strlen(msg);

    uint32_t plen = 1 + nlen + 2 + mlen;
    uint8_t *buf = xcalloc(plen, 1);
    size_t pos = 0;

    buf[pos++] = nlen;
    memcpy(buf + pos, from_nick, nlen);
    pos += nlen;

    buf[pos++] = (mlen >> 8) & 0xFF;
    buf[pos++] = (mlen & 0xFF);

    memcpy(buf + pos, msg, mlen);

    fprintf(stderr,
            "[DEBUG] send_dm_packet: to_fd=%d from='%s' msg='%s'\n",
            to->fd, from_nick, msg);

    bool ok = send_packet_raw(to, 0x12, buf, plen);
    free(buf);
    return ok;
}

/* ============================================================
 * Receive
 * ============================================================ */

static bool recv_packet(Client *c, uint8_t *opcode,
                        uint8_t *payload, uint32_t *plen)
{
    uint8_t hdr[7];
    if (read_exact(c->fd, hdr, 7) != 7)
        return false;

    uint32_t len = (hdr[0] << 24) |
                   (hdr[1] << 16) |
                   (hdr[2] << 8)  |
                   (hdr[3]);

    fprintf(stderr,
            "[DEBUG] recv_packet: fd=%d raw_header len=%u ver=0x%02X 0x%02X opcode=0x%02X\n",
            c->fd, len, hdr[4], hdr[5], hdr[6]);

    if (hdr[4] != 0x04 || hdr[5] != 0x17) {
        fprintf(stderr,
                "[DEBUG] recv_packet: fd=%d bad version bytes (0x%02X,0x%02X)\n",
                c->fd, hdr[4], hdr[5]);
        return false;
    }

    *opcode = hdr[6];

    if (len > *plen) {
        fprintf(stderr,
                "[DEBUG] recv_packet: fd=%d payload too large len=%u max=%u\n",
                c->fd, len, *plen);
        return false;
    }

    if (len > 0) {
        if (read_exact(c->fd, payload, len) != (ssize_t)len)
            return false;
    }

    *plen = len;

    fprintf(stderr,
            "[DEBUG] recv_packet: fd=%d opcode=0x%02X payload_len=%u\n",
            c->fd, *opcode, *plen);

    return true;
}

/* ============================================================
 * Handlers
 * ============================================================ */

static void handle_nick(Client *c, const char *newnick) {
    fprintf(stderr,
            "[DEBUG] handle_nick: fd=%d old='%s' new='%s'\n",
            c->fd, c->nick, newnick ? newnick : "(null)");

    if (!newnick || !*newnick) return;

    Client *existing = find_client_by_nick(newnick);
    if (existing && existing != c) {
        fprintf(stderr,
                "[DEBUG] handle_nick: nick '%s' already in use\n",
                newnick);
        send_error(c, "That name's already on the Marauder's Map. Choose another.");
        return;
    }

    strncpy(c->nick, newnick, MAX_NICK);
    c->nick[MAX_NICK] = '\0';
    send_ok(c);
}

static void handle_join(Client *c, const char *room, const char *pass) {
    fprintf(stderr,
            "[DEBUG] handle_join: fd=%d nick='%s' room='%s' pass='%s'\n",
            c->fd, c->nick, room ? room : "(null)", pass ? pass : "(null)");

    if (!room || !*room) return;

    if (c->room && strcmp(c->room->name, room) == 0) {
        fprintf(stderr,
                "[DEBUG] handle_join: already in room '%s'\n", room);
        send_error(c, "You've already apparated into this room. No need for a Time-Turner.");
        return;
    }

    Room *r = find_room_by_name(room);
    if (!r) {
        fprintf(stderr,
                "[DEBUG] handle_join: room '%s' does not exist, creating\n",
                room);
        r = get_or_create_room(room, pass);
    } else {
        const char *stored = r->password;
        const char *given  = pass ? pass : "";
        if (stored[0] != '\0' || given[0] != '\0') {
            if (strcmp(stored, given) != 0) {
                fprintf(stderr,
                        "[DEBUG] handle_join: bad password for room '%s'\n",
                        room);
                send_error(c, "Incorrect password. Maybe try 'Alohomora'?");
                return;
            }
        }
    }

    if (c->room) room_remove_client(c);
    room_add_client(r, c);
    send_ok(c);
}

static void handle_leave(Client *c) {
    fprintf(stderr,
            "[DEBUG] handle_leave: fd=%d nick='%s' room='%s'\n",
            c->fd, c->nick, c->room ? c->room->name : "(none)");

    if (!c->room) {
        /* Match reference behavior: leaving when not in a room = disconnect */
        send_ok(c);
        remove_client(c);
        return;
    }

    room_remove_client(c);
    send_ok(c);
}

static bool send_user_list(Client *c, Client **users, int count) {
    /* Status payload format:
     * [type:1=0x00][ repeated { nick_len:1, nick } ... ]
     */
    uint32_t total = 1; /* type byte */
    for (int i = 0; i < count; i++) {
        size_t len = strlen(users[i]->nick);
        if (len > 255) len = 255;
        total += 1 + (uint32_t)len;
    }

    uint8_t *payload = xcalloc(total, 1);
    int pos = 0;

    payload[pos++] = 0x00; /* OK */

    for (int i = 0; i < count; i++) {
        size_t len = strlen(users[i]->nick);
        if (len > 255) len = 255;
        payload[pos++] = (uint8_t)len;
        memcpy(payload + pos, users[i]->nick, len);
        pos += (int)len;
    }

    fprintf(stderr,
            "[DEBUG] send_user_list: fd=%d count=%d total_bytes=%u\n",
            c->fd, count, total);

    bool ok = send_packet_raw(c, 0x9A, payload, total);
    free(payload);
    return ok;
}

static void handle_list_users(Client *c) {
    Client *list[1024];
    int count = 0;

    if (c->room) {
        for (Client *m = c->room->members; m; m = m->next_in_room)
            list[count++] = m;
        fprintf(stderr,
                "[DEBUG] handle_list_users: fd=%d in-room list, count=%d room='%s'\n",
                c->fd, count, c->room->name);
    } else {
        for (Client *m = clients_head; m; m = m->next_global)
            list[count++] = m;
        fprintf(stderr,
                "[DEBUG] handle_list_users: fd=%d global list, count=%d\n",
                c->fd, count);
    }

    send_user_list(c, list, count);
}

/*
 * Room list using the SAME status format as list-users:
 *
 * Status opcode 0x9A, payload:
 *   [type:1 = 0x00]
 *   then repeated:
 *      [room_len:1][room_name bytes]
 *
 * Example with one room "room":
 *   len = 6
 *   payload = 00 04 72 6f 6f 6d
 *
 * The client uses this to print:
 *   "List of rooms: room1 room2"
 */
static void handle_list_rooms(Client *c) {
    Room *rooms[1024];
    int count = 0;

    for (Room *r = rooms_head; r; r = r->next) {
        if (count < 1024) {
            rooms[count++] = r;
        }
    }

    uint32_t total = 1; /* type byte */
    for (int i = 0; i < count; i++) {
        size_t len = strlen(rooms[i]->name);
        if (len > 255) len = 255;
        total += 1 + (uint32_t)len;
    }

    uint8_t *payload = xcalloc(total, 1);
    int pos = 0;

    payload[pos++] = 0x00; /* OK */

    for (int i = 0; i < count; i++) {
        size_t len = strlen(rooms[i]->name);
        if (len > 255) len = 255;
        payload[pos++] = (uint8_t)len;
        memcpy(payload + pos, rooms[i]->name, len);
        pos += (int)len;
    }

    fprintf(stderr,
            "[DEBUG] handle_list_rooms: fd=%d count=%d total_bytes=%u\n",
            c->fd, count, total);

    /* Only a 0x9A status packet — no extra opcodes, so the client
       will not see an "Unexpected message type". */
    send_packet_raw(c, 0x9A, payload, total);
    free(payload);
}

static void handle_room_chat(Client *c, const char *msg) {
    fprintf(stderr,
            "[DEBUG] handle_room_chat: fd=%d nick='%s' room='%s' msg='%s'\n",
            c->fd, c->nick, c->room ? c->room->name : "(none)", msg);

    if (!c->room) {
        send_error(c, "You're talking to the walls. No one is here to listen.");
        return;
    }

    for (Client *m = c->room->members; m; m = m->next_in_room) {
        if (m == c) continue;
        send_room_message(m, c->room->name, c->nick, msg);
    }

    send_ok(c);
}

/* Direct message:
 * client -> server (opcode 0x12):
 *   [dest_len:1][dest][msg_len:2][msg]
 *
 * server behavior:
 *   - if dest not found: error to sender
 *   - if found:
 *       * send OK (status 0x9A type=0) to sender (no text)
 *       * send DM (opcode 0x12) to recipient:
 *           [sender_len:1][sender][msg_len:2][msg]
 */
static void handle_msg(Client *c, const char *dest, const char *text) {
    fprintf(stderr,
            "[DEBUG] handle_msg: fd=%d from='%s' to='%s' msg='%s'\n",
            c->fd, c->nick, dest ? dest : "(null)", text ? text : "(null)");

    Client *d = find_client_by_nick(dest);
    if (!d) {
        fprintf(stderr,
                "[DEBUG] handle_msg: dest nick '%s' not found\n",
                dest);
        send_error(c, "That wizard isn't here. Maybe try the Room of Requirement?");
        return;
    }

    send_ok(c);
    send_dm_packet(d, c->nick, text);
}

/* ============================================================
 * Dispatch
 * ============================================================ */

static void process_packet(Client *c, uint8_t opcode, uint8_t *p, uint32_t len) {
    fprintf(stderr,
            "[DEBUG] process_packet: fd=%d opcode=0x%02X len=%u\n",
            c->fd, opcode, len);

    switch (opcode) {

    case 0x9B: /* handshake request */
        send_handshake(c);
        break;

    case 0x0F: { /* nick */
        if (len < 1) {
            fprintf(stderr, "[DEBUG] process_packet nick: len<1\n");
            break;
        }
        uint8_t nlen = p[0];
        if (1 + nlen > len) {
            fprintf(stderr,
                    "[DEBUG] process_packet nick: bad lengths nlen=%u len=%u\n",
                    nlen, len);
            break;
        }

        char nick[MAX_NICK + 1];
        if (nlen > MAX_NICK) nlen = MAX_NICK;
        memcpy(nick, &p[1], nlen);
        nick[nlen] = '\0';

        handle_nick(c, nick);
        break;
    }

    case 0x03: { /* join */
        if (len < 1) {
            fprintf(stderr, "[DEBUG] process_packet join: len<1\n");
            break;
        }
        uint8_t rlen = p[0];
        if (1 + rlen + 1 > len) {
            fprintf(stderr,
                    "[DEBUG] process_packet join: bad room/pass lengths rlen=%u len=%u\n",
                    rlen, len);
            break;
        }

        uint8_t plen_off = 1 + rlen;
        uint8_t plen = p[plen_off];
        if (plen_off + 1 + plen > len) {
            fprintf(stderr,
                    "[DEBUG] process_packet join: bad plen=%u len=%u\n",
                    plen, len);
            break;
        }

        char room[MAX_ROOM + 1], pass[MAX_ROOM + 1];
        if (rlen > MAX_ROOM) rlen = MAX_ROOM;
        memcpy(room, &p[1], rlen);
        room[rlen] = '\0';

        if (plen > MAX_ROOM) plen = MAX_ROOM;
        memcpy(pass, &p[plen_off + 1], plen);
        pass[plen] = '\0';

        handle_join(c, room, pass);
        break;
    }

    case 0x15: { /* room chat from client */
        if (len < 3) {
            fprintf(stderr, "[DEBUG] process_packet room chat: len<3\n");
            break;
        }

        uint8_t rlen = p[0];
        if (1 + rlen + 2 > len) {
            fprintf(stderr,
                    "[DEBUG] process_packet room chat: bad lengths rlen=%u len=%u\n",
                    rlen, len);
            break;
        }

        uint16_t mlen = (uint16_t)((p[1 + rlen] << 8) | p[2 + rlen]);
        if (3 + rlen + mlen > len) {
            fprintf(stderr,
                    "[DEBUG] process_packet room chat: bad mlen=%u len=%u\n",
                    mlen, len);
            break;
        }
        if (mlen > MAX_MSG) mlen = MAX_MSG;

        char msg[MAX_MSG + 1];
        memcpy(msg, p + 3 + rlen, mlen);
        msg[mlen] = '\0';

        handle_room_chat(c, msg);
        break;
    }

    case 0x12: { /* direct message from client */
        if (len < 3) {
            fprintf(stderr, "[DEBUG] process_packet DM: len<3\n");
            break;
        }
        uint8_t nlen = p[0];
        if (nlen == 0 || 1 + nlen + 2 > len) {
            fprintf(stderr,
                    "[DEBUG] process_packet DM: bad nlen=%u len=%u\n",
                    nlen, len);
            break;
        }

        char dest[MAX_NICK + 1];
        if (nlen > MAX_NICK) nlen = MAX_NICK;
        memcpy(dest, &p[1], nlen);
        dest[nlen] = '\0';

        uint16_t mlen = (uint16_t)((p[1 + nlen] << 8) | p[2 + nlen]);
        if (3 + nlen + mlen > len) {
            fprintf(stderr,
                    "[DEBUG] process_packet DM: bad mlen=%u len=%u\n",
                    mlen, len);
            break;
        }
        if (mlen > MAX_MSG) mlen = MAX_MSG;

        char msg[MAX_MSG + 1];
        memcpy(msg, p + 3 + nlen, mlen);
        msg[mlen] = '\0';

        handle_msg(c, dest, msg);
        break;
    }

    case 0x09: /* list rooms */
        handle_list_rooms(c);
        break;

    case 0x0C: /* list users */
        handle_list_users(c);
        break;

    case 0x06: /* leave */
        handle_leave(c);
        break;

    default:
        fprintf(stderr,
                "[DEBUG] process_packet: fd=%d unknown opcode=0x%02X, ignoring\n",
                c->fd, opcode);
        break;
    }
}

/* ============================================================
 * Main
 * ============================================================ */

int main(int argc, char **argv) {
    if (argc != 3 || strcmp(argv[1], "-p") != 0) {
        fprintf(stderr, "Usage: %s -p <port>\n", argv[0]);
        return 1;
    }

    int port = atoi(argv[2]);
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) die("socket");

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof addr) < 0)
        die("bind");
    if (listen(listen_fd, 32) < 0)
        die("listen");

    fprintf(stderr, "Server listening on port %d\n", port);

    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(listen_fd, &rfds);
        int maxfd = listen_fd;

        for (Client *c = clients_head; c; c = c->next_global) {
            FD_SET(c->fd, &rfds);
            if (c->fd > maxfd) maxfd = c->fd;
        }

        if (select(maxfd + 1, &rfds, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            die("select");
        }

        if (FD_ISSET(listen_fd, &rfds)) {
            int fd = accept(listen_fd, NULL, NULL);
            if (fd >= 0) {
                Client *c = xcalloc(1, sizeof(Client));
                c->fd = fd;
                snprintf(c->nick, sizeof(c->nick), "rand%d", next_rand_id++);
                fprintf(stderr,
                        "[DEBUG] new client connected: fd=%d nick='%s'\n",
                        fd, c->nick);
                add_client(c);
            } else {
                fprintf(stderr,
                        "[DEBUG] accept failed: errno=%d\n", errno);
            }
        }

        Client *next;
        for (Client *c = clients_head; c; c = next) {
            next = c->next_global;

            if (!FD_ISSET(c->fd, &rfds)) continue;

            uint8_t opcode;
            uint8_t buf[MAX_MSG];
            uint32_t blen = sizeof buf;

            if (!recv_packet(c, &opcode, buf, &blen)) {
                fprintf(stderr,
                        "[DEBUG] main loop: recv_packet failed, removing client fd=%d nick='%s'\n",
                        c->fd, c->nick);
                remove_client(c);
                continue;
            }

            process_packet(c, opcode, buf, blen);
        }
    }
}
