// src/network/network.c
#include "network.h"
#include "../utils/logger.h"
#include "../utils/colors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

static int g_listener_socket_fd = -1;
static Peer g_connected_peers[MAX_PEERS];
static size_t g_num_connected_peers = 0;

static pthread_t g_listener_thread;
static volatile bool g_listener_should_exit = false;
static bool g_listener_thread_running = false;

static void peer_add(int socket_fd, struct sockaddr_in addr) {
    if (g_num_connected_peers < MAX_PEERS) {
        g_connected_peers[g_num_connected_peers].socket_fd = socket_fd;
        g_connected_peers[g_num_connected_peers].address = addr;
        g_connected_peers[g_num_connected_peers].is_connected = true;
        g_num_connected_peers++;
        logger_log(LOG_LEVEL_INFO, "Peer added: %s:%d (FD: %d). Total peers: %zu",
                   inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), socket_fd, g_num_connected_peers);
    } else {
        logger_log(LOG_LEVEL_WARN, "Max peers reached, cannot add new peer (FD: %d).", socket_fd);
        close(socket_fd);
    }
}

static void peer_remove(int socket_fd) {
    for (size_t i = 0; i < g_num_connected_peers; ++i) {
        if (g_connected_peers[i].socket_fd == socket_fd) {
            close(socket_fd);
            g_connected_peers[i].is_connected = false;
            logger_log(LOG_LEVEL_INFO, "Peer removed: %s:%d (FD: %d).",
                       inet_ntoa(g_connected_peers[i].address.sin_addr),
                       ntohs(g_connected_peers[i].address.sin_port), socket_fd);

            for (size_t j = i; j < g_num_connected_peers - 1; ++j) {
                g_connected_peers[j] = g_connected_peers[j+1];
            }
            g_num_connected_peers--;
            return;
        }
    }
    logger_log(LOG_LEVEL_WARN, "Attempted to remove non-existent peer with FD: %d.", socket_fd);
}

static void* listener_thread_func(void* arg) {
    int port = *(int*)arg;
    free(arg);

    logger_log(LOG_LEVEL_INFO, "Listener thread started on port %d.", port);

    g_listener_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listener_socket_fd == -1) {
        logger_log(LOG_LEVEL_ERROR, "Listener thread: Failed to create listener socket: %s", strerror(errno));
        g_listener_thread_running = false;
        return NULL;
    }

    int optval = 1;
    if (setsockopt(g_listener_socket_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        logger_log(LOG_LEVEL_ERROR, "Listener thread: Failed to set socket options: %s", strerror(errno));
        close(g_listener_socket_fd);
        g_listener_socket_fd = -1;
        g_listener_thread_running = false;
        return NULL;
    }

    if (fcntl(g_listener_socket_fd, F_SETFL, O_NONBLOCK) == -1) {
        logger_log(LOG_LEVEL_ERROR, "Listener thread: Failed to set listener socket to non-blocking: %s", strerror(errno));
        close(g_listener_socket_fd);
        g_listener_socket_fd = -1;
        g_listener_thread_running = false;
        return NULL;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(g_listener_socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        logger_log(LOG_LEVEL_ERROR, "Listener thread: Failed to bind listener socket to port %d: %s", port, strerror(errno));
        close(g_listener_socket_fd);
        g_listener_socket_fd = -1;
        g_listener_thread_running = false;
        return NULL;
    }

    if (listen(g_listener_socket_fd, 5) == -1) {
        logger_log(LOG_LEVEL_ERROR, "Listener thread: Failed to listen on socket: %s", strerror(errno));
        close(g_listener_socket_fd);
        g_listener_socket_fd = -1;
        g_listener_thread_running = false;
        return NULL;
    }

    logger_log(LOG_LEVEL_INFO, "Listener thread: Network listener active on port %d. Waiting for connections...", port);

    fd_set master_fds;
    FD_ZERO(&master_fds);
    FD_SET(g_listener_socket_fd, &master_fds);

    int max_fd = g_listener_socket_fd;

    while (!g_listener_should_exit) {
        fd_set read_fds = master_fds;
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);

        if (activity < 0) {
            if (errno == EINTR) {
                continue;
            }
            logger_log(LOG_LEVEL_ERROR, "Listener thread: Select error: %s", strerror(errno));
            break;
        }

        if (activity == 0) {
            continue;
        }

        if (FD_ISSET(g_listener_socket_fd, &read_fds)) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int client_sock_fd = accept(g_listener_socket_fd, (struct sockaddr*)&client_addr, &client_len);

            if (client_sock_fd == -1) {
                if (errno == EWOULDBLOCK || errno == EAGAIN) {
                    continue;
                }
                logger_log(LOG_LEVEL_ERROR, "Listener thread: Failed to accept new connection: %s", strerror(errno));
                break;
            }

            if (fcntl(client_sock_fd, F_SETFL, O_NONBLOCK) == -1) {
                logger_log(LOG_LEVEL_ERROR, "Listener thread: Failed to set client socket to non-blocking: %s", strerror(errno));
                close(client_sock_fd);
                continue;
            }

            peer_add(client_sock_fd, client_addr);
            logger_log(LOG_LEVEL_INFO, "Listener thread: Accepted new connection from %s:%d. FD: %d",
                                       inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), client_sock_fd);
            print_green("Accepted new connection from %s:%d.\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

            FD_SET(client_sock_fd, &master_fds);
            if (client_sock_fd > max_fd) {
                max_fd = client_sock_fd;
            }
        }

        for (size_t i = 0; i < MAX_PEERS; ++i) {
            if (g_connected_peers[i].is_connected) {
                int current_peer_fd = g_connected_peers[i].socket_fd;

                if (current_peer_fd != -1 && FD_ISSET(current_peer_fd, &read_fds)) {
                    uint8_t buffer[1024];
                    ssize_t bytes_received = network_receive_message(current_peer_fd, buffer, sizeof(buffer) - 1);

                    if (bytes_received > 0) {
                        buffer[bytes_received] = '\0';
                        logger_log(LOG_LEVEL_INFO, "Listener thread: Received message from FD %d: \"%s\"", current_peer_fd, buffer);
                        print_cyan("Received message from peer %s:%d: \"%s\"\n",
                                   inet_ntoa(g_connected_peers[i].address.sin_addr),
                                   ntohs(g_connected_peers[i].address.sin_port),
                                   buffer);
                    } else {
                        FD_CLR(current_peer_fd, &master_fds);
                        logger_log(LOG_LEVEL_INFO, "Listener thread: Cleared FD %d from master_fds (disconnected/error).", current_peer_fd);

                        if (current_peer_fd == max_fd) {
                            max_fd = g_listener_socket_fd;
                            for (size_t j = 0; j < MAX_PEERS; ++j) {
                                if (g_connected_peers[j].is_connected && g_connected_peers[j].socket_fd > max_fd) {
                                    max_fd = g_connected_peers[j].socket_fd;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if (g_listener_socket_fd != -1) {
        close(g_listener_socket_fd);
        FD_CLR(g_listener_socket_fd, &master_fds);
        g_listener_socket_fd = -1;
        logger_log(LOG_LEVEL_INFO, "Listener thread: Listener socket closed.");
    }
    logger_log(LOG_LEVEL_INFO, "Listener thread: Exiting.");
    g_listener_thread_running = false;
    return NULL;
}

int network_init() {
    for (size_t i = 0; i < MAX_PEERS; ++i) {
        g_connected_peers[i].socket_fd = -1;
        g_connected_peers[i].is_connected = false;
        memset(&g_connected_peers[i].address, 0, sizeof(struct sockaddr_in));
    }
    g_num_connected_peers = 0;
    g_listener_should_exit = false;
    g_listener_thread_running = false;
    logger_log(LOG_LEVEL_INFO, "Network module initialized.");
    return 0;
}

int network_start_listener(int port) {
    if (g_listener_thread_running) {
        logger_log(LOG_LEVEL_WARN, "Listener is already running.");
        print_yellow("Listener is already running on port %d.\n", port);
        return -1;
    }

    int* thread_port = malloc(sizeof(int));
    if (!thread_port) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for listener thread port.");
        print_red("Error: Failed to allocate memory for listener thread.\n");
        return -1;
    }
    *thread_port = port;

    g_listener_should_exit = false;

    if (pthread_create(&g_listener_thread, NULL, listener_thread_func, thread_port) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to create listener thread: %s", strerror(errno));
        print_red("Error: Failed to create listener thread.\n");
        free(thread_port);
        return -1;
    }

    g_listener_thread_running = true;
    logger_log(LOG_LEVEL_INFO, "Listener thread successfully launched for port %d.", port);
    print_green("Network listener thread launched on port %d.\n", port);
    return 0;
}

int network_connect_to_peer(const char* ip_address, int port) {
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        logger_log(LOG_LEVEL_ERROR, "Failed to create client socket for %s:%d: %s", ip_address, port, strerror(errno));
        print_red("Error: Failed to create client socket for %s:%d.\n", ip_address, port);
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip_address, &server_addr.sin_addr) <= 0) {
        logger_log(LOG_LEVEL_ERROR, "Invalid IP address %s: %s", ip_address, strerror(errno));
        print_red("Error: Invalid IP address '%s'.\n", ip_address);
        close(sock_fd);
        return -1;
    }

    if (connect(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        logger_log(LOG_LEVEL_ERROR, "Failed to connect to peer %s:%d: %s", ip_address, port, strerror(errno));
        print_red("Error: Failed to connect to peer %s:%d.\n", ip_address, port);
        close(sock_fd);
        return -1;
    }

    peer_add(sock_fd, server_addr);
    logger_log(LOG_LEVEL_INFO, "Successfully connected to peer %s:%d (FD: %d).", ip_address, port, sock_fd);
    print_green("Successfully connected to peer %s:%d.\n", ip_address, port);
    return 0;
}

ssize_t network_send_message(int peer_socket_fd, const uint8_t* message, size_t message_len) {
    if (peer_socket_fd == -1 || message == NULL || message_len == 0) {
        logger_log(LOG_LEVEL_ERROR, "Invalid arguments for network_send_message.");
        return -1;
    }

    ssize_t bytes_sent = send(peer_socket_fd, message, message_len, 0);
    if (bytes_sent == -1) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
             logger_log(LOG_LEVEL_WARN, "Send buffer full for FD %d. Try again later.", peer_socket_fd);
             return 0;
        }
        logger_log(LOG_LEVEL_ERROR, "Failed to send message to FD %d: %s", peer_socket_fd, strerror(errno));
        peer_remove(peer_socket_fd);
    } else if ((size_t)bytes_sent < message_len) {
        logger_log(LOG_LEVEL_WARN, "Partial message sent to FD %d. Sent %zd of %zu bytes.",
                   peer_socket_fd, bytes_sent, message_len);
    } else {
        logger_log(LOG_LEVEL_DEBUG, "Sent %zd bytes to FD %d.", bytes_sent, peer_socket_fd);
    }
    return bytes_sent;
}

ssize_t network_receive_message(int peer_socket_fd, uint8_t* buffer, size_t buffer_len) {
    if (peer_socket_fd == -1 || buffer == NULL || buffer_len == 0) {
        logger_log(LOG_LEVEL_ERROR, "Invalid arguments for network_receive_message.");
        return -1;
    }

    ssize_t bytes_received = recv(peer_socket_fd, buffer, buffer_len, 0);
    if (bytes_received == -1) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            return 0;
        }
        logger_log(LOG_LEVEL_ERROR, "Failed to receive message from FD %d: %s", peer_socket_fd, strerror(errno));
        peer_remove(peer_socket_fd);
        return -1;
    } else if (bytes_received == 0) {
        logger_log(LOG_LEVEL_INFO, "Peer FD %d disconnected gracefully.", peer_socket_fd);
        peer_remove(peer_socket_fd);
        return 0;
    } else {
        logger_log(LOG_LEVEL_DEBUG, "Received %zd bytes from FD %d.", bytes_received, peer_socket_fd);
    }
    return bytes_received;
}

int network_get_first_peer_socket_fd() {
    for (size_t i = 0; i < g_num_connected_peers; ++i) {
        if (g_connected_peers[i].is_connected) {
            return g_connected_peers[i].socket_fd;
        }
    }
    return -1;
}

void network_shutdown() {
    logger_log(LOG_LEVEL_INFO, "Shutting down network module...");
    print_cyan("Shutting down network module...\n");

    if (g_listener_thread_running) {
        logger_log(LOG_LEVEL_INFO, "Signaling listener thread to exit.");
        g_listener_should_exit = true;
        pthread_join(g_listener_thread, NULL);
        logger_log(LOG_LEVEL_INFO, "Listener thread joined successfully.");
    } else {
        logger_log(LOG_LEVEL_INFO, "Listener thread was not running.");
    }

    if (g_listener_socket_fd != -1) {
        close(g_listener_socket_fd);
        g_listener_socket_fd = -1;
        logger_log(LOG_LEVEL_INFO, "Listener socket (residual close) closed.");
    }

    for (size_t i = 0; i < MAX_PEERS; ++i) {
        if (g_connected_peers[i].is_connected) {
            close(g_connected_peers[i].socket_fd);
            g_connected_peers[i].socket_fd = -1;
            g_connected_peers[i].is_connected = false;
        }
    }
    g_num_connected_peers = 0;
    logger_log(LOG_LEVEL_INFO, "All peer connections closed.");
    print_green("Network module shut down successfully.\n");
}

/**
 * @brief Broadcasts data of a specific message type to all connected peers.
 */
int network_broadcast_data(MessageType type, const uint8_t* data, size_t data_len) {
    if (data == NULL || data_len == 0) {
        logger_log(LOG_LEVEL_WARN, "network_broadcast_data: No data or zero length provided for broadcast.");
        return 0; // Nothing to broadcast
    }

    if (g_num_connected_peers == 0) {
        logger_log(LOG_LEVEL_INFO, "network_broadcast_data: No peers to broadcast to.");
        return 0;
    }

    // Allocate a buffer that can hold the message type + data
    // The type is an int, so it needs 4 bytes
    size_t total_message_len = sizeof(MessageType) + data_len;
    uint8_t* full_message = (uint8_t*)malloc(total_message_len);
    if (full_message == NULL) {
        logger_log(LOG_LEVEL_ERROR, "network_broadcast_data: Failed to allocate memory for broadcast message.");
        return -1;
    }

    // Copy message type to the beginning of the buffer
    memcpy(full_message, &type, sizeof(MessageType));
    // Copy data payload after the message type
    memcpy(full_message + sizeof(MessageType), data, data_len);

    int peers_sent_to = 0;
    for (size_t i = 0; i < MAX_PEERS; ++i) {
        if (g_connected_peers[i].is_connected) {
            ssize_t sent = network_send_message(g_connected_peers[i].socket_fd, full_message, total_message_len);
            if (sent > 0) { // Consider it sent if any bytes were written
                peers_sent_to++;
                logger_log(LOG_LEVEL_DEBUG, "Broadcasted %zu bytes (Type: %d) to peer FD %d.", total_message_len, type, g_connected_peers[i].socket_fd);
            } else if (sent == -1) {
                logger_log(LOG_LEVEL_ERROR, "Failed to broadcast data to peer FD %d (error occurred).", g_connected_peers[i].socket_fd);
                // peer_remove is already called by network_send_message on error, so no explicit call here.
            } else { // sent == 0, meaning EWOULDBLOCK/EAGAIN
                logger_log(LOG_LEVEL_WARN, "Could not broadcast data to peer FD %d (send buffer full).", g_connected_peers[i].socket_fd);
            }
        }
    }

    free(full_message);
    logger_log(LOG_LEVEL_INFO, "Broadcasted data (Type: %d, Len: %zu) to %d peers.", type, data_len, peers_sent_to);
    return peers_sent_to;
}
