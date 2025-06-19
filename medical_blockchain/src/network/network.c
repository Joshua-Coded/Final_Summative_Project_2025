// src/network/network.c
#include "network.h"
#include "../utils/logger.h"
#include "../utils/colors.h"
#include "../core/blockchain.h" // For adding blocks/transactions
#include "../core/transaction.h" // For deserializing transactions
#include "../core/mempool.h"    // For adding transactions to mempool

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>     // For close()
#include <errno.h>      // For errno and strerror()
#include <fcntl.h>      // For fcntl() and O_NONBLOCK

// For socket addresses (inet_ntoa)
#include <arpa/inet.h>  // For htons, ntohs, inet_ntoa, inet_pton
#include <netinet/in.h> // For sockaddr_in

static int g_listener_socket_fd = -1;
static Peer g_connected_peers[MAX_PEERS];
static size_t g_num_connected_peers = 0;

static pthread_t g_listener_thread;
static volatile bool g_listener_should_exit = false;
static bool g_listener_thread_running = false;

// Forward declaration for internal use
static void peer_add(int socket_fd, struct sockaddr_in addr);
static void peer_remove(int socket_fd);
static ssize_t network_read_bytes(int peer_socket_fd, uint8_t* buffer, size_t bytes_to_read);
static ssize_t network_write_bytes(int peer_socket_fd, const uint8_t* buffer, size_t bytes_to_write);


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

            // Shift remaining elements to fill the gap
            for (size_t j = i; j < g_num_connected_peers - 1; ++j) {
                g_connected_peers[j] = g_connected_peers[j+1];
            }
            g_num_connected_peers--;
            return;
        }
    }
    logger_log(LOG_LEVEL_WARN, "Attempted to remove non-existent peer with FD: %d.", socket_fd);
}

/**
 * @brief Reads a specific number of bytes from a socket, handling partial reads.
 * This is a blocking read, but the overall listener thread is non-blocking with select().
 *
 * @param peer_socket_fd The socket to read from.
 * @param buffer The buffer to store the received bytes.
 * @param bytes_to_read The exact number of bytes to read.
 * @return The number of bytes successfully read, 0 if connection closed, or -1 on error.
 */
static ssize_t network_read_bytes(int peer_socket_fd, uint8_t* buffer, size_t bytes_to_read) {
    size_t total_bytes_read = 0;
    while (total_bytes_read < bytes_to_read) {
        ssize_t bytes_received = recv(peer_socket_fd, buffer + total_bytes_read, bytes_to_read - total_bytes_read, 0);
        if (bytes_received == -1) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                // No data currently available. Return what we've read so far.
                // Or if at the start, indicate no data. For blocking, this wouldn't happen.
                // For non-blocking: it means we need more data, but it's not here yet.
                // Given select() will tell us if there's data, this case means something is wrong
                // or we are in a partial read scenario and the rest isn't there yet.
                // For simplified logic, if no new bytes were read, treat it as "no data".
                if (total_bytes_read == 0) return 0;
                break; // Exit if no more data immediately available
            }
            logger_log(LOG_LEVEL_ERROR, "Failed to receive bytes from FD %d: %s", peer_socket_fd, strerror(errno));
            peer_remove(peer_socket_fd);
            return -1; // Error
        } else if (bytes_received == 0) {
            logger_log(LOG_LEVEL_INFO, "Peer FD %d disconnected gracefully during read.", peer_socket_fd);
            peer_remove(peer_socket_fd);
            return 0; // Connection closed
        }
        total_bytes_read += bytes_received;
    }
    return total_bytes_read;
}

/**
 * @brief Writes a specific number of bytes to a socket, handling partial writes.
 *
 * @param peer_socket_fd The socket to write to.
 * @param buffer The buffer containing bytes to send.
 * @param bytes_to_write The exact number of bytes to write.
 * @return The number of bytes successfully written, 0 if send buffer full, or -1 on error.
 */
static ssize_t network_write_bytes(int peer_socket_fd, const uint8_t* buffer, size_t bytes_to_write) {
    size_t total_bytes_sent = 0;
    while (total_bytes_sent < bytes_to_write) {
        ssize_t bytes_sent = send(peer_socket_fd, buffer + total_bytes_sent, bytes_to_write - total_bytes_sent, 0);
        if (bytes_sent == -1) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                logger_log(LOG_LEVEL_WARN, "Send buffer full for FD %d. Sent %zu of %zu bytes. Try again later.",
                           peer_socket_fd, total_bytes_sent, bytes_to_write);
                return total_bytes_sent; // Indicate partial send, not an error
            }
            logger_log(LOG_LEVEL_ERROR, "Failed to send bytes to FD %d: %s", peer_socket_fd, strerror(errno));
            peer_remove(peer_socket_fd);
            return -1; // Error
        } else if (bytes_sent == 0) {
            logger_log(LOG_LEVEL_INFO, "Peer FD %d disconnected gracefully during write (0 bytes sent).", peer_socket_fd);
            peer_remove(peer_socket_fd);
            return -1; // Peer disconnected
        }
        total_bytes_sent += bytes_sent;
    }
    return total_bytes_sent;
}

/**
 * @brief Sends a full message (header + payload) to a connected peer.
 * This function handles message framing by prepending a header with type and length.
 *
 * @param peer_socket_fd The socket file descriptor of the peer.
 * @param type The type of the message (from MessageType enum).
 * @param payload The raw data payload to send.
 * @param payload_len The length of the data payload in bytes.
 * @return The total number of bytes successfully sent (header + payload), or -1 on error.
 */
ssize_t network_send_full_message(int peer_socket_fd, MessageType type, const uint8_t* payload, size_t payload_len) {
    if (peer_socket_fd == -1 || payload == NULL || payload_len == 0) {
        logger_log(LOG_LEVEL_ERROR, "Invalid arguments for network_send_full_message (type %d, len %zu).", type, payload_len);
        return -1;
    }

    // Construct header
    MessageHeader header;
    header.type = htonl(type); // Convert to network byte order
    header.payload_len = htonl(payload_len); // Convert to network byte order

    // Calculate total size
    size_t total_size = sizeof(MessageHeader) + payload_len;
    uint8_t* full_message_buffer = (uint8_t*)malloc(total_size);
    if (full_message_buffer == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for full message buffer (type %d, len %zu).", type, payload_len);
        return -1;
    }

    // Copy header and payload into a single buffer
    memcpy(full_message_buffer, &header, sizeof(MessageHeader));
    memcpy(full_message_buffer + sizeof(MessageHeader), payload, payload_len);

    // Send the entire message (header + payload)
    ssize_t bytes_sent = network_write_bytes(peer_socket_fd, full_message_buffer, total_size);

    free(full_message_buffer); // Free the temporary buffer

    if (bytes_sent == (ssize_t)total_size) {
        logger_log(LOG_LEVEL_DEBUG, "Successfully sent %zd bytes (Type: %d, Payload Len: %zu) to FD %d.",
                   bytes_sent, type, payload_len, peer_socket_fd);
    } else if (bytes_sent >= 0) {
        logger_log(LOG_LEVEL_WARN, "Partial send of message (Type: %d, Payload Len: %zu) to FD %d. Sent %zd of %zu bytes.",
                   type, payload_len, peer_socket_fd, bytes_sent, total_size);
    } // else bytes_sent is -1 (error), already logged by network_write_bytes

    return bytes_sent;
}


/**
 * @brief Receives a full message (header + payload) from a connected peer.
 * This function handles message framing by reading the header first, then the payload.
 *
 * @param peer_socket_fd The socket file descriptor of the peer.
 * @param out_type A pointer to store the received MessageType.
 * @param out_payload A pointer to a uint8_t* which will be allocated to hold the received payload.
 * The caller is responsible for freeing this memory.
 * @param out_payload_len A pointer to store the length of the received payload.
 * @return The total number of bytes successfully received (header + payload), 0 if no data
 * is immediately available (non-blocking), or -1 on error/disconnection.
 */
ssize_t network_receive_full_message(int peer_socket_fd, MessageType* out_type, uint8_t** out_payload, size_t* out_payload_len) {
    if (peer_socket_fd == -1 || out_type == NULL || out_payload == NULL || out_payload_len == NULL) {
        logger_log(LOG_LEVEL_ERROR, "Invalid arguments for network_receive_full_message.");
        return -1;
    }

    *out_payload = NULL;
    *out_payload_len = 0;
    *out_type = MSG_TYPE_UNKNOWN;

    MessageHeader header;
    ssize_t header_bytes_read = network_read_bytes(peer_socket_fd, (uint8_t*)&header, sizeof(MessageHeader));

    if (header_bytes_read == 0) {
        // No data immediately available (non-blocking) or graceful disconnect
        return 0;
    }
    if (header_bytes_read == -1) {
        // Error during read, peer_remove already handled
        return -1;
    }
    if (header_bytes_read < (ssize_t)sizeof(MessageHeader)) {
        logger_log(LOG_LEVEL_WARN, "Partial header received from FD %d. Expected %zu, got %zd.",
                   peer_socket_fd, sizeof(MessageHeader), header_bytes_read);
        // This is a problematic state. For simplicity, treat as error for now.
        // In a real system, you'd buffer partial messages.
        peer_remove(peer_socket_fd); // Assuming partial header means corruption or problem
        return -1;
    }

    // Convert from network byte order to host byte order
    *out_type = (MessageType)ntohl(header.type);
    size_t payload_len = ntohl(header.payload_len);
    *out_payload_len = payload_len;

    if (payload_len > 0) {
        *out_payload = (uint8_t*)malloc(payload_len);
        if (*out_payload == NULL) {
            logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for received payload (len %zu).", payload_len);
            peer_remove(peer_socket_fd);
            return -1;
        }

        ssize_t payload_bytes_read = network_read_bytes(peer_socket_fd, *out_payload, payload_len);
        if (payload_bytes_read == -1) {
            free(*out_payload); *out_payload = NULL;
            return -1;
        }
        if (payload_bytes_read < (ssize_t)payload_len) {
            logger_log(LOG_LEVEL_WARN, "Partial payload received from FD %d. Expected %zu, got %zd.",
                       peer_socket_fd, payload_len, payload_bytes_read);
            // Treat as error, free partially received payload
            free(*out_payload); *out_payload = NULL;
            peer_remove(peer_socket_fd);
            return -1;
        }
    } else {
        *out_payload = NULL; // No payload for 0 length
    }

    logger_log(LOG_LEVEL_DEBUG, "Received full message (Type: %d, Payload Len: %zu) from FD %d.",
               *out_type, *out_payload_len, peer_socket_fd);

    return (ssize_t)(sizeof(MessageHeader) + *out_payload_len);
}


// --- Message Handling Logic ---
void network_handle_received_message(MessageType type, const uint8_t* payload, size_t payload_len) {
    logger_log(LOG_LEVEL_DEBUG, "Handling message Type: %d, Payload Len: %zu", type, payload_len);

    switch (type) {
        case MSG_TYPE_TEST_MESSAGE: {
            // Assuming test messages are null-terminated strings
            char msg[payload_len + 1];
            memcpy(msg, payload, payload_len);
            msg[payload_len] = '\0'; // Ensure null-termination
            logger_log(LOG_LEVEL_INFO, "Received TEST MESSAGE: \"%s\"", msg);
            print_cyan("Received TEST MESSAGE from peer: \"%s\"\n", msg);
            break;
        }
        case MSG_TYPE_TRANSACTION: {
            logger_log(LOG_LEVEL_INFO, "Received TRANSACTION message.");
            Transaction* received_tx = transaction_deserialize(payload, payload_len);
            if (received_tx) {
                if (transaction_is_valid(received_tx) == 0) {
                    if (mempool_add_transaction(received_tx)) {
                        logger_log(LOG_LEVEL_INFO, "Received and added transaction %s to mempool.", received_tx->transaction_id);
                        print_green("Received transaction %s and added to mempool.\n", received_tx->transaction_id);
                    } else {
                        logger_log(LOG_LEVEL_WARN, "Received transaction %s but failed to add to mempool (duplicate/full).", received_tx->transaction_id);
                        transaction_destroy(received_tx); // Destroy if not added
                    }
                } else {
                    logger_log(LOG_LEVEL_WARN, "Received invalid transaction %s. Discarding.", received_tx->transaction_id);
                    transaction_destroy(received_tx); // Destroy invalid transaction
                }
            } else {
                logger_log(LOG_LEVEL_ERROR, "Failed to deserialize received transaction payload.");
            }
            break;
        }
        case MSG_TYPE_BLOCK: {
            logger_log(LOG_LEVEL_INFO, "Received BLOCK message (handling not fully implemented yet).");
            // Placeholder for block handling logic:
            // 1. Deserialize block
            // 2. Validate block
            // 3. Add to blockchain (handle potential chain forks/sync)
            print_cyan("Received BLOCK message from peer (processing logic to be implemented).\n");
            break;
        }
        default: {
            logger_log(LOG_LEVEL_WARN, "Received UNKNOWN message type: %d.", type);
            print_yellow("Received UNKNOWN message type %d from peer.\n", type);
            break;
        }
    }
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
    server_addr.sin_addr.s_addr = INADDR_ANY; // Listen on all available interfaces
    server_addr.sin_port = htons(port);

    if (bind(g_listener_socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        logger_log(LOG_LEVEL_ERROR, "Listener thread: Failed to bind listener socket to port %d: %s", port, strerror(errno));
        close(g_listener_socket_fd);
        g_listener_socket_fd = -1;
        g_listener_thread_running = false;
        return NULL;
    }

    if (listen(g_listener_socket_fd, 5) == -1) { // 5 is typical backlog queue size
        logger_log(LOG_LEVEL_ERROR, "Listener thread: Failed to listen on socket: %s", strerror(errno));
        close(g_listener_socket_fd);
        g_listener_socket_fd = -1;
        g_listener_thread_running = false;
        return NULL;
    }

    logger_log(LOG_LEVEL_INFO, "Listener thread: Network listener active on port %d. Waiting for connections...", port);

    fd_set master_fds; // Master set of file descriptors
    FD_ZERO(&master_fds);
    FD_SET(g_listener_socket_fd, &master_fds); // Add listener socket to master set

    int max_fd = g_listener_socket_fd; // Keep track of the highest file descriptor number

    while (!g_listener_should_exit) {
        fd_set read_fds = master_fds; // Copy master set for select()
        struct timeval timeout;
        timeout.tv_sec = 1; // 1-second timeout for select()
        timeout.tv_usec = 0;

        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);

        if (activity < 0) {
            if (errno == EINTR) {
                // Interrupted system call, typically safe to ignore and retry
                continue;
            }
            logger_log(LOG_LEVEL_ERROR, "Listener thread: Select error: %s", strerror(errno));
            break; // Fatal error, exit thread
        }

        if (activity == 0) {
            // Timeout, no activity, continue loop
            continue;
        }

        // Check for new incoming connections on the listener socket
        if (FD_ISSET(g_listener_socket_fd, &read_fds)) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int client_sock_fd = accept(g_listener_socket_fd, (struct sockaddr*)&client_addr, &client_len);

            if (client_sock_fd == -1) {
                if (errno == EWOULDBLOCK || errno == EAGAIN) {
                    // No new connection immediately available (non-blocking accept)
                    continue;
                }
                logger_log(LOG_LEVEL_ERROR, "Listener thread: Failed to accept new connection: %s", strerror(errno));
                break; // Fatal error, exit thread
            }

            // Set newly accepted client socket to non-blocking mode
            if (fcntl(client_sock_fd, F_SETFL, O_NONBLOCK) == -1) {
                logger_log(LOG_LEVEL_ERROR, "Listener thread: Failed to set client socket to non-blocking: %s", strerror(errno));
                close(client_sock_fd);
                continue; // Skip this client, but listener thread continues
            }

            peer_add(client_sock_fd, client_addr); // Add new peer to our connected list
            logger_log(LOG_LEVEL_INFO, "Listener thread: Accepted new connection from %s:%d. FD: %d",
                                       inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), client_sock_fd);
            print_green("Accepted new connection from %s:%d.\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

            FD_SET(client_sock_fd, &master_fds); // Add client socket to master set for monitoring
            if (client_sock_fd > max_fd) {
                max_fd = client_sock_fd; // Update max_fd if necessary
            }
        }

        // Check connected peer sockets for incoming data
        // Iterate through all possible peer indices (even if not currently connected to simplify FD_ISSET checks)
        // Note: Iterating MAX_PEERS times is fine, but can be optimized by iterating g_num_connected_peers.
        // However, g_connected_peers is an array that shifts, so safer to iterate and check is_connected.
        for (size_t i = 0; i < MAX_PEERS; ++i) {
            if (g_connected_peers[i].is_connected) { // Only check active connections
                int current_peer_fd = g_connected_peers[i].socket_fd;

                if (current_peer_fd != -1 && FD_ISSET(current_peer_fd, &read_fds)) {
                    // A peer socket has data to read
                    MessageType received_type;
                    uint8_t* received_payload = NULL;
                    size_t received_payload_len = 0;

                    ssize_t total_bytes_received = network_receive_full_message(
                        current_peer_fd, &received_type, &received_payload, &received_payload_len
                    );

                    if (total_bytes_received > 0) {
                        // Successfully received a full message, handle it
                        network_handle_received_message(received_type, received_payload, received_payload_len);
                        if (received_payload) free(received_payload); // Free payload after handling
                    } else if (total_bytes_received == 0) {
                        // Peer gracefully disconnected (network_receive_full_message handles peer_remove)
                        logger_log(LOG_LEVEL_INFO, "Listener thread: Peer FD %d disconnected gracefully.", current_peer_fd);
                        FD_CLR(current_peer_fd, &master_fds); // Remove from master set
                        // Max_fd recalculation happens implicitly if peer_remove updates array and loop continues
                        // Or can be explicitly recalculated after all peer checks in this select iteration.
                        // For simplicity, it will be recalculated on the next select iteration if this was max_fd.
                    } else { // total_bytes_received == -1 (error)
                        // Error occurred during receive (network_receive_full_message handles peer_remove)
                        logger_log(LOG_LEVEL_ERROR, "Listener thread: Error receiving message from FD %d.", current_peer_fd);
                        FD_CLR(current_peer_fd, &master_fds); // Remove from master set
                    }
                }
            }
        }
        // After iterating all peers, if max_fd was removed, recalculate it for the next select loop.
        // This is a simple but less efficient recalculation. A more robust solution might track it directly.
        max_fd = g_listener_socket_fd; // Start with listener FD
        for (size_t k = 0; k < MAX_PEERS; ++k) {
            if (g_connected_peers[k].is_connected && g_connected_peers[k].socket_fd > max_fd) {
                max_fd = g_connected_peers[k].socket_fd;
            }
        }
    }

    // Cleanup when listener thread exits
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

    // Set client socket to non-blocking mode as well, for consistency with listener
    if (fcntl(sock_fd, F_SETFL, O_NONBLOCK) == -1) {
        logger_log(LOG_LEVEL_ERROR, "Failed to set client socket to non-blocking: %s", strerror(errno));
        close(sock_fd);
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

    // Attempt to connect. For non-blocking sockets, connect might return EINPROGRESS.
    int connect_result = connect(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (connect_result == -1 && errno != EINPROGRESS) {
        logger_log(LOG_LEVEL_ERROR, "Failed to connect to peer %s:%d: %s", ip_address, port, strerror(errno));
        print_red("Error: Failed to connect to peer %s:%d.\n", ip_address, port);
        close(sock_fd);
        return -1;
    }

    // If connect returns EINPROGRESS, it means the connection is in progress.
    // We can then add it to our peer list and it will be monitored by the listener thread's select loop.
    peer_add(sock_fd, server_addr); // Add even if connection is in progress

    logger_log(LOG_LEVEL_INFO, "Successfully initiated connection to peer %s:%d (FD: %d).", ip_address, port, sock_fd);
    print_green("Successfully initiated connection to peer %s:%d.\n", ip_address, port);
    return 0; // Return 0 for successfully initiated connection.
}

// REMOVED: Old network_send_message and network_receive_message are now replaced by
// network_send_full_message and network_receive_full_message for framed messages.
// The raw send/recv are now internal helpers (network_read_bytes, network_write_bytes).


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
        // No FD_CLR needed for master_fds here if the thread exits correctly.
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
 * This function uses network_send_full_message internally to send framed messages.
 *
 * @param type The type of message to broadcast.
 * @param data The raw data to broadcast (payload).
 * @param data_len The length of the data.
 * @return The number of peers successfully sent to, or -1 on error.
 */
int network_broadcast_data(MessageType type, const uint8_t* data, size_t data_len) {
    if (data == NULL || data_len == 0) {
        logger_log(LOG_LEVEL_WARN, "network_broadcast_data: No data or zero length provided for broadcast (Type: %d).", type);
        return 0; // Nothing to broadcast
    }

    if (g_num_connected_peers == 0) {
        logger_log(LOG_LEVEL_INFO, "network_broadcast_data: No peers to broadcast to (Type: %d).", type);
        return 0;
    }

    int peers_sent_to = 0;
    // Iterate through a copy or iterate carefully as peer_remove might modify g_connected_peers
    // Safer to iterate backwards or store FDs to iterate. For simplicity here, iterate forward.
    // If a peer is removed by network_send_full_message, g_num_connected_peers will decrease,
    // and the array shifts.
    // A more robust approach might build a list of FDs to send to first.
    size_t initial_num_peers = g_num_connected_peers; // Capture current count
    for (size_t i = 0; i < initial_num_peers; ++i) { // Iterate up to original count
        // Need to re-check is_connected and socket_fd inside the loop if peer_remove shifts array
        // The safest way is to make a temporary list of FDs.
        // For simplicity for now, assuming peer_remove handles shifting and subsequent loop iterations
        // will correctly process remaining peers or skip invalid FDs.
        // Or, more simply, copy active FDs to a temp array:
        int active_fds[MAX_PEERS];
        size_t temp_count = 0;
        for (size_t j = 0; j < g_num_connected_peers; ++j) { // Use current g_num_connected_peers
            if (g_connected_peers[j].is_connected) {
                active_fds[temp_count++] = g_connected_peers[j].socket_fd;
            }
        }

        // Now iterate over the safe, temporary list
        for (size_t j = 0; j < temp_count; ++j) {
            ssize_t sent = network_send_full_message(active_fds[j], type, data, data_len);
            if (sent > 0) {
                peers_sent_to++;
                logger_log(LOG_LEVEL_DEBUG, "Broadcasted %zd bytes (Type: %d, Payload Len: %zu) to peer FD %d.", sent, type, data_len, active_fds[j]);
            } else if (sent == 0) {
                 logger_log(LOG_LEVEL_WARN, "Could not broadcast data to peer FD %d (send buffer full).", active_fds[j]);
            } else { // sent == -1 (error)
                 logger_log(LOG_LEVEL_ERROR, "Failed to broadcast data to peer FD %d (error occurred).", active_fds[j]);
                 // peer_remove is already called by network_send_full_message on error
            }
        }
        break; // Exit the outer loop after one pass of the temporary list
    }

    logger_log(LOG_LEVEL_INFO, "Broadcasted data (Type: %d, Data Len: %zu) to %d peers.", type, data_len, peers_sent_to);
    return peers_sent_to;
}

