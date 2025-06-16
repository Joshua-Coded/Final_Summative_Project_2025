// src/network/network.c
#include "network.h"
#include "../utils/logger.h"
#include "../utils/colors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // For close()
#include <errno.h>  // For errno
#include <fcntl.h>  // For fcntl (for non-blocking sockets)

// Global variables for network state
static int g_listener_socket_fd = -1;
static Peer g_connected_peers[MAX_PEERS]; // Simple array for managing peers
static size_t g_num_connected_peers = 0;

// Threading related globals
static pthread_t g_listener_thread;
static volatile bool g_listener_should_exit = false; // Flag to signal listener thread to stop
static bool g_listener_thread_running = false;       // To track if the thread was successfully launched

// --- Internal Helper Functions ---
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
        close(socket_fd); // Close the new connection if we can't manage it
    }
}

static void peer_remove(int socket_fd) {
    for (size_t i = 0; i < g_num_connected_peers; ++i) {
        if (g_connected_peers[i].socket_fd == socket_fd) {
            close(socket_fd);
            g_connected_peers[i].is_connected = false; // Mark as inactive
            logger_log(LOG_LEVEL_INFO, "Peer removed: %s:%d (FD: %d).",
                       inet_ntoa(g_connected_peers[i].address.sin_addr),
                       ntohs(g_connected_peers[i].address.sin_port), socket_fd);

            // Shift remaining peers to fill the gap (maintain a compact list)
            for (size_t j = i; j < g_num_connected_peers - 1; ++j) {
                g_connected_peers[j] = g_connected_peers[j+1];
            }
            g_num_connected_peers--;
            return;
        }
    }
    logger_log(LOG_LEVEL_WARN, "Attempted to remove non-existent peer with FD: %d.", socket_fd);
}


// Listener Thread Function (Refactored for select())
static void* listener_thread_func(void* arg) {
    int port = *(int*)arg; // Cast the argument back to an int pointer and dereference
    free(arg); // Free the dynamically allocated port memory

    logger_log(LOG_LEVEL_INFO, "Listener thread started on port %d.", port);

    // Create listener socket
    g_listener_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listener_socket_fd == -1) {
        logger_log(LOG_LEVEL_ERROR, "Listener thread: Failed to create listener socket: %s", strerror(errno));
        g_listener_thread_running = false;
        return NULL; // Exit thread
    }

    // Set socket option to reuse address (important for rapid restarts)
    int optval = 1;
    if (setsockopt(g_listener_socket_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        logger_log(LOG_LEVEL_ERROR, "Listener thread: Failed to set socket options: %s", strerror(errno));
        close(g_listener_socket_fd);
        g_listener_socket_fd = -1;
        g_listener_thread_running = false;
        return NULL;
    }

    // Set listener socket to non-blocking mode
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
    server_addr.sin_port = htons(port);      // Convert port to network byte order

    if (bind(g_listener_socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        logger_log(LOG_LEVEL_ERROR, "Listener thread: Failed to bind listener socket to port %d: %s", port, strerror(errno));
        close(g_listener_socket_fd);
        g_listener_socket_fd = -1;
        g_listener_thread_running = false;
        return NULL;
    }

    if (listen(g_listener_socket_fd, 5) == -1) { // 5 is the backlog queue size
        logger_log(LOG_LEVEL_ERROR, "Listener thread: Failed to listen on socket: %s", strerror(errno));
        close(g_listener_socket_fd);
        g_listener_socket_fd = -1;
        g_listener_thread_running = false;
        return NULL;
    }

    logger_log(LOG_LEVEL_INFO, "Listener thread: Network listener active on port %d. Waiting for connections...", port);

    fd_set master_fds; // Master set of file descriptors for select()
    FD_ZERO(&master_fds);
    FD_SET(g_listener_socket_fd, &master_fds); // Add listener socket to master set

    int max_fd = g_listener_socket_fd; // Keep track of the maximum FD value for select()

    // Main loop for handling connections and messages
    while (!g_listener_should_exit) {
        fd_set read_fds = master_fds; // Copy the master set for select()

        struct timeval timeout;
        timeout.tv_sec = 1;  // Check for activity every 1 second
        timeout.tv_usec = 0; // Microseconds

        // Select waits for activity on any socket in read_fds up to max_fd + 1
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);

        if (activity < 0) {
            if (errno == EINTR) { // Interrupted system call, just continue
                continue;
            }
            logger_log(LOG_LEVEL_ERROR, "Listener thread: Select error: %s", strerror(errno));
            break; // Exit loop on critical error
        }

        // If activity is 0, it was a timeout, just re-check g_listener_should_exit and continue
        if (activity == 0) {
            continue;
        }

        // --- Handle activity on sockets ---

        // 1. Check for new connections on the listener socket
        if (FD_ISSET(g_listener_socket_fd, &read_fds)) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int client_sock_fd = accept(g_listener_socket_fd, (struct sockaddr*)&client_addr, &client_len);

            if (client_sock_fd == -1) {
                if (errno == EWOULDBLOCK || errno == EAGAIN) {
                    // No new connection immediately available, or socket became non-blocking
                    continue; // Loop and re-select.
                }
                logger_log(LOG_LEVEL_ERROR, "Listener thread: Failed to accept new connection: %s", strerror(errno));
                break; // Exit loop on critical error
            }

            // Set the new client socket to non-blocking
            if (fcntl(client_sock_fd, F_SETFL, O_NONBLOCK) == -1) {
                logger_log(LOG_LEVEL_ERROR, "Listener thread: Failed to set client socket to non-blocking: %s", strerror(errno));
                close(client_sock_fd);
                continue; // Don't add this socket if we can't manage it
            }

            peer_add(client_sock_fd, client_addr);
            logger_log(LOG_LEVEL_INFO, "Listener thread: Accepted new connection from %s:%d. FD: %d",
                       inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), client_sock_fd);
            print_green("Accepted new connection from %s:%d.\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

            FD_SET(client_sock_fd, &master_fds); // Add new client socket to master set
            if (client_sock_fd > max_fd) { // Update max_fd if necessary
                max_fd = client_sock_fd;
            }
        }

        // 2. Check for incoming data on existing peer sockets
        // Iterate through g_connected_peers to check for data
        for (size_t i = 0; i < MAX_PEERS; ++i) {
            if (g_connected_peers[i].is_connected) { // Only check active peers
                int current_peer_fd = g_connected_peers[i].socket_fd;

                if (current_peer_fd != -1 && FD_ISSET(current_peer_fd, &read_fds)) {
                    uint8_t buffer[1024];
                    // network_receive_message now returns 0 for graceful disconnect OR EAGAIN/EWOULDBLOCK,
                    // and -1 for real errors (which also cause peer_remove).
                    // Because we use select(), if FD_ISSET is true, bytes_received should ideally be > 0 or 0 (disconnect).
                    ssize_t bytes_received = network_receive_message(current_peer_fd, buffer, sizeof(buffer) - 1);

                    if (bytes_received > 0) {
                        buffer[bytes_received] = '\0'; // Null-terminate for string printing
                        logger_log(LOG_LEVEL_INFO, "Listener thread: Received message from FD %d: \"%s\"", current_peer_fd, buffer);
                        print_cyan("Received message from peer %s:%d: \"%s\"\n",
                                   inet_ntoa(g_connected_peers[i].address.sin_addr),
                                   ntohs(g_connected_peers[i].address.sin_port),
                                   buffer);
                    } else { // bytes_received is 0 (disconnect) or -1 (error)
                        // This peer is no longer connected (or an error occurred).
                        // network_receive_message would have already called peer_remove.
                        // We need to remove its FD from the master_fds set.
                        FD_CLR(current_peer_fd, &master_fds);
                        logger_log(LOG_LEVEL_INFO, "Listener thread: Cleared FD %d from master_fds (disconnected/error).", current_peer_fd);

                        // If the disconnected FD was the max_fd, recalculate max_fd
                        if (current_peer_fd == max_fd) {
                            max_fd = g_listener_socket_fd; // Start re-evaluation from listener socket
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

    // Cleanup: Close the listener socket when the thread exits
    if (g_listener_socket_fd != -1) {
        close(g_listener_socket_fd);
        FD_CLR(g_listener_socket_fd, &master_fds); // Remove from set one last time
        g_listener_socket_fd = -1;
        logger_log(LOG_LEVEL_INFO, "Listener thread: Listener socket closed.");
    }
    logger_log(LOG_LEVEL_INFO, "Listener thread: Exiting.");
    g_listener_thread_running = false; // Mark thread as no longer running
    return NULL;
}


// --- Public Network Functions ---

int network_init() {
    // Initialize peer list
    for (size_t i = 0; i < MAX_PEERS; ++i) {
        g_connected_peers[i].socket_fd = -1;
        g_connected_peers[i].is_connected = false;
        memset(&g_connected_peers[i].address, 0, sizeof(struct sockaddr_in)); // Clear address too
    }
    g_num_connected_peers = 0;
    g_listener_should_exit = false; // Ensure flag is false on init
    g_listener_thread_running = false; // Ensure flag is false on init
    logger_log(LOG_LEVEL_INFO, "Network module initialized.");
    return 0;
}

int network_start_listener(int port) {
    if (g_listener_thread_running) {
        logger_log(LOG_LEVEL_WARN, "Listener is already running.");
        print_yellow("Listener is already running on port %d.\n", port);
        return -1;
    }

    // Allocate memory for the port to pass to the thread (pthread_create requires void*)
    int* thread_port = malloc(sizeof(int));
    if (!thread_port) {
        logger_log(LOG_LEVEL_ERROR, "Failed to allocate memory for listener thread port.");
        print_red("Error: Failed to allocate memory for listener thread.\n");
        return -1;
    }
    *thread_port = port;

    g_listener_should_exit = false; // Reset the exit flag

    // Create the listener thread
    if (pthread_create(&g_listener_thread, NULL, listener_thread_func, thread_port) != 0) {
        logger_log(LOG_LEVEL_ERROR, "Failed to create listener thread: %s", strerror(errno));
        print_red("Error: Failed to create listener thread.\n");
        free(thread_port); // Free memory if thread creation fails
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

    // Removed fcntl(sock_fd, F_SETFL, O_NONBLOCK) here.
    // The connect() call will now be blocking, which is desired for this CLI command.

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

    // This connect call will now block until connection is established or fails.
    if (connect(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        logger_log(LOG_LEVEL_ERROR, "Failed to connect to peer %s:%d: %s", ip_address, port, strerror(errno));
        print_red("Error: Failed to connect to peer %s:%d.\n", ip_address, port);
        close(sock_fd);
        return -1;
    }

    // Removed fcntl(sock_fd, F_SETFL, O_NONBLOCK) here.
    // While accepted sockets are non-blocking on the listener side,
    // this connecting socket can remain blocking for simplicity if
    // its I/O (send/recv) is not handled asynchronously on the client side.
    // The send/recv functions already handle EWOULDBLOCK/EAGAIN.

    peer_add(sock_fd, server_addr); // Add the newly connected peer
    logger_log(LOG_LEVEL_INFO, "Successfully connected to peer %s:%d (FD: %d).", ip_address, port, sock_fd);
    print_green("Successfully connected to peer %s:%d.\n", ip_address, port);
    return 0; // Success
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
             return 0; // Indicate no bytes sent due to non-blocking status
        }
        logger_log(LOG_LEVEL_ERROR, "Failed to send message to FD %d: %s", peer_socket_fd, strerror(errno));
        peer_remove(peer_socket_fd); // Assume connection is broken
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
            return 0; // No data currently available, but not an error (non-blocking)
        }
        logger_log(LOG_LEVEL_ERROR, "Failed to receive message from FD %d: %s", peer_socket_fd, strerror(errno));
        peer_remove(peer_socket_fd); // Assume connection broken
        return -1; // Indicate error
    } else if (bytes_received == 0) {
        logger_log(LOG_LEVEL_INFO, "Peer FD %d disconnected gracefully.", peer_socket_fd);
        peer_remove(peer_socket_fd); // Peer disconnected
        return 0; // Indicate graceful disconnect
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
    return -1; // No connected peers
}


void network_shutdown() {
    logger_log(LOG_LEVEL_INFO, "Shutting down network module...");
    print_cyan("Shutting down network module...\n");

    // Signal the listener thread to exit and wait for it to finish
    if (g_listener_thread_running) {
        logger_log(LOG_LEVEL_INFO, "Signaling listener thread to exit.");
        g_listener_should_exit = true; // Set the flag
        pthread_join(g_listener_thread, NULL); // Wait for the listener thread to terminate
        logger_log(LOG_LEVEL_INFO, "Listener thread joined successfully.");
    } else {
        logger_log(LOG_LEVEL_INFO, "Listener thread was not running.");
    }

    // Close listener socket if it was still open (should be closed by thread itself, but defensive)
    if (g_listener_socket_fd != -1) {
        close(g_listener_socket_fd);
        g_listener_socket_fd = -1;
        logger_log(LOG_LEVEL_INFO, "Listener socket (residual close) closed.");
    }

    // Close all connected peer sockets
    for (size_t i = 0; i < MAX_PEERS; ++i) {
        if (g_connected_peers[i].is_connected) {
            close(g_connected_peers[i].socket_fd);
            g_connected_peers[i].socket_fd = -1;
            g_connected_peers[i].is_connected = false;
            // No need to log peer_remove again, as it was likely logged on graceful disconnect/error
            // logger_log(LOG_LEVEL_INFO, "Closed connection to peer %s:%d (FD: %d).", ...);
        }
    }
    g_num_connected_peers = 0;
    logger_log(LOG_LEVEL_INFO, "All peer connections closed.");
    print_green("Network module shut down successfully.\n");
}
