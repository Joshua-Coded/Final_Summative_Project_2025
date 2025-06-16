// src/network/network.h
#ifndef NETWORK_H
#define NETWORK_H

#include <stdint.h>
#include <sys/socket.h> // For socket structures (sockaddr_in, etc.)
#include <netinet/in.h> // For internet address structures
#include <arpa/inet.h>  // For inet_ntoa
#include <stdbool.h>    // For bool type
#include <sys/select.h> // For fd_set, select
#include <pthread.h>    // <--- NEW: For threading

// Define a maximum number of peers a node can connect to
#define MAX_PEERS 10

// Define default port for blockchain communication
#define DEFAULT_PORT 8080

// Struct to represent a connected peer
typedef struct {
    int socket_fd;             // Socket file descriptor for this peer
    struct sockaddr_in address; // Peer's address information
    bool is_connected;         // True if the connection is active
    // Add other peer-specific info here as needed (e.g., last_seen, node_id)
} Peer;

// --- Network Initialization and Control ---

/**
 * @brief Initializes the networking module.
 * Sets up any global network-related resources.
 * @return 0 on success, -1 on failure.
 */
int network_init();

/**
 * @brief Starts the network listener on a specified port in a separate thread.
 * @param port The port number to listen on.
 * @return 0 on success (listener thread started), -1 on failure.
 */
int network_start_listener(int port);

/**
 * @brief Connects to a remote peer.
 * @param ip_address The IP address of the peer to connect to (e.g., "127.0.0.1").
 * @param port The port number of the peer.
 * @return 0 on success (connected), -1 on failure.
 */
int network_connect_to_peer(const char* ip_address, int port);

/**
 * @brief Sends a generic message to a connected peer.
 * This will be expanded later to handle specific message types (blocks, transactions).
 * @param peer_socket_fd The socket file descriptor of the peer to send to.
 * @param message The raw message data to send.
 * @param message_len The length of the message data.
 * @return Number of bytes sent, or -1 on error.
 */
ssize_t network_send_message(int peer_socket_fd, const uint8_t* message, size_t message_len);

/**
 * @brief Receives a generic message from a connected peer.
 * This will be expanded later.
 * @param peer_socket_fd The socket file descriptor of the peer to receive from.
 * @param buffer The buffer to store received data.
 * @param buffer_len The maximum size of the buffer.
 * @return Number of bytes received, or -1 on error.
 */
ssize_t network_receive_message(int peer_socket_fd, uint8_t* buffer, size_t buffer_len);

/**
 * @brief Retrieves the socket file descriptor of the first active connected peer.
 * This is a simplified function for initial CLI testing. In a full system,
 * you would manage peers more robustly (e.g., by ID or iterating a list).
 * @return The socket FD of the first connected peer, or -1 if no peers are connected.
 */
int network_get_first_peer_socket_fd();

/**
 * @brief Shuts down the networking module, closing all connections and listeners.
 */
void network_shutdown();

#endif // NETWORK_H
