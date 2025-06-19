// src/network/network.h
#ifndef NETWORK_H
#define NETWORK_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <sys/select.h>
#include <pthread.h>

#define MAX_PEERS 10
#define DEFAULT_PORT 8080

// Define a fixed size for the message header
#define MESSAGE_HEADER_SIZE (sizeof(uint32_t) + sizeof(uint32_t)) // Type (4 bytes) + Length (4 bytes)

typedef enum {
    MSG_TYPE_UNKNOWN = 0,
    MSG_TYPE_TEST_MESSAGE,
    MSG_TYPE_TRANSACTION,
    MSG_TYPE_BLOCK,
    // Add other message types as needed
} MessageType;

// Structure for message header (sent over network)
// Using uint32_t for consistent size
typedef struct {
    uint32_t type;         // Type of the message (e.g., MSG_TYPE_TRANSACTION)
    uint32_t payload_len;  // Length of the data payload following the header
} MessageHeader;

typedef struct {
    int socket_fd;
    struct sockaddr_in address;
    bool is_connected;
} Peer;

/**
 * @brief Initializes the networking module.
 */
int network_init();

/**
 * @brief Starts the network listener on a specified port in a separate thread.
 */
int network_start_listener(int port);

/**
 * @brief Connects to a remote peer.
 */
int network_connect_to_peer(const char* ip_address, int port);

/**
 * @brief Sends a full message (header + payload) to a connected peer.
 * This function handles message framing by prepending a header with type and length.
 *
 * @param peer_socket_fd The socket file descriptor of the peer.
 * @param type The type of the message (from MessageType enum).
 * @param payload The raw data payload to send.
 * @param payload_len The length of the data payload in bytes.
 * @return The number of bytes successfully sent (header + payload), or -1 on error.
 */
ssize_t network_send_full_message(int peer_socket_fd, MessageType type, const uint8_t* payload, size_t payload_len);

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
ssize_t network_receive_full_message(int peer_socket_fd, MessageType* out_type, uint8_t** out_payload, size_t* out_payload_len);


/**
 * @brief Retrieves the socket file descriptor of the first active connected peer.
 */
int network_get_first_peer_socket_fd();

/**
 * @brief Shuts down the networking module.
 */
void network_shutdown();

/**
 * @brief Broadcasts data of a specific message type to all connected peers.
 * This function uses network_send_full_message internally.
 *
 * @param type The type of message to broadcast.
 * @param data The raw data to broadcast (payload).
 * @param data_len The length of the data.
 * @return The number of peers successfully sent to, or -1 on error.
 */
int network_broadcast_data(MessageType type, const uint8_t* data, size_t data_len);


// --- Internal helper function for message handling (defined in .c but declared here for clarity) ---
// This function will be responsible for parsing and acting upon received messages.
void network_handle_received_message(MessageType type, const uint8_t* payload, size_t payload_len);


#endif // NETWORK_H
