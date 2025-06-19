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

typedef enum {
    MSG_TYPE_UNKNOWN = 0,
    MSG_TYPE_TEST_MESSAGE,
    MSG_TYPE_TRANSACTION,
    MSG_TYPE_BLOCK,
} MessageType;

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
 * @brief Sends a generic message to a connected peer.
 */
ssize_t network_send_message(int peer_socket_fd, const uint8_t* message, size_t message_len);

/**
 * @brief Receives a generic message from a connected peer.
 */
ssize_t network_receive_message(int peer_socket_fd, uint8_t* buffer, size_t buffer_len);

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
 */
int network_broadcast_data(MessageType type, const uint8_t* data, size_t data_len);

#endif // NETWORK_H
