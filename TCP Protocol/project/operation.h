#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdbool.h>

#define maximum_window_size 20
#define MSS 1012

typedef struct {
  uint32_t ack;
  uint32_t seq;
	uint16_t length;
	uint8_t flags;
	uint8_t unused;
	uint8_t payload[MSS]; // Data
} Packet;

typedef struct Node {
    Packet packet;
    struct Node *next;
} Node;

typedef struct {
    Node *send_buffer;
    Node *recv_buffer;
    uint32_t next_seq_num;
    uint32_t expected_seq_num;
    uint32_t latest_ack_num;
    int dup_ack_count;
    uint32_t current_window_size;
    bool ack_pending;
    struct timeval last_received_time;
    struct timeval current_time;
} State;

void append(Node **head, Packet packet);
void insert(Node **head, Packet packet);
void remove_acked_packets(State* state, Node **head, int ack_num);
void write_ordered_packets(State* state, Node **head);
Node *find(Node *head, int seq_num); 
void send_packet(State* state, int sockfd, struct sockaddr_in *addr, Packet *packet, bool no_payload);
void scan_recv_buffer(State* state, Packet *recv_packet);
void scan_send_buffer(State* state, Packet *ack_packet);
void read_and_send(State* state, int sockfd, struct sockaddr_in *receiver_addr);
void receive_and_ack(State* state, int sockfd, struct sockaddr_in *sender_addr, socklen_t* addr_size) ;
void retransmit (State* state, Node *send_buffer, int sockfd, struct sockaddr_in *recv_addr);
long time_diff(struct timeval *start, struct timeval *end);
void convert_to_littleEndian (Packet *packet);
void convert_to_bigEndian (Packet *packet);