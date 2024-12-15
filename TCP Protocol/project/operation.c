#include "operation.h"

#define RECV 0
#define SEND 1
#define RTOS 2
#define DUPA 3

static inline void print_diag(Packet* pkt, int diag) {
    switch (diag) {
    case RECV:
        fprintf(stderr, "RECV");
        break;
    case SEND:
        fprintf(stderr, "SEND");
        break;
    case RTOS:
        fprintf(stderr, "RTOS");
        break;
    case DUPA:
        fprintf(stderr, "DUPS");
        break;
    }

    bool syn = pkt->flags & 0b01;
    bool ack = pkt->flags & 0b10;
    fprintf(stderr, " %u ACK %u SIZE %hu FLAGS ", ntohl(pkt->seq),
            ntohl(pkt->ack), ntohs(pkt->length));
    if (!syn && !ack) {
        fprintf(stderr, "NONE");
    } else {
        if (syn) {
            fprintf(stderr, "SYN ");
        }
        if (ack) {
            fprintf(stderr, "ACK ");
        }
    }
    fprintf(stderr, "\n");
}
// Add a packet to the end of the list
void append(Node **head, Packet packet) {
    Node *new_node = (Node *)malloc(sizeof(Node));
    new_node->packet = packet;
    new_node->next = NULL;

    if (*head == NULL) {
        *head = new_node;
    } else {
        Node *current = *head;
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = new_node;
    }
}

void print_buffer(Node *head){
    Node* tmp = head;
    fprintf(stderr, "\t+Current buff:");
    while (tmp != NULL) {
        fprintf(stderr, "%u ", tmp->packet.seq);
        tmp = tmp->next;
    }
    fprintf(stderr, "\n");
}


// Insert a packet into a list in the order of increasing SEQ
void insert(Node **head, Packet packet) {
    Node *new_node = (Node *)malloc(sizeof(Node));
    new_node->packet = packet;
    new_node->next = NULL;

        // fprintf(stderr, "10\n");
    if (*head == NULL) {
        *head = new_node;
    } else {
        // fprintf(stderr, "11\n");
        Node *current = *head;
        Node *prev_node = current;
        if(current->packet.seq > new_node->packet.seq){
            new_node->next = *head;
            *head = new_node; 
            // fprintf(stderr, "12\n");
        }
        else {
            // fprintf(stderr, "13\n");
            while(current != NULL && current->packet.seq < new_node->packet.seq){
                prev_node = current;
                current = current->next;
            }
            // fprintf(stderr, "14 cur \n" );
            //don't add duplicate packet
            if(!current || new_node->packet.seq != current->packet.seq){
                new_node->next = current;
                prev_node->next = new_node;
            }
        }
    }
}
// Remove acknowledged packets from the list
void remove_acked_packets(State* state, Node **head, int ack_num) {
    while (*head != NULL && (*head)->packet.seq < ack_num) {
        Node *temp = *head;
        *head = (*head)->next;
        state->current_window_size -= 1;
        free(temp);
    }
}
//Write out ordered packets to standard output
void write_ordered_packets(State* state, Node **head){
    while(*head != NULL && (*head)->packet.seq == state->expected_seq_num){
        // print_diag(&((*head)->packet), RECV);
        fprintf(stderr, "\t\tI printed %u\n", state->expected_seq_num);
        state->expected_seq_num += (*head)->packet.length;
        write(STDOUT_FILENO, (*head)->packet.payload, (*head)->packet.length);
        // Update the expected_num_seq so that we can check if 
        // the next packet in the recv buffer is in order
        // convert_to_bigEndian(&(temp->packet));
        Node* tmp = *head;
        *head = (*head)->next;
        free(tmp);
        tmp = NULL;
    }
    //Remove these packets from the received buffer
    // remove_acked_packets(state, &(head), state->expected_seq_num);
}

// Find the packet with the given sequence number
Node *find(Node *head, int seq_num) {
    Node *current = head;
    while (current != NULL) {
        if (current->packet.seq == seq_num) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}
void send_packet(State* state, int sockfd, struct sockaddr_in *addr, Packet *packet, bool no_payload) {
    convert_to_bigEndian(packet);
    // if (packet->length > 0 && rand() % 4 > 0)
    // if (rand() % 10 ==1)
	// {
        print_diag(packet, SEND);
        sendto(sockfd, packet, sizeof(Packet), 0,
            (struct sockaddr *)addr, sizeof(struct sockaddr_in));
	// }
    // else
    // {
    //     fprintf(stderr, "Drop \n");
    // }
    
    // Store packets in the sending buffer only if it has payload
    convert_to_littleEndian(packet);
    if(!no_payload){
        append(&(state->send_buffer), *packet);
    } 

}

void scan_send_buffer(State* state, Packet *ack_packet) {
    int ack_num = ack_packet->ack;
    remove_acked_packets(state, &(state->send_buffer), ack_num);
}

void scan_recv_buffer(State* state, Packet *recv_packet){
    
        // fprintf(stderr, "6\n");
    if (recv_packet->seq < state->expected_seq_num) return;
        // fprintf(stderr, "7\n");
    insert(&(state->recv_buffer), *recv_packet);

        // fprintf(stderr, "8\n");
    // check if the received packet is in order 
    // then proceed to scan the receiving buffer
        // print_buffer(state->recv_buffer);
    write_ordered_packets(state, &(state->recv_buffer));
        // fprintf(stderr, "9\n");
    //Update ack_pending to signal that there is an ACK needed to be sent
    // state->ack_pending = true;
}

void read_and_send(State* state, int sockfd, struct sockaddr_in *receiver_addr) {
    char buffer[MSS];
    Packet packet = {0};
    // uint32_t maximum_window_size = 20240;
    // while(current_window_size < maximum_window_size){//TO-DO: last reading overflows the windown size
    int bytes_read = read(STDIN_FILENO, buffer, MSS);
    // Could add more logic to catch the error of read()
    if (bytes_read > 0) {
        packet.seq = state->next_seq_num;
        packet.length = bytes_read;
        state->next_seq_num += bytes_read;
        if(state->ack_pending == true){
            packet.ack = state->expected_seq_num;
            packet.flags = 2; 
            state->ack_pending = false;
        }
        memset(packet.payload, 0, MSS);
        memcpy(packet.payload, buffer, bytes_read);
        // fprintf(stderr, "send packet\n");
        send_packet(state, sockfd, receiver_addr, &packet, false);
        // fprintf(stderr, "already sent packet\n");
        state->current_window_size += 1;
    }
    // // Sending ACK without payload(dedicated ACK)
    if (state->ack_pending == true){
        packet.ack = state->expected_seq_num;
        packet.flags = 2;
        state->ack_pending = false;
        // fprintf(stderr, "about send ack with no data \n");
        send_packet(state, sockfd, receiver_addr, &packet, true);
        // fprintf(stderr, "already sent ack with no data \n");
    }
}


void read_std_and_send(State* state, int sockfd, struct sockaddr_in *receiver_addr) {
    char buffer[MSS];
    // uint32_t maximum_window_size = 20240;
    // while(current_window_size < maximum_window_size){//TO-DO: last reading overflows the windown size
    int bytes_read = read(STDIN_FILENO, buffer, MSS);
    // Could add more logic to catch the error of read()
    if (bytes_read > 0) {
        Packet* packet = malloc(sizeof(Packet));
        packet->seq = state->next_seq_num;
        packet->length = bytes_read;
        packet->flags = 0;

        state->next_seq_num += bytes_read;

        // if(state->ack_pending == true){
        //     packet.ack = state->expected_seq_num;
        //     packet.flags = 2; 
        //     state->ack_pending = false;
        // }
        memset(packet->payload, 0, MSS);
        memcpy(packet->payload, buffer, bytes_read);
        send_packet(state, sockfd, receiver_addr, packet, false);
        state->current_window_size += 1;
    }
    
    // Sending ACK without payload(dedicated ACK)
    // if (state->ack_pending == true){
    //     packet->ack = state->expected_seq_num;
    //     packet->flags = 2;
    //     state->ack_pending = false;
    //     send_packet(state, sockfd, receiver_addr, &packet, true);
    // }
}

void receive_and_ack(State* state, int sockfd, struct sockaddr_in *sender_addr, socklen_t* addr_size) {
    Packet packet;
    int bytes_recvd = recvfrom(sockfd, &packet, sizeof(Packet), 0,
                             (struct sockaddr *)sender_addr, addr_size);
    if (bytes_recvd > 0) {
        print_diag(&packet, RECV);
        convert_to_littleEndian(&packet);
        // Scan sending buffer if receiving ACK
        // fprintf(stderr, "1\n");
        if ((packet.flags >> 1) & 1) {
            scan_send_buffer(state, &packet);
            // Track the number of duplicate acks for retransmitting purpose
            fprintf(stderr, "%u, %u \n", state->latest_ack_num, packet.ack);
            if(state->latest_ack_num == packet.ack){
                state->dup_ack_count ++;
                if(state->dup_ack_count == 2){
                    fprintf(stderr, "3 dup ack \n");
                    retransmit(state, state->send_buffer, sockfd, sender_addr);
                    state->dup_ack_count = 0;
                    fprintf(stderr, "3 dup ack - after retransmit");
                }
            }
            else{
                    state->latest_ack_num = packet.ack;
                    state->dup_ack_count = 0;
                }
        }
         // Track the received time for retransmitting purpose
        gettimeofday(&(state->last_received_time), NULL);
        // fprintf(stderr, "2\n");

        if(packet.length == 0){
            // fprintf(stderr, "skip packet %u\n", packet.seq);
            return;
        }
        print_buffer(state->send_buffer);
        fprintf(stderr, "\t = curr %u, expect %u\n", state->next_seq_num, state->expected_seq_num);

        // else return;
        // Scan the received buffer
        // TO-DO: ACK packet with no payload, no effect on expected_seq_num.
        // However, it's still inserted in the list, so don't know what happen
        // when writing it to the standard out (potiential fix: put a condition
        // that payload must be greater than 0 before executing read())
        // if(state->current_window_size < maximum_window_size){
        // fprintf(stderr, "3.2\n");
            scan_recv_buffer(state, &packet);
        // }
        // fprintf(stderr, "3.1\n");
        state->ack_pending = true;
        // Packet packet ={state->next_seq_num, state->expected_seq_num, 0, 2,0,0};
        // convert_to_bigEndian(&packet);
        // print_diag(&packet, SEND);
        // sendto(sockfd, &packet, sizeof(Packet), 0, (struct sockaddr*) sender_addr, sizeof(struct sockaddr_in));

        // fprintf(stderr, "4.1\n");
        
        
    }
}
void retransmit (State* state, Node *send_buffer, int sockfd, struct sockaddr_in *recv_addr){

    if (send_buffer != NULL){
        fprintf(stderr, "next send is retransmit\n");
        Packet packet = {0, send_buffer->packet.seq, send_buffer->packet.length,
                         0, 0, 0};
        if (state->ack_pending == true){
            packet.ack = state->expected_seq_num;
            packet.flags = 2;
            state->ack_pending = false;
        }
        memcpy(packet.payload, send_buffer->packet.payload, MSS);
        convert_to_bigEndian(&packet);
        print_diag(&packet, SEND);
        sendto(sockfd, &(packet), sizeof(Packet),
             0, (struct sockaddr *) recv_addr, sizeof(struct sockaddr_in));
        // convert_to_littleEndian(&packet);
    }

        // fprintf(stderr, "pre-retransmit\n");
}
long time_diff(struct timeval *start, struct timeval *end) {
    struct timeval time_sub;
    timersub(end, start, &time_sub);
    return time_sub.tv_sec >=1 || (time_sub.tv_usec >= 1000000);
}

void convert_to_littleEndian (Packet *packet){
    packet->ack = ntohl(packet->ack);
    packet->seq = ntohl(packet->seq);
    packet->length = ntohs(packet->length);
}
void convert_to_bigEndian (Packet *packet){
    packet->ack = htonl(packet->ack);
    packet->seq = htonl(packet->seq);
    packet->length = htons(packet->length);
}