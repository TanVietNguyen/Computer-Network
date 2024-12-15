#include "operation.c"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>

int main(int argc, char* argv[]) {
   //Check if user input is valid
   if(argc != 3){
      // printf("Usage: %s <Hostname> <Port>\n", argv[0]);
      return 1;
   }
   //Get the server hostname and port
   char *hostname = argv[1];
   int port = atoi(argv[2]);
   // Create socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
                     // use IPv4  use UDP
     // Setup fd set for nonblock
   int flags = fcntl(sockfd, F_GETFL);
   flags |= O_NONBLOCK;
   fcntl(sockfd, F_SETFL, flags);
   //Set up the standard input non-blocking
   int flags_input = fcntl(0, F_GETFL);
   flags_input |= O_NONBLOCK;
   fcntl(0, F_SETFL, flags_input);
   // Construct server address
    struct sockaddr_in serveraddr;
    serveraddr.sin_family = AF_INET; // use IPv4
    if(strcmp(hostname, "localhost") == 0){
      serveraddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    }
    else{
      serveraddr.sin_addr.s_addr = inet_addr(hostname);
    }
    // Set sending port
   serveraddr.sin_port = htons(port); // Big endian
   // Create buffer to store incoming data
   socklen_t serversize = sizeof(serveraddr); // Temp buffer for recvfrom API

   State client_state = {
      .send_buffer = NULL,
      .recv_buffer = NULL,
      .next_seq_num = 0,
      .expected_seq_num = 0,
      .latest_ack_num = 0,
      .dup_ack_count = 0,
      .current_window_size = 0,
      .ack_pending = false,
      .last_received_time = {0}, 
      .current_time = {0}
   };
   // initial sequence number must be less than half of the maximum sequence number
   srand(time(NULL));
   client_state.next_seq_num = rand() % (INT32_MAX / 2);  
    client_state.next_seq_num = 456;


   // Initialize packet
   Packet firstHandshakePacket = {0, client_state.next_seq_num, 0, 1, 0, 0};
   //  Send first handshake Packet to a server
   convert_to_bigEndian(&firstHandshakePacket);
   print_diag(&firstHandshakePacket, SEND);
   int did_send = sendto(sockfd, &firstHandshakePacket, sizeof(firstHandshakePacket),
                     0, (struct sockaddr*) &serveraddr, serversize);
   //increment next_seq_num by 1
   client_state.next_seq_num ++;
   if (did_send < 0){
      perror("sendto failed");
      return errno;
   }
   Packet pkt_server = {0};
   char buffer_stdInput[MSS];
    
   int isHandShaked = false;
   int first_handshake = false;
   while(1){
      // need to be handshaked before doing anyting further
      if (!isHandShaked){
         int bytes_recvd = recvfrom(sockfd, &pkt_server, sizeof(pkt_server), 
                                 // socket  store data  how much
                                    0, (struct sockaddr*) &serveraddr, 
                                    &serversize);
         if(bytes_recvd > 0){
            print_diag(&pkt_server, RECV);
            convert_to_littleEndian(&pkt_server);
            // Get the first packet from the server
            if((pkt_server.ack == client_state.next_seq_num) && 
               ((pkt_server.flags >> 1) & 1)&&
               (pkt_server.flags & 1)){
                  // initilaize expected_seq_num, latest_ack_num
                  client_state.expected_seq_num = pkt_server.seq + 1;
                  // client_state.expected_seq_num ++;
                  client_state.latest_ack_num = pkt_server.ack;
                  first_handshake = true;
            }
         }
         if(first_handshake){
            // Send the second Packet to the server
            // can carry payload in the second Packet to the server
            // int read_len = read(0, buffer_stdInput, MSS);
            //in the second packet, send ACK flag, no SYN flag
            Packet second_pkt = {client_state.expected_seq_num, client_state.next_seq_num, 0, 2, 0, 0};
            // memcpy(second_pkt.payload, buffer_stdInput, sizeof(buffer_stdInput));
            convert_to_bigEndian(&second_pkt);
            print_diag(&second_pkt, SEND);
            int did_send = sendto(sockfd, &second_pkt, sizeof(second_pkt), 0, (struct sockaddr*)
                                 &serveraddr, serversize);
            if (did_send < 0){
               perror("sendto failed");
               return errno;
            }
            isHandShaked = true;

            fprintf(stderr, "handshaked");
            client_state.next_seq_num++;
            // Increase next_seq_num by 1 if carrying no payload
            // if (read_len == 0){
            //    client_state.next_seq_num ++;
            // }
            // else{
            //    client_state.next_seq_num += read_len;
            // }
         }
         continue;
      }
      // Handshake is established, Listen loop
      //receive packets
      receive_and_ack(&client_state, sockfd, &serveraddr, &serversize);
      // send packets until it reaches maximum window size
      if(client_state.current_window_size < maximum_window_size){
         read_and_send(&client_state, sockfd, &serveraddr);
      }
      else{
         client_state.ack_pending = true;
      }
      //retransmit packets
      gettimeofday(&client_state.current_time, NULL);
      if(time_diff(&client_state.last_received_time, &client_state.current_time)) { 
            retransmit(&client_state, client_state.send_buffer, sockfd, &serveraddr);
            gettimeofday(&client_state.last_received_time, NULL);
      }
   }
   //  Terminate the connection    
    close(sockfd);
    return 0;
}

