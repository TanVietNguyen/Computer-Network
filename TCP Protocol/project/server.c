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

int main(int argc, char* argv[]) {
   if(argc != 2){
      // printf("Usage: %s <port>\n", argv[0]);
      return 1;
   }
    /* 1. Create socket */
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
                     // use IPv4  use UDP
   // Setup fd set for nonblock
    int flags = fcntl(sockfd, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(sockfd, F_SETFL, flags);
    //Setup for Standard input to be non-blocking
    int flags_input = fcntl(0, F_GETFL);
    flags_input |= O_NONBLOCK;
    fcntl(0, F_SETFL, flags_input);
    /* 2. Construct our address */
    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET; // use IPv4
    servaddr.sin_addr.s_addr = INADDR_ANY; // accept all connections
                            // same as inet_addr("0.0.0.0") 
                                     // "Address string to network bytes"
    // Set receiving port
    int PORT = atoi(argv[1]);
    servaddr.sin_port = htons(PORT); // Big endian

    /* 3. Let operating system know about our config */
    int did_bind = bind(sockfd, (struct sockaddr*) &servaddr, 
                        sizeof(servaddr));
    // Error if did_bind < 0 :(
    if (did_bind < 0) return errno;

   State server_state = {
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
   srand(time(NULL));
   server_state.next_seq_num = rand() % (INT32_MAX / 2);  
   server_state.next_seq_num = 789;


    /* 4. Create buffer to store incoming data */
    Packet client_pkt;
    struct sockaddr_in clientaddr; // Same information, but about client
    socklen_t clientsize = sizeof(clientaddr);
    int client_connected = false;
    int first_handshake = true;
    int is_handshaked = false;

   gettimeofday(&server_state.last_received_time, NULL);

   while (true){
      //Establish handshake synchronization
      if (!is_handshaked){
         int bytes_recvd = recvfrom(sockfd, &client_pkt, sizeof(client_pkt), 
                              // socket  store data  how much
                                 0, (struct sockaddr*) &clientaddr, 
                                 &clientsize);
         if (bytes_recvd > 0){
            print_diag(&client_pkt, RECV);
            convert_to_littleEndian(&client_pkt);
            if(first_handshake){
               /* 6. Inspect data from client */
               char* client_ip = inet_ntoa(clientaddr.sin_addr);
                           // "Network bytes to address string"
               int client_port = ntohs(clientaddr.sin_port); // Little endian
               client_connected = true;
               server_state.expected_seq_num = client_pkt.seq;
               server_state.expected_seq_num ++;
               // fprintf(stderr,"%u",server_state.expected_seq_num);
               server_state.latest_ack_num = client_pkt.ack;
            }
            else{
               //Update expected_seq_num
               

               if(client_pkt.length == 0){
                  server_state.expected_seq_num++;
               }
               else{
                  server_state.expected_seq_num += client_pkt.length;
                  write(1, client_pkt.payload, sizeof(client_pkt.payload));
               }
               //Update latest_ack_num
               server_state.latest_ack_num = client_pkt.ack;
               // Update flag
               is_handshaked = true;
            }
         }
         //Send the first handshake packet to client
         if (client_connected){
            if(first_handshake){
               Packet first_handshake_pkt = {server_state.expected_seq_num, server_state.next_seq_num, 
                                           0, 3, 0};
               convert_to_bigEndian(&first_handshake_pkt);
               print_diag(&first_handshake_pkt, SEND);
               int did_send = sendto(sockfd, &first_handshake_pkt, sizeof(first_handshake_pkt), 
                                    0, (struct sockaddr*) &clientaddr, sizeof(clientaddr));
               first_handshake = false;
               server_state.next_seq_num ++;
               fprintf(stderr, "handshaked");
            }
         }
         continue;
      }
      // Start sending data
      else{
         // send packets
         if(server_state.current_window_size < maximum_window_size){
            read_and_send(&server_state, sockfd, &clientaddr);
         }
         else{
            server_state.ack_pending = true;
         }
         //receive packets
         receive_and_ack(&server_state, sockfd, &clientaddr, &clientsize);
         //retransmit packets
         gettimeofday(&server_state.current_time, NULL);
         if(time_diff(&server_state.last_received_time, &server_state.current_time)) {
               retransmit(&server_state, server_state.send_buffer, sockfd, &clientaddr);
               gettimeofday(&server_state.last_received_time, NULL);
         }
      }
   }
    /* 8. You're done! Terminate the connection */     
    close(sockfd);
    return 0;
}