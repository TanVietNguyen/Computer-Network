DESIGN CHOICE
I created a struct typed State containing all variables, including sequence number, sending buffer and receiving buffer, time, acknowledgement count, which client.c and server.c both uses.
The handshake process and data transmission happen in one loop. I use a flag to keep track when the handshake is finished. 
I created 3 main functions which are read_and_send(), receive_and_ack() and retranmisstion(). Both client.c and server.c calls these functions after the handshake is establish. I also created some sub functions to handle scan the receiving buffer, scan the sending buffer, adding packets, removing packets and some other small function.
I used linked list to store sent packets and receiving packets. However, I did not use the maximum size 20240 bytes as a condition to stop reading from stdin, I instead used the condition of maximum windown size. I know it is not ideal, but it is simpler to implement and easier for my debug process.
ENCOUNTERED ISSUES
I had a silly mistake is that i changed order of the fields in Packet struct, so when running the test cases with reference host, I failed all the test cases. 
I had the problem with aligning the correct SEQ between refclient and server. Because I did not consider the fact that last packet, the client send during handshake, can carry a payload, i just put a condition there, fixed the problem.
When implementing the linked-list, I unkowingly accessed some memory places that caused segmentation fault. I just used many fprint commands to trace the bug and fix it.
I fotgot to convert bytes ordering back and forth. Some caused subtle bugs. I was only able to find out after printing out and tracing sent and received packets. 
I also forgot that sizeof(packet.payload) and packet.length are totally different, and this caused some weird unintended behaviors in my program.
I failed the dropping simulation test casse. I had to trace through all the sent and received packets in the output log to realize that I messed the acknowledged numbers when retransmitting packets. I changed the ackknowledged number of all retranmitted packets to the current acknowledged number.