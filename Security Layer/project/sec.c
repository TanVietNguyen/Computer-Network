#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>

#include "consts.h"
#include "io.h"
#include "security.h"
#include <openssl/evp.h>

int state_sec = 0;              // Current state for handshake
uint8_t nonce[NONCE_SIZE];      // Store generated nonce to verify signature
uint8_t peer_nonce[NONCE_SIZE]; // Store peer's nonce to sign

void init_sec(int initial_state) {
    state_sec = initial_state;
    init_io();

    if (state_sec == CLIENT_CLIENT_HELLO_SEND) { 
        generate_private_key(); 
        derive_public_key(); 
        derive_self_signed_certificate(); 
        load_ca_public_key("ca_public_key.bin"); 
    } else if (state_sec == SERVER_CLIENT_HELLO_AWAIT) { 
        load_certificate("server_cert.bin"); 
        load_private_key("server_key.bin"); 
        derive_public_key(); 
    } 
    
    generate_nonce(nonce, NONCE_SIZE);
}

void construct_tlv(uint8_t *message, uint8_t message_type, size_t message_length, uint8_t *data){
    memcpy(message + 3, data, message_length);
    message[0] = message_type;
    size_t buf_len = htons(message_length);
    memcpy(message + 1, &buf_len, 2);
}

void construct_lv (uint8_t *message, size_t message_length, uint8_t *data){
    memcpy(message + 2, data, message_length);
    message[0] = (message_length >> 8)  & 0xFF;
    message[1] = message_length & 0xFF;
 }
 
ssize_t input_sec(uint8_t* buf, size_t max_length) {
    // This passes it directly to standard input (working like Project 1)
    // return input_io(buf, max_length);

    switch (state_sec) {
    case CLIENT_CLIENT_HELLO_SEND: {
        print("SEND CLIENT HELLO");

        /* Insert Client Hello sending logic here */
        size_t size = 0;
        // Construct Nonce of client's message
        construct_tlv(buf, NONCE_CLIENT_HELLO, NONCE_SIZE, nonce);
        size = size + NONCE_SIZE + 3;
        // Construct client's message
        construct_tlv(buf, CLIENT_HELLO, size, buf);
        size = size + 3;
        state_sec = CLIENT_SERVER_HELLO_AWAIT;
        return size;
    }
    case SERVER_SERVER_HELLO_SEND: {
        print("SEND SERVER HELLO");
        size_t size = 0;
        /* Insert Server Hello sending logic here */
        // First 3 bytes are reserved for type and length of the message
        // Construc Nonce of server's message
        construct_tlv(buf, NONCE_SERVER_HELLO, NONCE_SIZE, nonce);
        size = size + NONCE_SIZE + 3; 
        // Add certificate to Server's message
        memcpy(buf + size, certificate, cert_size);
        size = size + cert_size;
        // Construct client's nonce signature of server's message
        uint8_t nonce_signature[128];
        size_t signature_length = sign(peer_nonce, NONCE_SIZE, nonce_signature);
        construct_tlv(buf + size, NONCE_SIGNATURE_SERVER_HELLO, signature_length, nonce_signature);
        size = size + signature_length + 3;
        // Construct server's hello message
        construct_tlv(buf, SERVER_HELLO, size, buf);
        size = size + 3;
        state_sec = SERVER_KEY_EXCHANGE_REQUEST_AWAIT;
        return size;
    }
    case CLIENT_KEY_EXCHANGE_REQUEST_SEND: {
        print("SEND KEY EXCHANGE REQUEST");
        size_t size = 0;
        /* Insert Key Exchange Request sending logic here */
        // Coonstruct the client's certificate
        memcpy(buf, certificate, cert_size);
        size = size + cert_size;
        // Generate 2 needed keys
        derive_secret();
        derive_keys();

        uint8_t server_nonce_signatue[128];

        size_t signature_len = sign(peer_nonce, NONCE_SIZE, server_nonce_signatue);

        // Construct the server's signature nonce
        construct_tlv(buf + size, NONCE_SIGNATURE_KEY_EXCHANGE_REQUEST, signature_len, server_nonce_signatue);
        size = size + signature_len + 3;
        // Construct key exchange request message
        construct_tlv(buf, KEY_EXCHANGE_REQUEST, size, buf);
        size = size + 3;
        state_sec = CLIENT_FINISHED_AWAIT;
        return size;
    }
    case SERVER_FINISHED_SEND: {
        print("SEND FINISHED");

        /* Insert Finished sending logic here */
        size_t size = 0;
        // Construct finished message
        construct_tlv(buf, FINISHED, 0, NULL);
        size = size + 3;
        derive_secret();
        derive_keys();
        state_sec = DATA_STATE;
        return size;
    }
    case DATA_STATE: {
        /* Insert Data sending logic here */

        // PT refers to the amount you read from stdin in bytes
        // CT refers to the resulting ciphertext size
        // fprintf(stderr, "SEND DATA PT %ld CT %lu\n", stdin_size, cip_size);
        uint8_t plaintext[943];
        size_t plaintext_size = input_io(plaintext, 943);
        if(plaintext_size <= 0){
            return 0;
        }
        // generate initial vector
        uint8_t initial_vector[IV_SIZE];
        generate_nonce(initial_vector, IV_SIZE);
         // encrypt the plaintext
        uint8_t ciphertext[944];
        size_t ciphertext_size = encrypt_data(plaintext, plaintext_size, initial_vector, ciphertext);
        if (ciphertext_size > 944)
        {
            fprintf(stderr, "Ciphertext size is invalid\n");
            exit(4);
        }
        // Create HMAC digest
        uint8_t hmac_digest[IV_SIZE + 944];
        memcpy(hmac_digest, initial_vector, IV_SIZE);
        memcpy(hmac_digest + IV_SIZE, ciphertext, ciphertext_size);

        uint8_t buffer_digest[MAC_SIZE];
        hmac(hmac_digest, IV_SIZE + ciphertext_size, buffer_digest);
        
        size_t size = 0;
        // Contruct initialization vector
        construct_tlv(buf, INITIALIZATION_VECTOR, IV_SIZE, initial_vector);
        size = size + IV_SIZE + 3;
        // Construct ciphertext
        construct_tlv(buf + size, CIPHERTEXT, ciphertext_size, ciphertext);
        size = size + ciphertext_size + 3;
        // Construct MAC
        construct_tlv(buf + size, MESSAGE_AUTHENTICATION_CODE, MAC_SIZE, buffer_digest);
        size = size + MAC_SIZE + 3;
        // Contruct data message
        construct_tlv(buf, DATA, size, buf);
        size = size + 3;
        return size;
    }
    default:
        return 0;
    }
}

void parse_tlv(uint8_t* message, uint8_t* message_type, size_t* message_length, uint8_t* data){
    *message_type = message[0];
    memcpy(message_length, message + 1, 2);
    *message_length = ntohs(*message_length);
    memcpy(data, message + 3, *message_length );
}
void output_sec(uint8_t* buf, size_t length) {
    // This passes it directly to standard output (working like Project 1)
    // return output_io(buf, length);

    switch (state_sec) {
    case SERVER_CLIENT_HELLO_AWAIT: {
        if (*buf != CLIENT_HELLO)
            exit(4);

        print("RECV CLIENT HELLO");

        /* Insert Client Hello receiving logic here */
        size_t size = 0; 
        uint8_t client_hello_type;
        size_t client_hello_length;
        uint8_t client_nonce[35];
        uint8_t client_nonce_type;
        size_t client_nonce_length;
        // parse the client's hello message
        parse_tlv(buf, &client_hello_type, &client_hello_length, client_nonce);
        size = size + 3;
        // parse the client's nonce, and store its data in peer_nonce
        parse_tlv(buf + size, &client_nonce_type, &client_nonce_length, peer_nonce);
        state_sec = SERVER_SERVER_HELLO_SEND;
        break;
    }
    case CLIENT_SERVER_HELLO_AWAIT: {
        if (*buf != SERVER_HELLO)
            exit(4);

        print("RECV SERVER HELLO");

        /* Insert Server Hello receiving logic here */
        size_t size = 0;
        uint8_t server_hello_type;
        size_t server_hello_length;
        uint8_t server_hello_data[300];
        // parse the server's hello message
        print("0======================");
        parse_tlv(buf, &server_hello_type, &server_hello_length, server_hello_data);
       
        size = size + 3;
        //parse the server_hello_data to get server's nonce
        
        uint8_t server_nonce_type;
        size_t server_nonce_length;
        uint8_t server_nonce_data[40];
        parse_tlv(buf + size, &server_nonce_type, &server_nonce_length, peer_nonce);
        size = size + 3 + server_nonce_length;
         print("1======================");

        // parse the server_hello_data to get certificate
        uint8_t certificate_type;
        size_t certificate_length;
        uint8_t certificate_data[200];
        parse_tlv(buf + size, &certificate_type, &certificate_length, certificate_data);
        size = size + 3;
        // parse certificate_data to get public key 
        uint8_t server_public_key_type;
        size_t server_public_key_length;
        uint8_t server_public_key_data[128];
        parse_tlv(buf + size, &server_public_key_type, &server_public_key_length, server_public_key_data);
        load_peer_public_key(server_public_key_data, server_public_key_length);
        size = size + 3 + server_public_key_length;
        // parse certificate_data to get signature
        uint8_t server_sig_type;
        size_t server_sig_length;
        uint8_t server_sig_data[128];
        parse_tlv(buf + size, &server_sig_type, &server_sig_length, server_sig_data);
        size = size + 3 + server_sig_length;

        print("2======================");
        //Verify if server public key is signed by CA authority
        if (verify(server_public_key_data, server_public_key_length, server_sig_data, server_sig_length, ec_ca_public_key) != 1)
        {
            fprintf(stderr, "Error: server's public key is invalid\n");
            exit(1);
        }
        // parse server_hello_data to get client's nonce signature
        uint8_t nonce_sig_type;
        size_t nonce_sig_length;
        uint8_t nonce_sig_data[128];
        parse_tlv(buf + size, &nonce_sig_type, &nonce_sig_length, nonce_sig_data);
        size = size + 3 + nonce_sig_length;

        // verify if nonce sig is signed by server
        if (verify(nonce, NONCE_SIZE, nonce_sig_data, nonce_sig_length, ec_peer_public_key) != 1)
        {
            fprintf(stderr, "Error: client's nonce signature is not signed\n");
            exit(2);
        }
        state_sec = CLIENT_KEY_EXCHANGE_REQUEST_SEND;
        break;
    }
    case SERVER_KEY_EXCHANGE_REQUEST_AWAIT: {
        if (*buf != KEY_EXCHANGE_REQUEST)
            exit(4);

        print("RECV KEY EXCHANGE REQUEST");

        /* Insert Key Exchange Request receiving logic here */
        size_t size = 0;
        uint8_t key_exchange_request_type;
        size_t key_exchange_request_len;
        uint8_t key_exchange_request_data[300];
        print("0============================");
        // Parse client's key exchange request
        parse_tlv(buf, &key_exchange_request_type, &key_exchange_request_len, key_exchange_request_data);
        size = size + 3;
         print("1============================");
        // Parse client's exchange key request to get its certificate
        uint8_t cert_type;
        size_t cert_len;
        uint8_t cert_data[200];
        parse_tlv(buf + size, &cert_type, &cert_len, cert_data);
        size = size + 3;
        //Parse client's certificate to get its public key
        uint8_t client_pub_key_type;
        size_t client_pub_key_len;
        uint8_t client_pub_key_data[128];
        parse_tlv(buf + size, &client_pub_key_type, &client_pub_key_len, client_pub_key_data);
        size = size + 3 + client_pub_key_len;
        load_peer_public_key(client_pub_key_data, client_pub_key_len);
        // Parse client's certificate to get its signature
        uint8_t client_sig_type;
        size_t client_sig_len;
        uint8_t client_sig_data[128];
        parse_tlv(buf + size, &client_sig_type, &client_sig_len, client_sig_data);
        size = size + 3 + client_sig_len;
        if (verify(client_pub_key_data, client_pub_key_len, client_sig_data, client_sig_len, ec_peer_public_key) != 1)
        {
            fprintf(stderr, "Error: client's public key is not signed\n");
            exit(1);
        }
        // Parse the client's key exchange requets to get server's nonce signature
        uint8_t nonce_sig_type;
        size_t nonce_sig_len;
        uint8_t nonce_sig_data[128];
        parse_tlv(buf + size, &nonce_sig_type, &nonce_sig_len, nonce_sig_data);
        size = size + 3 + nonce_sig_len;
        // verify if server's nonce signature is signed
        if (verify(nonce, NONCE_SIZE, nonce_sig_data, nonce_sig_len, ec_peer_public_key) != 1)
        {
            fprintf(stderr, "Error: server's nonce signature is not signed by client\n");
            exit(2);
        }
        state_sec = SERVER_FINISHED_SEND;
        break;
    }
    case CLIENT_FINISHED_AWAIT: {
        if (*buf != FINISHED)
            exit(4);

        print("RECV FINISHED");

        state_sec = DATA_STATE;
        break;
    }
    case DATA_STATE: {
        if (*buf != DATA)
            exit(4);

        /* Insert Data receiving logic here */

        // PT refers to the resulting plaintext size in bytes
        // CT refers to the received ciphertext size
        // fprintf(stderr, "RECV DATA PT %ld CT %hu\n", data_len, cip_len);
        size_t size = 0;
        uint8_t data_type;
        size_t data_len;
        uint8_t data_data[1024];
        //Parse data message to get the data of message
        parse_tlv(buf, &data_type, &data_len, data_data);
        size = size + 3;
        // Parse the data part of message to get inital vector
        uint8_t iv_type;
        size_t iv_len;
        uint8_t iv_data[IV_SIZE];
        parse_tlv(buf + size, &iv_type, &iv_len, iv_data);
        size = size + 3 + iv_len;
        // Parse the data part of message to get the ciphertext
        uint8_t ciphertext_type;
        size_t ciphertext_len;
        uint8_t ciphertext_data[944];
        parse_tlv(buf + size, &ciphertext_type, &ciphertext_len, ciphertext_data);
        size = size + 3 + ciphertext_len;
        // Parse the data part of message to get MAC
        uint8_t MAC_type;
        size_t MAC_len;
        uint8_t MAC_data[MAC_SIZE];
        parse_tlv(buf + size, &MAC_type, &MAC_len, MAC_data);
        size = size + 3 + MAC_len;
        // Calcualte HMAC digest
        uint8_t HMAC_digest[IV_SIZE + 944];
        memcpy(HMAC_digest, iv_data, IV_SIZE);
        memcpy(HMAC_digest + IV_SIZE, ciphertext_data, ciphertext_len);

        uint8_t HMAC_buffer[MAC_SIZE];
        hmac(HMAC_digest, IV_SIZE + ciphertext_len, HMAC_buffer);
        // Verify if the HMAC digest matched MAC_data
        if (memcmp(MAC_data, HMAC_buffer, MAC_SIZE) != 0)
        {
            fprintf(stderr, "Error: HMAC digest does not match MAC data\n");
            exit(3); 
        }
        // decrypt ciphertext
        uint8_t plaintext_buf[943];
        size_t plaintext_size = decrypt_cipher(ciphertext_data, ciphertext_len, iv_data, plaintext_buf);
        if (plaintext_size > 943)
        {
            fprintf(stderr, "Error: Plaintext size is invalid\n");
            exit(4);
        }

        return output_io(plaintext_buf, plaintext_size);
        break;
    }
    default:
        break;
    }
}
