#pragma once

#include <stdint.h>
#include <unistd.h>

// Initialize security layer
void init_sec(int initial_state);

// Get input from security layer
ssize_t input_sec(uint8_t* buf, size_t max_length);

// Output to security layer
void output_sec(uint8_t* buf, size_t length);
void construct_tlv(uint8_t *message, uint8_t message_type, uint16_t message_length, uint8_t *data);
void construct_lv (uint8_t *message, uint16_t message_length, uint8_t *data);
void parse_tlv(uint8_t* message, uint8_t* message_type, uint16_t* message_length, uint8_t* data);
void parse_lv(uint8_t* message, uint8_t* messgae_length, uint8_t* data);

