#include <cstdlib>
#include <cstring>
#include <vector>
#include <cassert>
#include <cstdio>
#include "synerp_messages.h"

//@@decoder: SynerPMessageHeader_t
void SynerPMessageHeaderDecode(std::vector<char>& buffer, SynerPMessageHeader_t &msg_header_struct, size_t &buffer_size) {
    // if (buffer.size() < HEADER_SIZE) return; // Error: Buffer too small
    msg_header_struct.size = static_cast<uint8_t>(buffer[0]);
    msg_header_struct.cmd = static_cast<_e_SynerPCommand>(buffer[1]);
    buffer_size = HEADER_SIZE;
}

// @@encoder: SynerPMessage_t
void SynerPMessageEncode(SynerPMessage_t &msg_struct, std::vector<char>& buffer, size_t &buffer_size) {
    // Calculate the total size of the message
    // without null termination.
    msg_struct.header.size = HEADER_SIZE; // 1 for cmd, 1 for size

    if (msg_struct.uname.sz) {
        msg_struct.header.size += (sizeof(uint8_t) + msg_struct.uname.sz);
    }
    if (msg_struct.data.sz) {
        msg_struct.header.size += (sizeof(uint8_t) + msg_struct.data.sz);
    }
    // Print debug information
    printf("Message size (header.size): %d\n", msg_struct.header.size); // no nul

    // Encode the header
    size_t offset = 0;
    buffer[offset] = msg_struct.header.size;
    offset++;
    buffer[offset] = msg_struct.header.cmd;
    offset++;

    // copy username size
    if (msg_struct.uname.sz > 0) {
        buffer[offset] = msg_struct.uname.sz;
        offset++;
        // Copy the username
        std::memcpy(&buffer[offset], msg_struct.uname.contents, msg_struct.uname.sz);
        offset += msg_struct.uname.sz;
        buffer[offset] = '\0'; // ensure null-termination
        offset++;
    }

    if (msg_struct.data.sz > 0) {
        // copy data payload size
        buffer[offset] = msg_struct.data.sz;
        offset++;
        // Copy the data payload
        std::memcpy(&buffer[offset], msg_struct.data.contents, msg_struct.data.sz); // +1 to include null terminator
        offset += msg_struct.data.sz;
        buffer[offset] = '\0'; // ensure null-termination
        offset++;
    }
    // printf("Encoded bytes (with null): %d\n", offset);
    // printf("Expected message bytes (without null): %d\n", msg_struct.header.size);
    // assert(offset == msg_struct.header.size + 2);

    // Update the buffer size
    buffer_size = offset;

    // Resize the buffer to the required size
    buffer.resize(buffer_size);
}

// @@decoder: SynerPMessage_t
void SynerPMessageDecode(std::vector<char>& buffer, SynerPMessage_t &msg_struct, size_t &buffer_size) {
    size_t offset = 0;
    
    // Decode the message header
    SynerPMessageHeaderDecode(buffer, msg_struct.header, buffer_size); //bufsz = HEADER_SZ
    offset += HEADER_SIZE; // 3rd byte

    // uname sz
    msg_struct.uname.sz = buffer[offset];
    if (msg_struct.uname.sz > 0) {
        offset += sizeof(uint8_t); // 4th byte
        // uname contents 
        memcpy(msg_struct.uname.contents, &buffer[offset],  msg_struct.uname.sz + 1); // for nul
        offset += (msg_struct.uname.sz + 1);
    }
    // data sz
    msg_struct.data.sz = buffer[offset];
    if (msg_struct.data.sz > 0) {
        offset += sizeof(uint8_t);

        //data contents
        memcpy(msg_struct.data.contents, &buffer[offset],  msg_struct.data.sz + 1); // for nul
        offset += (msg_struct.data.sz + 1);
    }
    
    // printf("Decoded bytes: %d\n", offset + 1);
    // printf("Expected message bytes: %d\n", msg_struct.header.size);
    //assert(offset == msg_struct.header.size - 1);
    
    // Update the buffer size
    buffer_size = offset;
}