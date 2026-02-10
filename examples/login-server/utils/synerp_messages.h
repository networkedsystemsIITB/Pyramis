/**
 * FILE: synerp_messages.h
 * -----------------------
 * This file defines the single message format that is used by the 
 * simple client-server that uses a toy "SynerP" L-7 protocol 
 * over TCP/SCTP/UDP. Uses length-prefixed message-framing.
 * all payloads are null terminated.
 */
#ifndef __SYNERP_MESSAGES_H__
#define __SYNERP_MESSAGES_H__
#include <stdint.h>
#include <iostream>
#include <cstdint>  // for std::int8_t

#define HEADER_SIZE 2 // 1 + 1
#define MAX_MESSAGE_SIZE_P 100
#define MAX_USERNAME_SIZE 8 
#define MAX_PAYLOAD_SIZE (MAX_MESSAGE_SIZE_P - HEADER_SIZE - MAX_USERNAME_SIZE) 

typedef enum SynerPCommand: std::uint8_t {
    ECHO = 0, 
    LOGIN_REQUEST, // 1
    LOGIN_RESPONSE, // 2
    TIMER_NOTIFICATION // 3
} _e_SynerPCommand;

typedef enum LoginResponse: std::uint8_t  {
    USER_EXIST = 0,
    USER_NEW,
    USER_TIMER_EXPIRY
} _e_SynerPLoginResponse;

#pragma pack(push, 1)
typedef struct SynerPMessageHeader {
    uint8_t size; // calculated and filled by client after payload has been stored. on server, anytime recv returns < 
    _e_SynerPCommand cmd; // 1 byte enum
} SynerPMessageHeader_t;

typedef struct Username {
    uint8_t sz;
    char contents[MAX_USERNAME_SIZE];
} Username_t;

typedef struct DataBlock {
    uint8_t sz;
    char contents[MAX_PAYLOAD_SIZE];
} DataBlock_t;

typedef struct SynerPMessage {
    SynerPMessageHeader_t header;
    Username_t uname;
    DataBlock_t data;
} SynerPMessage_t;

#pragma pack(pop)

#endif