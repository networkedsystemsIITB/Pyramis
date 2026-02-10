/**
 * FILE: synerp_messages.h
 * -----------------------
 * This file defines the single message format that is used by the 
 * simple client-server that uses a toy "SynerP" L-7 protocol 
 * over TCP/SCTP/UDP. Uses length-prefixed message-framing.
 * null terminator not assumed.
 */
#ifndef __SYNERP_MESSAGES_H__
#define __SYNERP_MESSAGES_H__
#include <stdint.h>
#include <iostream>
#include <cstdint>  // for std::int8_t

#define HEADER_SIZE 2 // 1 + 1
#define MAX_MESSAGE_SIZE 100
#define MAX_USERNAME_SIZE 8 
#define MAX_PAYLOAD_SIZE (MAX_MESSAGE_SIZE - HEADER_SIZE - MAX_USERNAME_SIZE) 

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

typedef enum TimerType: std::uint8_t  {
    T_LOGIN_FORGET = 1
} _e_TimerType;

#pragma pack(push, 1)

typedef struct SynerPMessageHeader {
    uint8_t size; // without null
    _e_SynerPCommand cmd; // 1 byte enum
} SynerPMessageHeader_t;

typedef struct Username {
    uint8_t sz; // without null
    char contents[MAX_USERNAME_SIZE]; //with null
} Username_t;

typedef struct DataBlock {
    uint8_t sz; //without null
    char contents[MAX_PAYLOAD_SIZE]; // with null
} DataBlock_t;

typedef struct SynerPMessage {
    SynerPMessageHeader_t header;
    Username_t uname;
    DataBlock_t data;
} SynerPMessage_t;

#pragma pack(pop)

//@@encoder: SynerPMessageHeader_t
void SynerPMessageHeaderEncode(SynerPMessageHeader_t &msg_struct, std::vector<char>& bufer, size_t &buffer_size);

//@@decoder: SynerPMessageHeader_t
void SynerPMessageHeaderDecode(std::vector<char>& message, SynerPMessageHeader_t &msg_struct, size_t &buffer_size);

// @@encoder: SynerPMessage_t
void SynerPMessageEncode(SynerPMessage_t &msg_struct, std::vector<char>& buffer, size_t &buffer_size);

// @@decoder: SynerPMessage_t
void SynerPMessageDecode(std::vector<char>& buffer, SynerPMessage_t &msg_struct, size_t &buffer_size);

// create a custom response string
std::string generate_login_response(std::string userID, _e_SynerPLoginResponse r_type);

#endif
