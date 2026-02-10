#include <iostream>
#include <vector>
#include <cstring>

// Definitions from the original code
#define HEADER_SIZE 2 // 1 + 1
#define MAX_MESSAGE_SIZE 128
#define MAX_USERNAME_SIZE 16
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

typedef struct SynerPMessageHeader {
    uint8_t size; // calculated and filled by client after payload has been stored. on server, anytime recv returns < 
    _e_SynerPCommand cmd; // 1 byte enum
} SynerPMessageHeader_t;

typedef struct SynerPMessage {
    SynerPMessageHeader_t header;
    char uname[MAX_USERNAME_SIZE]; // must be nul terminated.
    char data[MAX_PAYLOAD_SIZE];
} SynerPMessage_t;

// Encoder and decoder function prototypes
void SynerPMessageHeaderEncode(SynerPMessageHeader_t &msg_struct, std::vector<char>& buffer, size_t &buffer_size);
void SynerPMessageHeaderDecode(std::vector<char>& buffer, SynerPMessageHeader_t &msg_struct, size_t &buffer_size);
void SynerPMessageEncode(SynerPMessage_t &msg_struct, std::vector<char>& buffer, size_t &buffer_size);
void SynerPMessageDecode(std::vector<char>& buffer, SynerPMessage_t &msg_struct, size_t &buffer_size);

// Function implementations
void SynerPMessageHeaderEncode(SynerPMessageHeader_t &msg_struct, std::vector<char>& buffer, size_t &buffer_size) {
    buffer.push_back(static_cast<char>(msg_struct.size));
    buffer.push_back(static_cast<char>(msg_struct.cmd));
    buffer_size = buffer.size();
}

void SynerPMessageHeaderDecode(std::vector<char>& buffer, SynerPMessageHeader_t &msg_struct, size_t &buffer_size) {
    if (buffer.size() < HEADER_SIZE) return; // Error: Buffer too small
    msg_struct.size = static_cast<uint8_t>(buffer[0]);
    msg_struct.cmd = static_cast<_e_SynerPCommand>(buffer[1]);
    buffer_size = HEADER_SIZE;
}

void SynerPMessageEncode(SynerPMessage_t &msg_struct, std::vector<char>& buffer, size_t &buffer_size) {
    msg_struct.header.size = HEADER_SIZE + strlen(msg_struct.uname) + strlen(msg_struct.data) + 2;
    SynerPMessageHeaderEncode(msg_struct.header, buffer, buffer_size);
    buffer.insert(buffer.end(), msg_struct.uname, msg_struct.uname + MAX_USERNAME_SIZE);
    buffer_size = buffer.size();
    buffer.insert(buffer.end(), msg_struct.data, msg_struct.data + strlen(msg_struct.data));
    buffer_size = buffer.size();
}

void SynerPMessageDecode(std::vector<char>& buffer, SynerPMessage_t &msg_struct, size_t &buffer_size) {
    size_t offset = 0;
    
    // Decode the message header
    SynerPMessageHeaderDecode(buffer, msg_struct.header, buffer_size);
    offset += HEADER_SIZE;
    
    // Check if the buffer is large enough to contain the username
    if (buffer.size() < offset + MAX_USERNAME_SIZE) {
        std::cerr << "Error: Insufficient buffer size for username" << std::endl;
        return;
    }
    
    // Copy the username from the buffer to msg_struct.uname
    std::copy(buffer.begin() + offset, buffer.begin() + offset + MAX_USERNAME_SIZE, msg_struct.uname);
    msg_struct.uname[MAX_USERNAME_SIZE - 1] = '\0'; // Ensure null termination
    offset += MAX_USERNAME_SIZE;
    
    // Calculate the payload size based on the message size and subtract the header size and username size
    size_t payload_size = msg_struct.header.size - HEADER_SIZE - MAX_USERNAME_SIZE;
    
    // Check if the buffer is large enough to contain the payload
    if (buffer.size() < offset + payload_size) {
        std::cerr << "Error: Insufficient buffer size for payload" << std::endl;
        return;
    }
    
    // Copy the payload data from the buffer to msg_struct.data
    std::copy(buffer.begin() + offset, buffer.begin() + offset + payload_size, msg_struct.data);
    msg_struct.data[payload_size] = '\0'; // Ensure null termination
    
    // Update the buffer size
    buffer_size = msg_struct.header.size;
}


std::string generate_login_response(std::string userID, _e_SynerPLoginResponse r_type) {
    switch (r_type) {
        case USER_EXIST:
            return "User [" + userID + "]" + " already exists!";
            break;
        case USER_NEW:
            return "New User [" + userID + "]" + " logged in";
            break;
        default:
            return "Invalid response type"; // all are null terminated.
    }
}

int main() {
    SynerPMessage_t original_message {};
    //original_message.header.size = HEADER_SIZE + MAX_USERNAME_SIZE + 5; // Example payload size 5
    original_message.header.cmd = LOGIN_REQUEST;
    std::string userID = "abcde";
    memcpy(original_message.uname, userID.c_str(), userID.length());
    
    std::string login_response = generate_login_response(userID, USER_NEW);
    //std::cout <<login_response.length() << std::endl;
    memcpy(original_message.data, login_response.c_str(), MAX_PAYLOAD_SIZE);

    std::vector<char> buffer;
    size_t buffer_size = 0;

    // Encode the message
    SynerPMessageEncode(original_message, buffer, buffer_size);
    //std::cout << buffer_size << std::endl;

    // Decode the message
    SynerPMessage_t decoded_message {};
    SynerPMessageDecode(buffer, decoded_message, buffer_size);

    // Display the decoded message
    std::cout << "Decoded Message:\n";
    std::cout << "Size: " << static_cast<int>(decoded_message.header.size) << "\n";
    std::cout << "Command: " << static_cast<int>(decoded_message.header.cmd) << "\n";
    std::cout << "Username: " << decoded_message.uname << "\n";
    std::cout << "Data: " << decoded_message.data<< "\n";
    std::cout << strlen(decoded_message.data) << "\n";

    return 0;
}
