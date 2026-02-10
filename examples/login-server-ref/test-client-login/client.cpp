#include <iostream>
#include <vector>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <mutex>
#include "synerp_messages.h"
#include <cstdio>
#include <sys/epoll.h>

#define S_PORT 5858
#define C_PORT 6868
#define MAX_EPOLL_EVENTS 10

std::mutex print_mutex;

std::string generate_login_response(_e_SynerPLoginResponse r_type) {
    switch (r_type) {
        case USER_EXIST:
            return "User already exists!";
        case USER_NEW:
            return "New User logged in";
        default:
            return "Invalid response type";
    }
}

void sendLoginRequest(int socket, std::string &username) {
    SynerPMessage_t login_req {};
    
    login_req.header.cmd = LOGIN_REQUEST;
    
    memcpy(login_req.uname.contents, username.data(), username.size());
    login_req.uname.sz = username.size();

    std::string resp = generate_login_response(USER_NEW);
    memcpy(login_req.data.contents, resp.data(), resp.size());
    login_req.data.sz = resp.size();

    std::vector<char> login_req_enc(MAX_MESSAGE_SIZE, 0);
    size_t login_req_enc_sz {};
    SynerPMessageEncode(login_req, login_req_enc, login_req_enc_sz);

    ssize_t sent = sendto(socket, login_req_enc.data(), login_req_enc_sz, 0, NULL, 0);

    if (sent < 0) {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cerr << "Failed to send login request" << std::endl;
    } else {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "Login request sent, <" << sent << " bytes>" << std::endl;
    }
}

void recv_response(int client_socket) {
    std::vector<char> recv_buffer(MAX_MESSAGE_SIZE, 0);
    struct sockaddr_in dest_addr {};
    socklen_t len = sizeof(dest_addr);
    int rc = recvfrom(client_socket, recv_buffer.data(), MAX_MESSAGE_SIZE, 0, (struct sockaddr*)&dest_addr, &len);
    if (rc == -1) {
        std::lock_guard<std::mutex> lock(print_mutex);
        printf("recvfrom failed, Error: %s\n", strerror(errno));
    } else if (rc == 0) {
        std::lock_guard<std::mutex> lock(print_mutex);
        printf("%s", "recvfrom returned 0 len msg\n");
    } else {
        recv_buffer.resize(rc);
    }

    SynerPMessage_t login_response {};
    size_t login_response_enc_sz {};
    SynerPMessageDecode(recv_buffer, login_response, login_response_enc_sz);

    if (login_response.header.cmd == TIMER_NOTIFICATION) {
        printf("\n[SERVER]: %s\n", login_response.data.contents);
    } else {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "\n[SERVER]: " << login_response.data.contents << ", <" << login_response.uname.contents << ">\n";
    }
    std::cout << "Username: " << std::flush;

    
}

void receiveResponses(int clientSocket, int epfd) {
    struct epoll_event events[MAX_EPOLL_EVENTS];
    while (true) {
        int nfds = epoll_wait(epfd, events, MAX_EPOLL_EVENTS, -1);
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == clientSocket) {
                recv_response(clientSocket);
            }
        }
    }
}

int main() {
    int clientSocket = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    if (clientSocket < 0) {
        std::cerr << "Failed to create socket" << std::endl;
        return 1;
    }

    struct sockaddr_in local_addr {};
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(C_PORT);
    local_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(clientSocket, (struct sockaddr *)&local_addr, sizeof(local_addr)) == -1) {
        printf("Bind failed, port %d, Error %s", C_PORT, strerror(errno));
        return -1;
    }

    struct sockaddr_in server_addr {};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(S_PORT);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(clientSocket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        printf("Connect failed, port %d, Error %s", C_PORT, strerror(errno));
        return -1;
    }

    int epfd = epoll_create1(0);
    struct epoll_event conn_event {};
    conn_event.data.fd = clientSocket;
    conn_event.events = EPOLLIN;

    if (epoll_ctl(epfd, EPOLL_CTL_ADD, clientSocket, &conn_event) == -1) {
        std::cerr << "Epoll ctl failed for fd " << clientSocket << ": " << std::strerror(errno) << "\n";
    }

    std::thread recv_thread(receiveResponses, clientSocket, epfd);
    recv_thread.detach();

    std::string username;
    while (true) {
        std::cout << "Username: ";
        std::getline(std::cin, username);

        if (username.size() > MAX_USERNAME_SIZE) {
            std::cerr << "Username too long, try again" << "\n";
            continue;
        }
        sendLoginRequest(clientSocket, username);
    }

    close(clientSocket);
    return 0;
}
