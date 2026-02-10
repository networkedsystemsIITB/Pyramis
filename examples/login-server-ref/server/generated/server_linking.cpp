/**
 * FILE: server.cpp
 * ---------------- 
 * This NF implements a login procedure via a simple application protocol. 
 * The call-flow is simple:
 * 1. NF_B->server (login_request)
 * 2. server->NF_B (login_response) 
*/

#include "linking.h"
#include "contexts.h"
#include <algorithm>
#define C_PORT 6868 // temp

void server_entry(std::vector<char>& message, int length, int sockfd, struct nfvInstanceData *nfvInst) {
    
    // DECODE(SynerPMessageDecode, m, message, m_enc_sz)
    SynerPMessage_t m {};
    size_t m_enc_sz = {}; 
    SynerPMessageDecode(m, message, m_enc_sz);

    // SET(userCMD, m.header.cmd) 
    _e_SynerPCommand userCMD = m.header.cmd;

    // SET(userID, m.uname.contents)
    std::string userID(m.uname.contents); // nul term.

    int procedure_key = generate_procedure_key();

    if (userCMD == ECHO) {
        do_echo(m, sockfd, nfvInst);
    } else {
        if(userCMD == LOGIN_REQUEST) {
            // UDF(procedure_key, generate_procedure_key

            printf("Procedure key: %d, sockfd: %d\n", procedure_key, sockfd);
            
            // CALL(do_login, userID, procedure_key)
            do_login(userID, procedure_key, sockfd, nfvInst);
        } else {
            std::cout << "Invalid command: " << userCMD << "\n";
        }
    }
}

// receiving fd == sending fd
//----
// EVENT do_echo(message_body):
void do_echo(SynerPMessage_t message_body, int sockfd, struct nfvInstanceData *nfvInst) {
    // ENCODE(SynerPMessageEncoder, message_body_enc, message_body, message_body_enc_sz)
    size_t message_body_enc_sz {};
    std::vector<char> message_body_enc(MAX_MESSAGE_SIZE, 0);
    SynerPMessageEncode(message_body_enc, message_body, message_body_enc_sz); // null added. 
    
    // SEND(message_body, Server, NF_B, NULL)
    send_data("127.0.0.1", C_PORT, message_body_enc, SHORT, UDP_PROTOCOL, NF_B, message_body_enc_sz, sockfd, NULL, nfvInst);
}

void do_login(std::string userID, int procedure_key, int sockfd, struct nfvInstanceData *nfvInst) {
    // LOOKUP
    pthread_mutex_lock(&user_login_map_lock);
    bool login_status = user_login_map[userID].login_status;
    pthread_mutex_unlock(&user_login_map_lock);

    if (login_status) {

        // TIMER_STOP(T_FORGET, userID)
        generic_timer_stop(nfvInst, T_LOGIN_FORGET, userID); // remove the timerfdd, procedure key lost. 
        
        //int procedure_key = fd_to_key_map[sockfd]; // contains no entries yet. (only added via create_conn()
        printf("RE-login, procedure_key: %d\n", procedure_key);
        
        // CREATE_MESSAGE
        SynerPMessage_t simple {};

        // SET(simple.header.cmd, MACRO(LOGIN_RESPONSE))
        simple.header.cmd = LOGIN_RESPONSE;

        // UDF ()
        std::string login_response = generate_login_response(USER_EXIST);

        // SET(simple.uname.contents, userID);
        memcpy(simple.uname.contents, userID.data(), userID.size()); // no null

        // SET(simple.uname.sz, userID.size())
        simple.uname.sz = userID.size();

        // SET(simple.data.contents, login_response)
        memcpy(simple.data.contents, login_response.data(), login_response.size()); // no null
        
        // SET(simple.data.sz = login_response.size())
        simple.data.sz = login_response.size();

        // ENCODE(SynerPMessageEncoder, simple_enc, simple, simple_enc_sz)
        size_t simple_enc_sz {};
        std::vector<char> simple_enc(MAX_MESSAGE_SIZE, 0);
        SynerPMessageEncode(simple_enc, simple, simple_enc_sz); // null added.

        // SEND
        // no procedure key, on message receipt, do callback?
        // callback specified if procedure in progress.
        printf("Sending RE_login response to NF_B, fd: %d\n", sockfd);
        send_data("127.0.0.1", C_PORT, simple_enc, SHORT, UDP_PROTOCOL, NF_B, simple_enc_sz, sockfd, NULL, nfvInst);

        // RE_START timer
        fdData_t timer_fdd = generic_timer_start(nfvInst, procedure_key, T_LOGIN_FORGET, 5, &forget_user); // gen
        timer_fdd.timer_ctx.timer_id = T_LOGIN_FORGET; // gen from preprocess of timers.
        timer_fdd.timer_ctx.user_id = userID;         // gen
        // add to fd_map
        // ideally, should be protected w lock.
        //printf("Adding timer with timer fd: %d\n", timer_fdd.fd);
        nfvInst->fd_map[timer_fdd.fd] = timer_fdd; // gen

        //printf("Add key_to_fd_map: procedure_key=%d, sockfd=%d\n", procedure_key, sockfd);
        
        // maybe hack
        // SET_KEY(procedure_key)
        key_to_fd_map[procedure_key] = sockfd;
    } else {
        printf("Add key_to_fd_map: procedure_key=%d, sockfd=%d\n", procedure_key, sockfd);
        key_to_fd_map[procedure_key] = sockfd;

        pthread_mutex_lock(&user_login_map_lock);
        user_login_map[userID].login_status = true;
        pthread_mutex_unlock(&user_login_map_lock);

        // TIMER_START (T_LOGIN_FORGET, 5, forget_user)
        // CREATE_TIMER_CTX(t_context)
        // SET(t_context, user_id, userID)
        // SET(t_context, timer_id, MACRO(T_LOGIN_FORGET))
        // TIMER_START(timer_id, t_timeout, t_callback, t_context)
        //
        // fdData_t timer_fdd = generic_timer_start()
        fdData_t timer_fdd = generic_timer_start(nfvInst, procedure_key, T_LOGIN_FORGET, 5, &forget_user); // gen
        // set timer context
        timer_fdd.timer_ctx.timer_id = T_LOGIN_FORGET;  // gen from preprocess of timers.
        timer_fdd.timer_ctx.user_id = userID;
        // add to fd_map
        // ideally, should be protected w lock.
        printf("Adding timer with timer fd: %d\n", timer_fdd.fd);
        nfvInst->fd_map[timer_fdd.fd] = timer_fdd; // gen

        // create message
        SynerPMessage_t simple {};
        simple.header.cmd = LOGIN_RESPONSE;

        // UDF ()
        std::string login_response = generate_login_response(USER_NEW);

        // SET(simple.uname.contents, userID);
        memcpy(simple.uname.contents, userID.data(), userID.size()); // no null

        // SET(simple.uname.sz, userID.size())
        simple.uname.sz = userID.size();

        // SET()
        memcpy(simple.data.contents, login_response.data(), login_response.size()); // no null
        simple.data.sz = login_response.size();

        // ENCODE(SynerPMessageEncoder, simple_enc, simple, simple_enc_sz)
        size_t simple_enc_sz {};
        std::vector<char> simple_enc(MAX_MESSAGE_SIZE, 0);
        SynerPMessageEncode(simple_enc, simple, simple_enc_sz); //null added

        // SEND on udp socket that recd the original request from NF_B.
        // SEND(simple, Server, NF_B, NULL)
        // NULL -> needs old sockfd.
        // callback -> create new socket.
        send_data("127.0.0.1", C_PORT, simple_enc, SHORT, UDP_PROTOCOL, NF_B, simple_enc_sz, sockfd, NULL, nfvInst);
    }
}

//@@timer
// EVENT forget_user(user_id, timer_id)
void forget_user(timer_expiry_context_t& timer_ctx, struct nfvInstanceData *nfvInst) {
    printf("In timer callback\n");
    std::string user_id = timer_ctx.user_id; // gen from pyramis args
    _e_TimerType timer_id = timer_ctx.timer_id; // gen from pyramis args.

    pthread_mutex_lock(&user_login_map_lock);
    user_login_map[user_id].login_status = false;
    pthread_mutex_unlock(&user_login_map_lock);

    // CREATE_MESSAGE
    SynerPMessage_t simple {};

    // SET
    simple.header.cmd = TIMER_NOTIFICATION;

    // UDF
    std::string timer_expiry_response = generate_timer_response(user_id, timer_id, USER_TIMER_EXPIRY);
    printf("response: %s\n", timer_expiry_response.c_str());
    // SET()
    memcpy(simple.data.contents, timer_expiry_response.data(), timer_expiry_response.size());
    // SET()
    simple.data.sz = timer_expiry_response.size();

    // ENCODE(encodername, login_response, login_response_enc, login_response_enc_sz)
    size_t simple_enc_sz {};
    std::vector<char> simple_enc(MAX_MESSAGE_SIZE, 0);
    SynerPMessageEncode(simple_enc, simple, simple_enc_sz);
    
    // SEND
    // if send in timercallback -> fd = keytofd[timer->key]
    printf("Sending timer expiry response to NF_B, fd: %d\n", key_to_fd_map[timer_ctx.procedure_key]);
    send_data("127.0.0.1", C_PORT, simple_enc, SHORT, UDP_PROTOCOL, NF_B, simple_enc_sz, key_to_fd_map[timer_ctx.procedure_key], NULL, nfvInst);
    
    // TIMER_STOP(T_LOGIN_FORGET, user_id)
    generic_timer_stop(nfvInst, timer_id, user_id);

    return;
}

// autogen
fdData_t generic_timer_start(struct nfvInstanceData *nfvInst, int procedure_key, _e_TimerType timer_type, int timeout_sec, void (*callback)(timer_expiry_context_t& timer_ctx, struct nfvInstanceData *nfvInst)) {
    (void) timer_type;
    int tfd = timerfd_create(CLOCK_REALTIME, 0);
    struct itimerspec new_spec = {
        .it_interval = {0,0}, // .tv_sec, .tv_nsec. interval for periodic timer, after first expiry
        .it_value = {timeout_sec, 0}     // .tv_sec, .tv_nsec. the first expiry period
    };
    // _utr == new_value, _otr == old_value
    timerfd_settime(tfd, 0, &new_spec, NULL); // timer started

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = tfd;
    epoll_ctl(nfvInst->epoll_fd, EPOLL_CTL_ADD, tfd, &ev);

    fdData_t timer_fdd = fdData_t(TIMERFD_SOCKET, tfd);

    timer_expiry_context_t timer_ctx {};
    timer_ctx.procedure_key = procedure_key; //always
    //printf("Key from timer: %d\n", timer_ctx.procedure_key);

    timer_fdd.timer_ctx = timer_ctx;    // always

    timer_fdd.timerCB = callback; // always

    return timer_fdd;
}

// autogen
void generic_timer_stop(struct nfvInstanceData *nfvInst, _e_TimerType timer_id, std::string userID) {
    printf("Stopping timer\n");
    const auto it = std::find_if(
    nfvInst->fd_map.begin(),
    nfvInst->fd_map.end(), 
    [&userID, &timer_id](const auto &fd_map_entry) { return (fd_map_entry.second.timer_ctx.timer_id == timer_id
    && fd_map_entry.second.timer_ctx.user_id == userID); } // requires g++ -std=c++17. if using insert to insert values into map.
    );

    if (it != nfvInst->fd_map.end()) {
        auto tfd = it->second.fd;
        
        struct itimerspec stop_timer_spec = {{}, {}}; // shut off timer.
        timerfd_settime(tfd, 0, &stop_timer_spec, NULL);
        
        // removes the tfd from any epoll that was tracking it
        close(tfd);
        
        // remove the tfd from the fdmap
        //printf("erasing %d\n", tfd);
        nfvInst->fd_map.erase(it);
        //printf("erased %d\n", tfd);
    }  
}