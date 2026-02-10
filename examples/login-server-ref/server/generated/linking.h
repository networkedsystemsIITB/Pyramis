#ifndef __LINKING_H__
#define __LINKING_H__

// include paths need to be dynamically generated
// for platform_file headers.
#include "../udf.h"
#include "synerp_platform.h"

// events defined in NF_Linking.cpp
void do_echo(SynerPMessage_t message_body, int sockfd, struct nfvInstanceData *nfvInst);
void server_entry(std::vector<char>& message, int length, int sockfd, struct nfvInstanceData *nfvInst);
void do_login(std::string userID, int procedure_key, int sockfd, struct nfvInstanceData *nfvInst);

// default events if TIMER functions are called.
fdData_t generic_timer_start(timer_expiry_context_t& timer_ctx, int timeout_sec, void (*callback)(timer_expiry_context_t& timer_ctx, struct nfvInstanceData *nfvInst), struct nfvInstanceData *nfvInst);
void generic_timer_stop(timer_expiry_context_t& timer_ctx, struct nfvInstanceData *nfvInst);

void forget_user(timer_expiry_context_t& timer, struct nfvInstanceData *nfvInst);
std::string _errno(const std::string& base);

// default maps
extern std::map<int, int> fd_to_key_map;
extern std::map<int, int> key_to_fd_map;

// for every map, have a lock
extern pthread_mutex_t user_login_map_lock;
extern pthread_mutex_t fd_to_key_map_lock;
extern pthread_mutex_t key_to_fd_map_lock;

#endif