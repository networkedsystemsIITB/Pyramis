#ifndef __PLATFORM_H
#define __PLATFORM_H

#include "../../utility_library/common/include/datatypes.h"
#include "../../utility_library/synerp_messages.h"

// from template.
#include <map>
#include <set>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <queue>
#include <sys/eventfd.h>

/* Default duration & retries are set to sane values, change them in the
 * derived class's constructor */
#define TIMER_DEFAULT_DURATION (6)
#define TIMER_DEFAULT_RETRIES (4)
/* Only for DPDK start */
#define NF_UPF_DUMMY_FD 64246
/* Only for DPDK end */
using namespace std;

// from interfaces.
typedef enum NODE_ENUM
{
    NF_A, 
    NF_B
} NODE;

/* gFdList array maintains socket fds for all channels */
/*
 * Better not to keep this global. Encapsulate in platform.
 * Thay way only platform will have write access to fdList.
 *
 * Each process will form channels with all nfv comp instances.
 * Likewise gFdList has E_MAX_NFV_COMPONENTS channel fds.
 */
/*
 * Similarly ipAddr,compId,CB[] should be part of object.
 * Thiss object should be encapsulated at platform layer.
 */
typedef void (*cbs)(void *msg, int len, uint Id, uint16_t streamId);
#define MAX_CONNECTIONS 1024
#define E_MAX_NFV_COMPONENTS 10
#define MAX_EPOLL_EVENTS E_MAX_NFV_COMPONENTS *MAX_CONNECTIONS
#define MAX_MESSAGE_SIZE 10000
#define LISTEN_QUEUE_BACKLOG 10

/* using 2 streams for now */
#define NON_UE_MESSAGE_STREAM 0
#define UE_MESSAGE_STREAM 1

typedef enum executionStates
{
    E_NFV_INVALID_STATE = -1,
    E_NFV_STARTED = 0,
    E_NFV_STOPPED
} _e_nfv_exec_state;

typedef enum protocols
{
    TCP_PROTOCOL = 0,
    UDP_PROTOCOL,
    SCTP_PROTOCOL,
    TOTAL_PROTOCOLS
} _e_protocols;

typedef enum socketTypes
{
    SELF_CONNECT = -1,
    SCTP_PROTOCOL_SERVER_ACCEPT_SOCKET,
    SCTP_PROTOCOL_SERVER_DATA_SOCKET,
    SCTP_PROTOCOL_CLIENT_SOCKET,
    TCP_PROTOCOL_SERVER_ACCEPT_SOCKET,
    TCP_PROTOCOL_SERVER_DATA_SOCKET,
    TCP_PROTOCOL_CLIENT_SOCKET,
    UDP_PROTOCOL_SERVER_ACCEPT_SOCKET,
    UDP_PROTOCOL_SERVER_DATA_SOCKET,
    UDP_PROTOCOL_CLIENT_SOCKET,
    TIMERFD_SOCKET,
    NUM_SOCKET_TYPES // always the last one
} _e_socketType;


typedef enum connectionType
{
    PERSISTENT=0,
    SHORT,
    TOTAL_TYPES
} _e_connectionType;

typedef enum TimerType: std::uint8_t {
    T_LOGIN_FORGET = 1
} _e_TimerType;


struct timer_expiry_context_T_LOGIN_FORGET {
    std::string user_id;
    int procedure_key;
};

struct timer_expiry_context_T_OTHER {
    int procedure_key;
    int other_data;
};

typedef union timer_expiry_contexts {
    struct timer_expiry_context_T_LOGIN_FORGET t1; // from __identifier given in the CREATE_TIMER_CONTEXT.
    struct timer_expiry_context_T_OTHER t2;
} timer_expiry_context_t;  // MAKE THIS A VARIANT. see variant.cpp

// from template
typedef struct fdData
{
    _e_socketType type;
    uint port;
    uint id;
    int fd;
    uint32_t ipAddr; /* PEER ipAddr to which Component can connect to */
    /* Useful when
     * 1. RAN wants to connect to multiple AMFs.
     * 2. RAN wants to connect to any peer pingable AMF. Not necessarily
     * within same machine */
    _e_connectionType connectionType;

    // uint ue_id;
    // std::string timer_id;
    timer_expiry_context_t timer_ctx;
    void (*timerCB) (timer_expiry_context_t& timer_ctx, struct nfvInstanceData *nfvInst);

    fdData()
    {
        port = 0;
        type = NUM_SOCKET_TYPES;
        id = 0;
        fd = -1;
    }
    fdData(_e_socketType type, uint port, int fd, uint32_t ipAddr,_e_connectionType connectionType)
    {
        this->type = type;
        this->port = port;
        this->id = fd;
        this->fd = fd;
        this->ipAddr = ipAddr;
        this->connectionType=connectionType;
    }

    fdData(_e_socketType type, int fd)
    {
        this->type = type;
        this->fd = fd;
    }
} fdData_t;

// from template
struct nfvInstanceData
{
    uint32_t bind_addr; /* Component's OWN ipAddr */
    _e_nfv_exec_state state;
    std::map<uint, fdData_t> fd_map; /* a map of all fds thru which data
                                 can be sent or received. Not for listen FDs */

    std::set<uint> fd_to_be_closed_set;
    /* TODO: locking so that multiple ppl read the map, a few edit it.
     * std::shared_mutex fdmap_mutex;
     */
    int epoll_fd;

    /* One Event fd, ring the bell, and eventCB will be called. */
    int event_fd;
    int id;
    int thread_id;
};

// from template
int open_and_init_socket(fdData_t& socket_fdd, uint32_t bind_addr, struct nfvInstanceData *nfvInst);
int platform_tcp_recv_data(int active_fd, std::vector<char>& msg);
int platform_udp_recv_data(int active_fd, std::vector<char>& msg);
int platform_sctp_recv_data(int active_fd, std::vector<char>& msg, int *stream_id);
void send_data(std::string peer_ip, int peer_port, std::vector<char>& msg, _e_connectionType conn_type,
    _e_protocols protocol, NODE peer_node, size_t message_length, int procedure_key_or_original_receiver_fd, 
    void (*callback)(std::vector<char>&, int, int, nfvInstanceData *), struct nfvInstanceData *nfvInst
    );
int send_response(std::string peer_ip, int peer_port, int original_receiver_fd, std::vector<char>& msg, 
    _e_protocols protocol, int message_length
    );
int platform_tcp_send_data(int sending_fd, std::vector<char>& msg, int message_length, 
    struct sockaddr_in *sin
    );
int platform_udp_send_data(int sending_fd, std::vector<char>& msg, int message_length, 
    struct sockaddr_in *sin
    );
int platform_sctp_send_data(int sending_fd, std::vector<char>& msg, int message_length,
    struct sockaddr_in *sin, uint16_t stream_id
    );
int create_connection(std::string peer_ip, int peer_port, struct sockaddr_in peer_addr, _e_protocols protocol);
int send_new_request(std::string peer_ip, int peer_port, std::vector<char>& msg, _e_connectionType conn_type, 
    _e_protocols protocol, NODE peer_node, int message_length, int procedure_key,
    void (*callback)(std::vector<char>&, int, int, nfvInstanceData *), struct nfvInstanceData *nfvInst
    );
void inline remove_fd_from_epoll(int epfd, int fd);

#endif