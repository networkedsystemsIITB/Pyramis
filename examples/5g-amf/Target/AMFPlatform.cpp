// TODO: close the connections

#include "../platform.h"
#include "../logging.h"

#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <bits/stdc++.h>
#include <netinet/sctp.h>

using namespace std;

void ngapIncoming(char *, int, int, struct sockaddr_in *, struct nfvInstanceData *);
void sbiIncomingRequestJSON(char *, int, int, struct sockaddr_in *, struct nfvInstanceData *);


vector<struct nfvInstanceData *> nfvInstVector;

/* Payload Protocol ID */
#define SCTP_PPID_NGAP 1006632960L /* htonl(60) */
#define SCTP_PPID_S1AP 301989888L  /* htons(18) */
uint8_t ppid_warn_rate = 0;        /* will print a warning every 20th time */

pthread_mutex_t globalLock;
pthread_mutex_t fdToRequestHandlerMapLock;
pthread_mutex_t fdToResponseHandlerMapLock;
pthread_mutex_t nfvInstVectorLock;
pthread_mutex_t persistentNodeProtocolToFdMapLock;
pthread_mutex_t fdToKeyMapLock;
pthread_mutex_t keyToFdMapLock;

// <locksPlaceHolderStart>
pthread_mutex_t globalContextMapLock;
pthread_mutex_t SuciAmfUeNgapIdMapLock;
pthread_mutex_t UeContextMapLock;
pthread_mutex_t SupiAmfUeNgapIdMapLock;
pthread_mutex_t UeContextMapTempLock;

// <locksPlaceHolderEnd>

set<int> registrationAcceptSet;

map<int, void (*)(char *, int, int, struct sockaddr_in *, struct nfvInstanceData *)> portToRequestHandlerMap;
map<int, void (*)(char *, int, int, struct sockaddr_in *, struct nfvInstanceData *)> fdToResponseHandlerMap;
map<int, void (*)(char *, int, int, struct sockaddr_in *, struct nfvInstanceData *)> fdToRequestHandlerMap;
map<int, int> persistentNodeProtocolToFdMap;
map<int, int> fdToKeyMap;

vector<fdData_t> interfaceVector=
{fdData_t(SCTP_PROTOCOL_SERVER_ACCEPT_SOCKET,38413,0,INADDR_NONE,PERSISTENT),fdData_t(TCP_PROTOCOL_SERVER_ACCEPT_SOCKET,65533,0,INADDR_NONE,SHORT)};

void signal_callback_handler(int signum)
{
    //pthread_mutex_lock(&globalLock);
    //higLog("Signal Handler Called");
    //for (auto itr : registrationAcceptSet)
    //    midLog("%d registration Accept", itr);
    
    //pthread_mutex_unlock(&globalLock);
    exit(0);
}

/* Function to set NONBLOCK flag on socket
 * check it's output if it is a must have flag.
 * 0 for success, -1 for error */
int setNonBlock(int fd)
{
    LOG_ENTRY;
    int flags;
    if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
    {
        higLog("fcntl get flags failed on fd %d, Error %s", fd, strerror(errno));
        LOG_EXIT;
        return -1;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        higLog("fcntl set flags failed on fd %d, Error %s", fd, strerror(errno));
        LOG_EXIT;
        return -1;
    }
    midLog("FD %d set as nonBlocking",fd);
    LOG_EXIT;
    return 0;
}

/* Function to open and bind sockets.
 * only Non-Blocking sockets
 * returns -1 on failure, fd on success */

// Sets up a passive-open for a single interface at the nf instance.
// listenfd is stored in the fdData() i.e. the specified interface.
// nfvinst.fdmap contains <listenfd, fdData> for the two interfaces specified
int openSocketAndInit(struct fdData &fdd, uint32_t bindAddr, struct nfvInstanceData *nfvInst)
{
    LOG_ENTRY;
    int fd = 0;
    struct sockaddr_in myaddr = {};
    uint port = fdd.port;
    /*no connection necessary to itself*/

    if (fdd.type == SCTP_PROTOCOL_SERVER_ACCEPT_SOCKET)
    {
        fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
        if (fd == -1)
        {   
            higLog("SCTP SERVER create failed, port %d, Error %s", port, strerror(errno));
            LOG_EXIT;
            return -1;
        }
        myaddr.sin_family = AF_INET;
        myaddr.sin_port = htons(port);
        myaddr.sin_addr.s_addr = bindAddr;

        /* set 2 instreams & 2 outstreams */ /* TODO: read this from a config */
        struct sctp_initmsg initmsg = {};
        initmsg.sinit_num_ostreams = 2;
        initmsg.sinit_max_instreams = 100; /* ATMOST 100 are allowed */
        lowLog("Setting %d instreams and atmost %d outstreams", initmsg.sinit_num_ostreams, initmsg.sinit_max_instreams);
        if (setsockopt(fd, SOL_SCTP, SCTP_INITMSG, &initmsg, sizeof(initmsg)) == -1)
        {
            higLog("setsockopt failed, Error: %s", strerror(errno));
            LOG_EXIT;
            return -1;
        }

        /* set it so we get stream id on rcving a message */
        struct sctp_event_subscribe events = {};
        events.sctp_data_io_event = 1;
        if (setsockopt(fd, SOL_SCTP, SCTP_EVENTS, (const void *)&events, sizeof(events)) == -1)
        {   
            higLog("setsockopt failed, Error: %s", strerror(errno));
            LOG_EXIT;
            return -1;
        }

        int tr = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &tr, sizeof(int)) == -1) // reuse ports
        {
            higLog("Port reuse failed, port %d, Error %s", port, strerror(errno));
            LOG_EXIT;
            return -1;
        }
    }
    else if (fdd.type == TCP_PROTOCOL_SERVER_ACCEPT_SOCKET)
    {
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd == -1)
        {
            higLog("TCP SERVER create failed, port %d, Error %s",
                   port, strerror(errno));
            LOG_EXIT;
            return -1;
        }
        myaddr.sin_family = AF_INET;
        myaddr.sin_port = htons(port);
        myaddr.sin_addr.s_addr = bindAddr;

        int tr = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &tr, sizeof(int)) == -1)
        {
            higLog("Port reuse failed, port %d, Error %s", port, strerror(errno));
            LOG_EXIT;
            return -1;
        }
    }
    else if (fdd.type == UDP_PROTOCOL_SERVER_ACCEPT_SOCKET)
    {
        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd == -1)
        {
            higLog("UDP SERVER create failed, port %d, Error %s", port, strerror(errno));
            LOG_EXIT;
            return -1;
        }
        myaddr.sin_family = AF_INET;
        myaddr.sin_port = htons(port);
        myaddr.sin_addr.s_addr = bindAddr;

        // int tr = 1;
        // if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &tr, sizeof(int)) == -1)
        // {
        //     higLog("Addr reuse failed, port %d, Error %s", port, strerror(errno));
        //     LOG_EXIT;
        //     return -1;
        // }

        int tr1 = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &tr1, sizeof(int)) == -1)
        {
            higLog("Port reuse failed, port %d, Error %s", port, strerror(errno));
            LOG_EXIT;
            return -1;
        }
    }
    else
    {
        higLog("Unknown socket type %d", fdd.type);
        LOG_EXIT;
        return -1;
    }

    if(fdd.type!=UDP_PROTOCOL_SERVER_ACCEPT_SOCKET)
        setNonBlock(fd);

    /*now bind to the port*/
    if (bind(fd, (struct sockaddr *)&myaddr, sizeof(myaddr)) == -1)
    {
        higLog("Bind failed, port %d, Error %s", port, strerror(errno));
        LOG_EXIT;
        return -1;
    }

    if (fdd.type == UDP_PROTOCOL_SERVER_ACCEPT_SOCKET)
    {
        fdd.fd = fd;
        fdd.id = fd;

        // No need for lock as all these will be setup before calling pollOnEvents
        for (int i = 0; i < nfvInstVector.size(); i++)
        {
            nfvInstVector[i]->fdmap[fdd.id] = fdd;
            fdToRequestHandlerMap[fdd.fd] = portToRequestHandlerMap[fdd.port];
        }

        LOG_EXIT;
        return fd;
    }

    if (listen(fd, LISTEN_QUEUE_BACKLOG) == -1)
    {
        higLog("Listen failed, port %d, Error %s", port, strerror(errno));
        close(fd);
        LOG_EXIT;
        return -1;
    }
    fdd.fd = fd;
    fdd.id = fd;
    nfvInst->fdmap[fdd.id] = fdd; // just store a single listenfd fd in the fdmap for a single iterface, in the first nf instance.

    LOG_EXIT;
    return fd;
}

// finalised
/*
 * This function opens socket on nfv-server for each channel.
 * The socket descriptor is then stored in fdList.
 *
 * Return: SUCCESS/FAILURE
 */
int openChannels()
{
    LOG_ENTRY;
    for (int i = 0; i < interfaceVector.size(); i++) // 2 interfaces at AMF with unique port number (SCTP, TCP)
    {
        if (openSocketAndInit(interfaceVector[i], nfvInstVector[0]->bindAddr, nfvInstVector[0]) < 0) // fddata~interface
            higLog("ERROR in open and init socket type %d", interfaceVector[i].type);
    }
 
    for (int i = 1; i < nfvInstVector.size(); i++) // for the other NF instances,
        nfvInstVector[i]->fdmap.insert(nfvInstVector[i]->fdmap.begin(), nfvInstVector[i]->fdmap.end()); //store -> likely empty.

    LOG_EXIT;
    return SUCCESS;
}

/*
 * This function initializes platform objects. It also makes
 * function calls which open listening socket for each channel.
 * The number of channels depend on setup sepcified.
 *
 * Arg IN: selfNfvCompId stands for comp id of process which
 *	   is making use of Platform services. The process
 *	   which is running as nfv.
 *	   ipAddr: IPv4 Address in network byte order. For now UDP sockets will
 *	   be bound to this address. Set it to INADDR_ANY to accept packets to all
 *	   src addresses.
 *
 * Return: nfvInstanceData pointer.
 */
struct nfvInstanceData *initPlatform(uint32_t ipAddr, int id)
{
    struct nfvInstanceData *nfvInst;

    nfvInst = new struct nfvInstanceData;
    nfvInst->state = E_NFV_INVALID_STATE;
    nfvInst->fdmap = {};
    nfvInst->fdToBeClosedSet = {};
    nfvInst->epollFd = epoll_create1(0);
    if (nfvInst->epollFd == -1)
    {
        higLog("epoll fd creation failed, Error: %s", strerror(errno));
        exit(1);
    }
    nfvInst->bindAddr = ipAddr;
    nfvInst->threadId = id;
    return nfvInst;
};

int platformTCPSendData(int fd, char *msg, int len, struct sockaddr_in *sin)
{
    LOG_ENTRY;
    int rc = sendto(fd, msg, len, 0, (sockaddr *)sin, sin ? sizeof(struct sockaddr_in) : 0);
    if (rc == -1)
        lowLog("sendto failed, Error: %s", strerror(errno));
    midLog("Sent %d bytes", rc);
    LOG_EXIT;
    return rc;
}

int platformUDPSendData(int fd, char *msg, int len, struct sockaddr_in *sin)
{
    LOG_ENTRY;
    socklen_t addrLen = sizeof (struct sockaddr_in);
    int rc = sendto(fd, msg, len, 0, (sockaddr *)sin, sin ? addrLen : 0);
    if (rc == -1)
        lowLog("sendto failed, Error: %s", strerror(errno));
    midLog("Sent %d bytes", rc);
    LOG_EXIT;
    return rc;
}

int platformSCTPSendData(int fd, char *msg, int len, struct sockaddr_in *sin, uint16_t streamId)
{
    LOG_ENTRY;
    int rc = sctp_sendmsg(fd, msg, len, (sockaddr *)sin, sin ? sizeof(struct sockaddr_in) : 0, SCTP_PPID_NGAP, 0, streamId, 0, 0);
    if (rc == -1)
        higLog("sendto failed, Error: %s", strerror(errno));
    else
        midLog("Sent %d bytes on stream %d", rc, streamId);
    LOG_EXIT;
    return rc;
}

/* recv the message, return recvfrom's output */
int platformTCPRecvData(int activeFD, char *msg)
{
    LOG_ENTRY;
    int rc;
    char buffer[MAX_MESSAGE_SIZE];
    higLog("msg here is (passed new message): %d\n", strlen(msg));
    higLog("%d: activeFD(expect 9)", activeFD);
    int cnt = 0;
    memset(msg, 0, MAX_MESSAGE_SIZE);

    // TODO: Avoid copying
    while (true)
    {
        rc = recv(activeFD, msg + cnt, MAX_MESSAGE_SIZE, 0);
        if (cnt == 0 && rc == -1)
            break;
        if (rc > 0)
        {
            cnt += rc;
            // ending with either '}' or '--/r/n'
            // server expects http messages.
            if (msg[cnt - 1] == '}' || (msg[cnt - 1] == 10 && msg[cnt - 2] == 13 && msg[cnt - 3] == 45 && msg[cnt - 4] == 45) || msg[cnt - 1] == ']' || strcmp(msg + cnt - 21, "Content-Length: 0\r\n\r\n") == 0)
                break;
        }
        if (rc == 0)
            return 0;
    }
    higLog("recvd msg len : %d", cnt);
    if (cnt < 0)
        lowLog("recvfrom failed, Error: %s", strerror(errno));
    else if (cnt == 0)
        lowLog("%s", "recvfrom returned 0 len msg");
    LOG_EXIT;
    return cnt;
}

/* recv the message, return recvfrom's output */
int platformUDPRecvData(int activeFD, char *msg, struct sockaddr_in &cliaddr, socklen_t &len)
{
    LOG_ENTRY;
    int rc = recvfrom(activeFD, msg, MAX_MESSAGE_SIZE, MSG_WAITALL, (struct sockaddr *)&cliaddr, &len);

    if (rc == -1)
        lowLog("recvfrom failed, Error: %s", strerror(errno));
    else if (rc == 0)
        lowLog("%s", "recvfrom returned 0 len msg");

    LOG_EXIT;
    return rc;
}

/* recv the message, return recvfrom's output */
int platformSCTPRecvData(int activeFD, char *msg, int *streamId)
{
    LOG_ENTRY;
    struct sctp_sndrcvinfo info = {};
    int flags = 0;
    int rc = sctp_recvmsg(activeFD, msg, MAX_MESSAGE_SIZE, NULL, NULL, &info,
                          &flags);
    if (rc < 0)
    {
        lowLog("recvfrom failed, Error: %s", strerror(errno));
        LOG_EXIT;
        if (errno == ECONNRESET) /* Non Graceful shutdown */
            return 0;
        return rc;
    }
    else if (rc == 0)
    { /* Graceful Shutdown */
        lowLog("%s", "recvfrom returned 0 len msg");
        LOG_EXIT;
        return rc;
    }
    else if (flags & MSG_NOTIFICATION)
    {
        /*received a notification, dont need it, NOT handling it.
         * typecast msg into sctp_notification if info is needed */
        LOG_EXIT;
        return -1;
        /* flags & MSG_EOR will be set if msg was of sufficient length.
         * TODO: start checking MSG_EOR flag too. For now msglen 3000 is suffi */
    }
    *streamId = info.sinfo_stream;
    if (info.sinfo_ppid != SCTP_PPID_NGAP)
    {
        if (ppid_warn_rate++ % 20 == 0)
            midLog("RATELIMITED_LOG: Warning: PPID is not 60, recv.d %d", ntohl(info.sinfo_ppid));
        /* We dont need strict rate limited logging, which is why
         * we are not using locks to protect ppid_warn_rate */
    }
    LOG_EXIT;
    return rc;
}

/* accept connections and add it to epoll */
void acceptConnections(fdData_t *acceptFdd, struct nfvInstanceData *nfvInst)
{
    LOG_ENTRY;
    int newfd = accept4(acceptFdd->fd, NULL, NULL, SOCK_NONBLOCK); // the non-blocking data fd
    if (newfd == -1)
    {
        higLog("accept4 failed, Error: %s", strerror(errno));
        LOG_EXIT;
        return;
    }

    if (nfvInst->fdmap.size() >= MAX_CONNECTIONS)
    {
        higLog("%s", "fd map full");
        close(newfd); /*refuse connection */
        LOG_EXIT;
        return;
    }

    /* init emptyFD does not need protection, as it happens only
     * in the main thread. */
    fdData_t fdd;

    switch (acceptFdd->type) // type of the listen socket
    {

    case SCTP_PROTOCOL_SERVER_ACCEPT_SOCKET:
        fdd.type = SCTP_PROTOCOL_SERVER_DATA_SOCKET;
        break;
    case TCP_PROTOCOL_SERVER_ACCEPT_SOCKET:
        fdd.type = TCP_PROTOCOL_SERVER_DATA_SOCKET;
        break;
    default:
        higLog("Event on unknown accept socket\n");
        break;
    }

    // create a new fddata of same type as listening socket.
    // it is derived from.
    fdd.fd = newfd;
    fdd.id = newfd;
    fdd.port = acceptFdd->port;
    // if the new accept fd ie. data fd was previously used 
    // and is still in the fdmap, erase that entry from the
    // fdmap. 
    // Ideally, the newfd should be fresh.
    if (nfvInst->fdmap.find(fdd.id) != nfvInst->fdmap.end())
    {
        higLog("Error while adding fd into the map");
        close(newfd);
        __attribute__((unused)) int erasedFds = nfvInst->fdmap.erase(newfd);
        higLog("Erased %d fds", erasedFds);
        LOG_EXIT;
        return;
    }
    // if a persistent connection is created, add this accept 
    // socket to the epollfd monitoring list.
    if (acceptFdd->connectionType == PERSISTENT)
    {
        pthread_mutex_lock(&nfvInstVectorLock);
        for (int i = 0; i < nfvInstVector.size(); i++)
        {
            struct epoll_event event;

            memset(&event, 0, sizeof(event));
            event.events = EPOLLIN;
            event.data.fd = newfd;
            nfvInstVector[i]->fdmap[fdd.id] = fdd;
            int epollFd = nfvInstVector[i]->epollFd;
            if (epoll_ctl(epollFd, EPOLL_CTL_ADD, newfd, &event) == -1)
            {
                higLog("epoll_ctl failed, fd id %d, Error %s", fdd.id, strerror(errno));
                LOG_EXIT;
                return;
            }
            midLog("Accepted a new connection, epoll %d, fd %d, core %d\n", epollFd, fdd.fd, nfvInstVector[i]->threadId); /* LNTC */
        }
        pthread_mutex_unlock(&nfvInstVectorLock);
    }
    else
    {   
        
        struct epoll_event event;
        memset(&event, 0, sizeof(event));
        event.events = EPOLLIN;
        event.data.fd = newfd;
        nfvInst->fdmap[fdd.id] = fdd; // single nf assumption. all data will be exch via new fd.
        int epollFd = nfvInst->epollFd;
        if (epoll_ctl(epollFd, EPOLL_CTL_ADD, newfd, &event) == -1)
        {
            higLog("epoll_ctl failed, fd id %d, Error %s", fdd.id, strerror(errno));
            LOG_EXIT;
            return;
        }
        midLog("Accepted a new connection, id %d, fd %d", fdd.id, fdd.fd); /* LNTC */
    }
    pthread_mutex_lock(&fdToRequestHandlerMapLock);
    fdToRequestHandlerMap[fdd.fd] = portToRequestHandlerMap[fdd.port]; //events at this fd (data fd) are handled by the callbacks.
    pthread_mutex_unlock(&fdToRequestHandlerMapLock);
    LOG_EXIT;
}

// finalised
void inline removeFdFromEpoll(int epollFd, int fd)
{
    LOG_ENTRY;
    if (epoll_ctl(epollFd, EPOLL_CTL_DEL, fd, NULL) == -1)
        higLog("epoll_ctl DEL failed, Error %s for fd :%d and epoll fd: %d", strerror(errno), fd, epollFd);
    else
        midLog("Removed fd %d from epoll fd %d", fd, epollFd);
    LOG_EXIT;
}

void recvAndProcessCallbacks(struct nfvInstanceData *nfvInst, std::map<uint, fdData_t>::iterator &fddIter)
{
    LOG_ENTRY;
    fdData_t &fdd = fddIter->second;
    int rc;
    char *msg;

    msg = (char *)malloc(sizeof(char) * MAX_MESSAGE_SIZE);

    struct sockaddr_in cliaddr;
    socklen_t len;
    
    memset(&cliaddr, 0, sizeof(cliaddr));
    len = sizeof(cliaddr);


    /* alloc here, either freed in CB
     * or MUST be freed in the current func (failure or CB is not called) */

    int streamId = 0;
    switch (fdd.type)
    {
    case SCTP_PROTOCOL_SERVER_DATA_SOCKET:
        rc = platformSCTPRecvData(fdd.fd, msg, &streamId);
        break;
    case TCP_PROTOCOL_SERVER_DATA_SOCKET:
        rc = platformTCPRecvData(fdd.fd, msg);
        break;

    case UDP_PROTOCOL_SERVER_DATA_SOCKET:
        rc = platformUDPRecvData(fdd.fd, msg, cliaddr, len);
        break;
    case SCTP_PROTOCOL_CLIENT_SOCKET:
        rc = platformSCTPRecvData(fdd.fd, msg, &streamId);
        break;

    case TCP_PROTOCOL_CLIENT_SOCKET:
        rc = platformTCPRecvData(fdd.fd, msg);
        break;

    case UDP_PROTOCOL_CLIENT_SOCKET:
        rc = platformUDPRecvData(fdd.fd, msg, cliaddr, len);
        break;
    /*
     * case TIMERFD:
        
    */

    default:
        lowLog("no action needed for fdd.type %d", fdd.type);
        free(msg);
        LOG_EXIT;
        return;
    }
    int epollFd = nfvInst->epollFd;
    int temp = fdd.fd;
    if (rc > 0)
    {
        pthread_mutex_lock(&fdToRequestHandlerMapLock);
        auto itr = fdToRequestHandlerMap.find(fdd.fd);
        if (itr == fdToRequestHandlerMap.end())
        {   
            pthread_mutex_unlock(&fdToRequestHandlerMapLock);

            pthread_mutex_lock(&fdToResponseHandlerMapLock);
            itr = fdToResponseHandlerMap.find(fdd.fd);
            if (itr == fdToResponseHandlerMap.end())
            {
                pthread_mutex_unlock(&fdToResponseHandlerMapLock);
                higLog("Handler couldn't be found for the fd:%d", fdd.fd);
            }
            else
            {
                pthread_mutex_unlock(&fdToResponseHandlerMapLock);
                itr->second(msg, rc, fdd.fd, &cliaddr, nfvInst); // exits when amf_linking sends a message. passs
                pthread_mutex_lock(&fdToResponseHandlerMapLock);

                // close the datafd that recd the event
                auto fdToCloseItr = nfvInst->fdToBeClosedSet.find(fdd.fd);

                if (fdToCloseItr != nfvInst->fdToBeClosedSet.end())
                {
                    removeFdFromEpoll(nfvInst->epollFd, fdd.fd);
                    nfvInst->fdToBeClosedSet.erase(fdd.fd);
                    nfvInst->fdmap.erase(fdd.fd);
                    fdToResponseHandlerMap.erase(temp);
                    if (close(temp) < 0)
                    {
                        higLog("Failed closing fd: %d", temp);
                    }
                    else
                    {
                        midLog("Closed fd %d", temp);
                    }
                }
                pthread_mutex_unlock(&fdToResponseHandlerMapLock);
            }
        }
        else
        {
            pthread_mutex_unlock(&fdToRequestHandlerMapLock);
            itr->second(msg, rc, fdd.fd, &cliaddr, nfvInst);
        }
    }

    else if (rc == 0)
    {
        removeFdFromEpoll(epollFd, fdd.fd);
        pthread_mutex_lock(&fdToRequestHandlerMapLock);
        fdToRequestHandlerMap.erase(fdd.fd);
        nfvInst->fdmap.erase(fddIter);
        pthread_mutex_unlock(&fdToRequestHandlerMapLock);

        if (close(temp) == -1)
            higLog("close failed, Error %s", strerror(errno));

        /* TODO: notify that the connection has closed. */
        midLog("Removed data fd %d, id%d", fdd.fd, fdd.id);
    }

    if (msg)
        free(msg);

    LOG_EXIT;
}

int CreateConnection(string ip, int port, struct sockaddr_in addr, _e_protocols protocol)
{
    LOG_ENTRY;
    int sockid;

    if (protocol == TCP_PROTOCOL)
        sockid = socket(AF_INET, SOCK_STREAM, 0);
    else if (protocol == UDP_PROTOCOL)
        sockid = socket(AF_INET, SOCK_DGRAM, 0);
    else if (protocol == SCTP_PROTOCOL)
        sockid = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    else
        higLog("Protocol is not supported\n");

    int ret = connect(sockid, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
    if (ret < 0)
    {   
        if (errno != EINPROGRESS)
        {
            perror("CONNECT FAILED");
            close(sockid);
            LOG_EXIT;
            return -1;
        }
    }
    LOG_EXIT;
    return sockid;
}

// finalised
int sendResponse(string ip, int fd, char *msg, _e_protocols protocol, int len, struct sockaddr_in *client_ip)
{
    LOG_ENTRY;
    int ret;
    if (protocol == SCTP_PROTOCOL)
        ret = platformSCTPSendData(fd, msg, len, NULL, 0);
    else if (protocol == TCP_PROTOCOL)
        ret = platformTCPSendData(fd, msg, len, NULL);
    else if (protocol == UDP_PROTOCOL)
        ret = platformUDPSendData(fd, msg, len, client_ip);

    midLog("Sent Response to FD:%d", fd);
    LOG_EXIT;
    return ret;
}

// finalised
int sendRequest(string ip, int port, char *msg, bool isShort, _e_protocols protocol, NODE node, int len, void (*responseProcessing)(char *, int, int, struct sockaddr_in *, nfvInstanceData *), struct nfvInstanceData *nfvInst, int key)
{
    LOG_ENTRY;
    int fd;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip.c_str());
    addr.sin_port = htons(port);
    bool isNewFdCreated = false;
    higLog("msg len is: %d\n", strlen(msg));

    if (isShort)
    {
        fd = CreateConnection(ip, port, addr, protocol);
        nfvInst->fdToBeClosedSet.insert(fd);
        isNewFdCreated = true;
    }
    else
    {
        int protocolNodeKey = (protocol << 8) | node; // node that is the destination will always have the same key. same 
        pthread_mutex_lock(&persistentNodeProtocolToFdMapLock);
        if (persistentNodeProtocolToFdMap.find(protocolNodeKey) == persistentNodeProtocolToFdMap.end())
        {
            fd = CreateConnection(ip, port, addr, protocol);
            persistentNodeProtocolToFdMap[protocolNodeKey] = fd;
            pthread_mutex_unlock(&persistentNodeProtocolToFdMapLock);
            isNewFdCreated = true;
        }
        else
        {
            fd = persistentNodeProtocolToFdMap[protocolNodeKey];
            pthread_mutex_unlock(&persistentNodeProtocolToFdMapLock);
        }
    }

    // amf ~caches peer node comm. fds
    if (isNewFdCreated)
    {
        fdData_t fdd;
        fdd.fd = fd;
        if (protocol == SCTP_PROTOCOL)
            fdd.type = SCTP_PROTOCOL_CLIENT_SOCKET;
        else if (protocol == TCP_PROTOCOL)
            fdd.type = TCP_PROTOCOL_CLIENT_SOCKET;
        else if (protocol == UDP_PROTOCOL)
            fdd.type = UDP_PROTOCOL_CLIENT_SOCKET;
        nfvInst->fdmap[fd] = fdd;

        struct epoll_event event;
        memset(&event, 0, sizeof(event));
        event.events = EPOLLIN; // to detect responses only
        event.data.fd = fd;
        int epollFd = nfvInst->epollFd;
        higLog("epollFd: %d", epollFd);

        if (epoll_ctl(epollFd, EPOLL_CTL_ADD, fd, &event) == -1)
        {
            higLog("epoll_ctl failed, fd id %d, Error %s", fdd.id, strerror(errno));
            LOG_EXIT;
            return -1;
        }
        midLog("Fd:%d added to epoll", fd);

        pthread_mutex_lock(&fdToResponseHandlerMapLock);
        fdToResponseHandlerMap[fd] = responseProcessing; // if a response is recd, the callback specified by linking is called.
        fdToKeyMap[fd] = key; // maps a datafd to a UE.
        pthread_mutex_unlock(&fdToResponseHandlerMapLock);
    }
    int ret;
    if (protocol == SCTP_PROTOCOL)
        ret = platformSCTPSendData(fd, msg, len, &addr, 0);
    else if (protocol == TCP_PROTOCOL)
        ret = platformTCPSendData(fd, msg, len, &addr);
    else if (protocol == UDP_PROTOCOL)
        ret = platformUDPSendData(fd, msg, len, &addr);

    midLog("Sent Request to FD:%d", fd);
    LOG_EXIT;
    return ret;
}

// finalised
void sendData(string ip, int port, char *msg, bool isShort, _e_protocols protocol, NODE node, int len, int keyOrfd, void (*responseProcessing)(char *, int, int, struct sockaddr_in *, nfvInstanceData *), struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst)
{
    LOG_ENTRY;
    // if no callback specified at amf (to handle potential response from other NF),
    // this msg is a response to some request from NF->AMF.
    if (responseProcessing == NULL) 
        sendResponse(ip, keyOrfd, msg, protocol, len, client_ip);
    else
        sendRequest(ip, port, msg, isShort, protocol, node, len, responseProcessing, nfvInst, keyOrfd);
    LOG_EXIT;
}

// add listening sockeet (tcp) and udp socket to the epoll fd of the current NF instance(thread)
void *pollOnEvents(void *arg)
{
    LOG_ENTRY;
    int s;
    cpu_set_t cpuset;
    pthread_t thread;

    struct nfvInstanceData *nfvInst = (struct nfvInstanceData *)arg;
    thread = pthread_self();

    CPU_ZERO(&cpuset);

    CPU_SET(4 + nfvInst->threadId, &cpuset);

    s = pthread_setaffinity_np(thread, sizeof(cpuset), &cpuset);
    if (s != 0)
        printf("pthread_setaffinity_np");

    struct epoll_event activeEvents[MAX_EPOLL_EVENTS];

    // there will be 2 fds that listen
    // for connections. epollfd monitors these 
    // listen fds.
    for (std::map<uint, fdData_t>::iterator fddIter = nfvInst->fdmap.begin(); fddIter != nfvInst->fdmap.end(); fddIter++)
    {
        fdData_t *fddPtr = &(fddIter->second);
        struct epoll_event event;
        memset(&event, 0, sizeof(event));
        event.events = EPOLLIN;
        event.data.fd = fddPtr->fd;

        if (epoll_ctl(nfvInst->epollFd, EPOLL_CTL_ADD, fddPtr->fd, &event) == -1)
            higLog("epoll_ctl failed for listening Fd, Error %s", strerror(errno));
        else
            lowLog("added fd %d into epoll fd %d", fddPtr->fd,nfvInst->epollFd);
        
        if(fddPtr->type==UDP_PROTOCOL_SERVER_ACCEPT_SOCKET) // for udp, only a single socket is required for data.
            fddPtr->type=UDP_PROTOCOL_SERVER_DATA_SOCKET;
    }

    nfvInst->state = E_NFV_STARTED;
    // @outset, we have two fds that can be commnicated with:
    // one tcp listenfd, and one udp data fd. For a single thread, but fds are being monitoreed by
    // a single epoll fd.
    // epoll numfds will be 2 in the begining at max. however, each fd may have been sent multiple connection messages
    // in the time it takes for epoll to return the events.
    // for the tcp socket fd, event means some data is buffered, could be one msg or several or part of one.
    // for the udp socket, eent means a signoeMESSAGE from another NF.
    while (true) {
        int numFds = epoll_wait(nfvInst->epollFd, activeEvents, MAX_EPOLL_EVENTS, -1); // epoll wait fills the event.data.fd field
        specialLog("Got %d events, processing...", numFds); // the datafd could have recd several messages while the previous events were being processed.
        for (int wokeup = 0; wokeup < numFds; wokeup++)
            lowLog("Event on fd %d and event %d on thread id %d\n", activeEvents[wokeup].data.fd, activeEvents[wokeup].events, nfvInst->threadId);

        for (int fd = 0; fd < numFds; fd++) // 
        {
            uint id = activeEvents[fd].data.fd; 
            std::map<uint, fdData_t>::iterator fddIter = nfvInst->fdmap.find(id); // fd that just recd a message.

            if (activeEvents[fd].events & EPOLLERR)
            {
                close(activeEvents[fd].data.fd);
                epoll_ctl(nfvInst->epollFd, EPOLL_CTL_DEL, activeEvents[fd].data.fd, NULL);
                continue;
            }

            if (fddIter == nfvInst->fdmap.end())
            {
                higLog("Received an event on a fd not present in map\nERROR: Issue with map clean up!!!!");
                continue;
            }

            // first, the listen sockets accept connections
            if (fddIter->second.type == SCTP_PROTOCOL_SERVER_ACCEPT_SOCKET)
                acceptConnections(&fddIter->second, nfvInst);
            else if (fddIter->second.type == TCP_PROTOCOL_SERVER_ACCEPT_SOCKET)
                acceptConnections(&fddIter->second, nfvInst);
            else if (fddIter->second.type == UDP_PROTOCOL_SERVER_ACCEPT_SOCKET)
                acceptConnections(&fddIter->second, nfvInst);
            // else if fdditer->second->type == TIMER_FD
            // fdditer->second->timerCB(.......) // a linking-defined callback, declaration in linkingheader.h
            // next at the datafd will be a NF message.
            else
                recvAndProcessCallbacks(nfvInst, fddIter);
        }
    }
    LOG_EXIT;
}

// finalised
int main(int argc, char const *argv[])
{
    setTag(argv[0]);
    signal(SIGINT, signal_callback_handler);

    if (argc != 3)
    {
        higLog("Specify: # threads");
        return 0;
    }

    int num_threads = stoi(argv[2]);

    string ip = "127.0.0.1";
    uint32_t addr = INADDR_ANY;

    if (ip != "")
    {
        if (inet_pton(AF_INET, ip.c_str(), &addr) < 0)
        {
            higLog("ipnet_pton failed, %s", strerror(errno));
            exit(1);
        }
    }

    nfvInstVector.resize(num_threads);
    vector<pthread_t> pthreads(num_threads);

    pthread_mutex_init(&globalLock, NULL);
    pthread_mutex_init(&fdToRequestHandlerMapLock, NULL);
    pthread_mutex_init(&fdToResponseHandlerMapLock, NULL);
    pthread_mutex_init(&nfvInstVectorLock, NULL);
    pthread_mutex_init(&persistentNodeProtocolToFdMapLock, NULL);
    pthread_mutex_init(&fdToKeyMapLock, NULL);
    pthread_mutex_init(&keyToFdMapLock, NULL);

    // <initialiseLocksPlaceHolderStart>
pthread_mutex_init (&globalContextMapLock, NULL);
pthread_mutex_init (&SuciAmfUeNgapIdMapLock, NULL);
pthread_mutex_init (&UeContextMapLock, NULL);
pthread_mutex_init (&SupiAmfUeNgapIdMapLock, NULL);
pthread_mutex_init (&UeContextMapTempLock, NULL);

    // <initialiseLocksPlaceHolderEnd>

    // registering event handlers
portToRequestHandlerMap[38413]=ngapIncoming;portToRequestHandlerMap[65533]=sbiIncomingRequestJSON;

    for (int i = 0; i < num_threads; i++)
        nfvInstVector[i] = initPlatform(addr, i);

    // opening listening , udp sockets and 
    openChannels();

    // adding to each of the epoll of Instances
    for (int i = 0; i < num_threads; i++)
    {
        if (pthread_create(&pthreads[i], NULL, pollOnEvents, (void *)nfvInstVector[i]) < 0)
        {
            higLog("pthread_create failed");
            return 0;
        }
    }

    for (int i = 0; i < num_threads; i++)
    {
        pthread_join(pthreads[i], NULL);
        midLog("Thread %d joined", i);
    }

    return 0;
}