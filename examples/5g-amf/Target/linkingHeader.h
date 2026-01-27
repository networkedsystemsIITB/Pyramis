// defaults, from template.
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/sctp.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <jsoncpp/json/json.h>

#include "../platform.h"
#include "nas/NasMessage.h"
#include "udf.h"
#include "contexts.h"
#include "../http_library.h"
#include "nas/mobility/RegistrationRequest.h"
#include "aka/include/securityContext.h"
#include "ngap/codec/include/ngap_helper.h"
#include "platform/include/multipart.h"
#include "ngap/include/PDUSessionResourceModifyRequestTransfer.h"
#include "ngap/include/UL-NGU-UP-TNLModifyItem.h"
#include "ngap/include/UP-TNLInformation.h"
#include "ngap/include/QosFlowAddOrModifyRequestItem.h"
#include "ngap/include/QosFlowItem.h"
#include <sys/time.h>

#define BUF_SIZE 8192

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

using json = nlohmann::json;

using namespace std;

extern map<int, int> fdToKeyMap;
extern pthread_mutex_t fdToKeyMapLock;
extern pthread_mutex_t keyToFdMapLock;


extern pthread_mutex_t SupiAmfUeNgapIdMapLock;
extern pthread_mutex_t UeContextMapLock;
extern pthread_mutex_t globalContextMapLock;
extern pthread_mutex_t UeContextMapTempLock;
extern pthread_mutex_t SuciAmfUeNgapIdMapLock;

#define state_type string

// from linking.cpp
void sbiIncoming(char* message, int len, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst);
void sbiIncomingRequestJSON(char* message, int len, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst);
void ngapIncoming(char* message, int len, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst);
void handleUPLN(NGAP_PDU_t* messageBody, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst);
void handleDNLN(NGAP_PDU_t* messageBody, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst);
void handleINITUE(NGAP_PDU_t* messageBody, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst);
void NGSetupRequest(NGAP_PDU_t* messageBody, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst);
void NGSetupResponse(NGAP_PDU_t* messageBody, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst);
void initialRegistrationRequest(NGAP_PDU_t* messageBody,nasMessage_t nasMsg, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst);
void identityRequest(NGAP_PDU_t* messageBody,nasMessage_t nasMsg, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst);
void identityResponse(NGAP_PDU_t* messageBody,nasMessage_t nasMsg, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst);
void nrfDiscoveryResponse(json messageBody, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst);
void AUSFSelection(AmfUeNgapId_t amfUeNgapId, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst);
void ueAuthentication(AmfUeNgapId_t amfUeNgapId, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst);
void ueAuthenticationResponse(json messageBody, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst);
void NasAuthentication(int amfUeNgapId, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst);
void NasAuthenticationResponse(NGAP_PDU_t* messageBody,nasMessage_t nasMsg, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst);
void ueAuthenticationUpdate(AmfUeNgapId_t amfUeNgapId, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst);
void ueAuthenticationUpdateResponse(json messageBody, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst);
void NasSecurityModeCommand(int amfUeNgapId, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst);
void NasSecurityInitiationResponse(NGAP_PDU_t* messageBody,nasMessage_t nasMsg, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst);
void initialContextSetup(AmfUeNgapId_t amfUeNgapId, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst);
void initialContextSetupResponse(NGAP_PDU_t* messageBody, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst);
void udmSelection(AmfUeNgapId_t amfUeNgapId, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst);
void uecmRegistration(AmfUeNgapId_t amfUeNgapId, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst);
void uecmRegistrationResponse(json messageBody, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst);
void udmSDMGet(int amfUeNgapId, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst);
void udmSDMGetResponse(json messageBody, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst);
void registrationAccept(int amfUeNgapId, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst);
void registrationAcceptResponse(NGAP_PDU_t* messageBody,nasMessage_t nasMsg, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst);
