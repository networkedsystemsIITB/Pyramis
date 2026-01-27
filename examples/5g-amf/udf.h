// defaults - for ngap and http, from template
#include "../utility_library/ngap/codec/include/ngap_helper.h"
#include "../utility_library/nas/NasMessage.h"
#include "../utility_library/nas/mobility/RegistrationRequest.h"
#include "../http_library.h"
#include "../../utility_library/aka/include/securityContext.h" // for nasmessagetoOctetString.
#include <nlohmann/json.hpp>
using json = nlohmann::json;

// decode functions must be void by defualt
void decode_sbi_message(json &messageBody, char *message, int len);
void decode_sbi_json_header(json &header, char *message, int len);
void decodeNgapPdu(NGAP_PDU_t *&ngapPdu_p, char *message, int blobLen);
void encodeNgap(char *buffer, NGAP_PDU_t* message, size_t &sz);
void encodeHTTP(string &buffer, HttpRequest& messagebody, size_t &sz);

int decodePduResSetupResTrnsfr(uint8_t* n2SmMessage);
int ngapGetProcedureCode(NGAP_PDU_t* ngapPdu);
// void ngapFree(NGAP_PDU_t *ngapPdu);

int ngapGetProcedureCode(int &procedureCode, NGAP_PDU_t* ngapPdu);
int ngapGetRanUeNgapId(RAN_UE_NGAP_ID_t &ranUeid, NGAP_PDU_t *ngapPdu);
int ngapGetAmfUeNgapId(AMF_UE_NGAP_ID_t &amfUeId, NGAP_PDU_t *ngapPdu);

int asn_INTEGER2ulong(AmfUeNgapId_t *l, const INTEGER_t *i);
int ngapGetNasPdu(NAS_PDU_t &naPdu, NGAP_PDU_t *ngapPdu);


int nasMessagePlainDecode(nasMessage_t &nasMessage, uint8_t *buffer, uint32_t decodedLen);
int generateAmfUeNgapId(AmfUeNgapId_t &amfUeNgapId);
int retrieveMobileIdentity(suci_t &_suci, RegistrationRequest_t *regRequest);
int suciToString(string &suci, suci_t &SUCI);
int suciSchemeToImsi(string &suci_imsi, suci_t &SUCI);
int computeIp(TransportLayerAddress_t &transportLayerAddress, json message);
int getGlobalRANId(GlobalRANNodeID_t &gNB, NGAP_PDU_t *ngapPdu);
int BitStringToNum(int &gnbId, BIT_STRING_t gNBId);

Cause_PR getCausePR(ngap_error_cause_t errNum);
int setFailureCause(Cause_t &Cause, int errNum);
int getNgApCause(Cause_t *cause, ngApCause_t *ngApCause);
int getCause(ngApCause_t ngapCause, Cause_t* cause);


//int OCTET_STRING_fromBuf(OCTET_STRING_t *st, const char *str, int len);
OCTET_STRING_t toOctetString(const char *str, int len=-1);
OCTET_STRING_t nasMessagetoOctetString(nasMessage_t *nas_m, secContext_t *secCtxt);
int BIT_STRING_fromNum(BIT_STRING_t *st, uint64_t input,int bit_length);
int BIT_STRING_fromBuf(BIT_STRING_t *st, const char *str,int bit_length); 

GUAMI_t generateGuami();
guti_5gMobileId_t generateGuti();
string getSnName();

int hexCopyFromStrings(uint8_t arr[], uint size, std::string hexS);
int hexCopyToStrings(std::string &hexS, uint8_t *arr, uint size);

int asn_ulong2INTEGER(INTEGER_t *st, unsigned long value);
int increment(uint8_t &num, int inc);