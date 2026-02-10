/**
 * FILE: udf.h
 * -------------
 * Enocoders and decoders must be specified via a single-line comment of 
 * the form <@@f_type: message_type> just above the function declaration.
 * Encoders/Decoders must always be passed the size of encoded data by reference.
 * Refer to decodesupi() for your decoders.
 * 
 * @@keygen: Necessary for every Pyramis NF. Every timer must have atleast a procedurekey,
 * i.e. a variable that contains the result of a call to a keygen. 
*/
#ifndef __UDF_H__
#define __UDF_H__

// All headers are user-defined.
// udf cant have any dependencies on the platform file
#include <vector>
//#include "./generated/synerp_platform.h"
#include "./utils/synerp_messages.h"

// include the platform file?
// #include "./__BUILD__/NF_A/NF_A_platform.h"

//@@encoder: SynerPMessageHeader_t
void SynerPMessageHeaderEncode(std::vector<char>& buffer, SynerPMessageHeader_t &msg_struct, size_t &buffer_size);

//@@decoder: SynerPMessageHeader_t
void SynerPMessageHeaderDecode(SynerPMessageHeader_t &msg_struct, std::vector<char>& message, size_t &buffer_size); // THIS IS CORRECT DECODE FORMAT (body,  buffer, size)

// THIS IS CORRECT ENCODE FORMAT (buffer, body, size)
//@@encoder: SynerPMessage_t
void SynerPMessageEncode(std::vector<char>& buffer, SynerPMessage_t &msg_struct, size_t &buffer_size); 

//@@decoder: SynerPMessage_t
void SynerPMessageDecode(SynerPMessage_t &msg_struct, std::vector<char>& buffer, size_t &buffer_size);


// int nasMessagePlainDecode(nasMessage_t &nasMessage, uint8_t *buffer, uint32_t decodedLen);
// int ngapGetNasPdu(NAS_PDU_t &naPdu, NGAP_PDU_t *ngapPdu);
// int ngapGetRanUeNgapId(RAN_UE_NGAP_ID_t &ranUeid, NGAP_PDU_t *ngapPdu);
// int ngapGetAmfUeNgapId(AMF_UE_NGAP_ID_t &amfUeId, NGAP_PDU_t *ngapPdu);
// int retrieveMobileIdentity(suci_t &_suci, RegistrationRequest_t *regRequest);
// int suciSchemeToImsi(std::string &suci_imsi, suci_t &SUCI);
// int generateAmfUeNgapId(AmfUeNgapId_t &amfUeNgapId);


// create a custom response string
std::string generate_login_response(_e_SynerPLoginResponse r_type);

std::string get_timer_name(_e_TimerType t_type);
std::string generate_timer_response(std::string userID, _e_TimerType t_type, _e_SynerPLoginResponse r_type);

//@@keygen
int generate_procedure_key();

#endif