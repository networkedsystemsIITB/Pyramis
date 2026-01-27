#include "udf.h"
#include <string.h>
#include "ngap/codec/include/ngap_helper.h"
#include "platform/include/logging.h"
#include "common/include/datatypes.h"

#define BUF_SIZE 8192 // maybe not the best. Maybe define in udf.h? Reqd for nasmessagetoOctetString.

//edit

/* There is no order constraint. SEQUENCE items can be in any possible order.
 * These functions search and provide the pointer to the same.
 *
 * Note: A comment was written here previously, which stated the opposite.
 *       It has been removed.
 *         -TT
 */

#define MAX_MESSAGE_SIZE 3000

queue <uint32_t> _5gTMSIFreeQ;


#define FETCH_IE_PTR(ieType, ieVar, var)                                    \
    void *temp;                                                             \
    /* got the seqHead pointer. find RAN_UE_NGAP_ID */                      \
    for(seq_itr=0; seq_itr<seqCount; seq_itr++) {                           \
        if(ASN_SEQUENCE_GET(seqHead, seq_itr, &temp) < 0) {                 \
            higLog("ASN_SEQUENCE_GET failed itr %d, count %d",              \
                        seq_itr, seqCount);                                 \
            return NULL;                                                    \
        }                                                                   \
        if(((ieType##_t*)temp)->value.present !=                            \
            ieType##__value_PR_##ieVar) {                                   \
            continue;                                                       \
        }                                                                   \
        var = &(((ieType##_t*)temp)->value.choice.ieVar);                   \
        break;                                                              \
    }                                                                       \
    if(seq_itr == seqCount) {                                               \
        higLog("%s",#ieVar " Not Found");                                   \
        return NULL;                                                        \
    }

void decode_sbi_message(json &messageBody, char *message, int len){
    // update messagebody ref
    string temp = string(message, len);
	HttpResponse res = string_to_response(temp);
    messageBody = res.message_content;
}

void decode_sbi_json_header(json &messageBody, char *message, int len){
    // update messagebody ref
    string temp = string(message, len);
    
	HttpResponse res = string_to_response(temp);
    messageBody = res.header;
    higLog("here");
}

void encodeHTTP(string& buffer, HttpRequest& httpmessage, size_t& sz){
        httpmessage.options.insert({"Content-Type", "application/json"}); //new
		httpmessage.SetContentLength(); // new - should be encodeJSON acc to encode_pos_only
		string httpmessage_enc = httpmessage.message_to_string();//new
        
        buffer = httpmessage_enc;
        sz = httpmessage_enc.length();
}

void encodeNgap(char *buffer, NGAP_PDU_t* message, size_t& sz) {
    char errBuf[sz] = {};
    size_t errlen = sz;
    asnLog(&asn_DEF_NGAP_PDU, message);
                    
    if (asn_check_constraints(&asn_DEF_NGAP_PDU, (void *)message, errBuf, &errlen) < 0)
        lowLog("check constraints failed: %s", errBuf);
    asn_enc_rval_t ec = aper_encode_to_buffer(&asn_DEF_NGAP_PDU, 0, (void *)message, (void *)buffer, sz);
    if (ec.encoded == -1)
    {
        higLog("Could not encode MessageAB(at %s)", ec.failed_type ? ec.failed_type->name : "unknown");
        exit(1);
    }
    else
    {
        lowLog("Encoded %d bits", ec.encoded);
        NGAP_PDU_t *decngap = 0;

        asn_dec_rval_t decRet = aper_decode_complete(0, &asn_DEF_NGAP_PDU, (void **)&decngap, (char *)buffer, sz);
        if (asn_check_constraints(&asn_DEF_NGAP_PDU, decngap, errBuf, &errlen) < 0)
            lowLog("check constraints failed: %s", errBuf);
        if (decRet.code == RC_OK)
            lowLog("%s", "Decode succeeded");
        else
            lowLog("Decode failed, Err %s", decRet.code == RC_FAIL ? "RC_FAIL" : "RC_WMORE");
        sz = BITCNT_TO_BYTECNT(ec.encoded);
    }
}

OCTET_STRING_t toOctetString(const char *str, int len){
    int t_len = len;

    if(len < 0){
        t_len = strlen(str) +  1;
    }

    char temp[t_len] = {};

    memcpy(temp, str, t_len);

    lowLog("tempstr in octet: %s", temp);

    OCTET_STRING_t ret_str = {};

    int ret = OCTET_STRING_fromBuf(&ret_str, temp, len);
    
    if(ret == -1){
        lowLog("OCTET_STRING converstion Failed");
        exit(-1);
    }


    return ret_str;
}

OCTET_STRING_t nasMessagetoOctetString(nasMessage_t *nas_m, secContext_t *secCtxt){
    char nasMsgBuf[BUF_SIZE] = {}; //either include 

    uint32_t nasMsgBufLen = 0;

    if (nasMessageEncode((uint8_t *)nasMsgBuf, MAX_MSG_LEN, nas_m, &nasMsgBufLen, secCtxt) == FAILURE)
        lowLog("%s", "NAS Message Encode failed");

	OCTET_STRING_t ret_str = {};
    lowLog("sz_oct: %ld\n", nasMsgBufLen);

	int ret = OCTET_STRING_fromBuf(&ret_str, nasMsgBuf, nasMsgBufLen);
    lowLog("sz_oct: %ld\n", ret_str.size);

    if(ret == -1){
        lowLog("OCTET_STRING converstion Failed");
        exit(-1);
    }

    return ret_str;
}

/* Will allocate and decode the contents into the struct.
 * RETURN: SUCCESS/FAILURE.
 * on success the extracted struct MUST be freed using ngapFree() NOT free()
 * on failure, the decoded struct is freed in decodeNgapPdu()
 */
int decodeNgapPdu(NGAP_PDU_t **ngapPdu_p, void * blob, int blobLen)
{
	NGAP_PDU_t  *ngapPdu = 0;
	asn_dec_rval_t decRet;
    char errBuf[MAX_MESSAGE_SIZE] = {};
    size_t errlen = MAX_MESSAGE_SIZE;

	/*decode msg into NGAP PDU*/
	decRet = aper_decode_complete(0, &asn_DEF_NGAP_PDU,
				(void**) &ngapPdu, (char*) blob, blobLen);

	if(asn_check_constraints(&asn_DEF_NGAP_PDU, ngapPdu,
					errBuf, &errlen) < 0)
		higLog("check constraints failed: %s", errBuf);

	if(decRet.code == RC_OK) {
		lowLog("%s", "Decode succeeded");
		asnLog(&asn_DEF_NGAP_PDU, ngapPdu);
		*ngapPdu_p = ngapPdu;
		return SUCCESS;
	} else {
		higLog("Decode failed, Err %s", decRet.code == RC_FAIL ?
						"RC_FAIL" : "RC_WMORE");
		ngapFree(ngapPdu);
		*ngapPdu_p = NULL;
		return FAILURE;
	}
}

void __asnLog(const asn_TYPE_descriptor_t *td, const void *struct_ptr,
            const char* file, int line, const char* func) {

#if 0
    //No longer needed since asnLog is mid log now
    if(!checkLevel(1)) {
        /* this will be rechecked in lowLog, But, going through all of
         * asn_fprint and finally not being printed by platform is just
         * to sad to watch. :( */
        return;
    }
#endif

    char *printBuf = NULL;
    size_t ptr = 0;
    FILE *filep = open_memstream(&printBuf, &ptr);
    if(filep==NULL) {
        printf("ERROR:open_memstream failed");
    }
    asn_fprint(filep, td, struct_ptr);

    fclose(filep);
    platformLog(0xF1, file, line, func,
                "\tASN_LOG: start:\n%sASN_LOG:end", printBuf);
    free(printBuf);
}



/* get the procedure code from NGAP_PDU*/
int   ngapGetProcedureCode(NGAP_PDU_t* ngapPdu)
{
	switch (ngapPdu->present) {
	case NGAP_PDU_PR_initiatingMessage:
		return ngapPdu->choice.initiatingMessage->procedureCode;
		break;
	case NGAP_PDU_PR_successfulOutcome:
		return ngapPdu->choice.successfulOutcome->procedureCode;
		break;
	case NGAP_PDU_PR_unsuccessfulOutcome:
		return ngapPdu->choice.unsuccessfulOutcome->procedureCode;
		break;
	default:
		higLog("Invalid NGAP PDU\n");
		return FAILURE;
	}
}

void * ngapGetProtocolIeListPtr(NGAP_PDU_t *ngapPdu)
{
    switch(ngapPdu->present) {
    case NGAP_PDU_PR_initiatingMessage: /*initiatingMessage*/
        switch(ngapPdu->choice.initiatingMessage->value.present) {
        case InitiatingMessage__value_PR_InitialUEMessage:
        {   /*brackets to prevent declarations within a case from
             * being visible in the next case */
            if(ngapPdu->choice.initiatingMessage->procedureCode !=
                    ProcedureCode_id_InitialUEMessage){
                higLog("Mismatching procedureCode %d",
                        ngapPdu->choice.initiatingMessage->procedureCode);
                return NULL;
            }
            InitialUEMessage_t *initUEmsg =
                &ngapPdu->choice.initiatingMessage->value.choice
                        .InitialUEMessage;
            return (void*)(&initUEmsg->protocolIEs.list);
        }

        case InitiatingMessage__value_PR_PDUSessionResourceSetupRequest:
        {
            if(ngapPdu->choice.initiatingMessage->procedureCode !=
                        ProcedureCode_id_PDUSessionResourceSetup){
                higLog("Mismatching procedureCode %d",
                        ngapPdu->choice.initiatingMessage->procedureCode);
                return NULL;
            }
            PDUSessionResourceSetupRequest_t *PDUSessionResSetupReq =
                &ngapPdu->choice.initiatingMessage->value.choice
                                .PDUSessionResourceSetupRequest;
            return (void*) (&PDUSessionResSetupReq->protocolIEs.list);
        }
        case InitiatingMessage__value_PR_UplinkNASTransport:
        {
            if(ngapPdu->choice.initiatingMessage->procedureCode !=
                    ProcedureCode_id_UplinkNASTransport){
                /* asn_VAL_44_id_UplinkNASTransport */
                higLog("Mismatching procedureCode %d",
                        ngapPdu->choice.initiatingMessage->procedureCode);
                return NULL;
            }
            UplinkNASTransport_t *uplinkNasTransport =
                &ngapPdu->choice.initiatingMessage->value.choice
                        .UplinkNASTransport;
            return (void*)(&uplinkNasTransport->protocolIEs.list);
        }

        case InitiatingMessage__value_PR_DownlinkNASTransport:
        {
            if(ngapPdu->choice.initiatingMessage->procedureCode !=
                    ProcedureCode_id_DownlinkNASTransport){
                /* asn_VAL_22_id_DownlinkNASTransport */
                higLog("Mismatching procedureCode %d",
                        ngapPdu->choice.initiatingMessage->procedureCode);
                return NULL;
            }
            DownlinkNASTransport_t *downlinkNasTransport =
                &ngapPdu->choice.initiatingMessage->value.choice
                        .DownlinkNASTransport;
            return (void*)(&downlinkNasTransport->protocolIEs.list);
        }


        case InitiatingMessage__value_PR_NGSetupRequest:
        {
            if(ngapPdu->choice.initiatingMessage->procedureCode !=
                    ProcedureCode_id_NGSetup){
                /* asn_VAL_7_id_NGSetup */
                higLog("Mismatching procedureCode %d",
                        ngapPdu->choice.initiatingMessage->procedureCode);
                return NULL;
            }
            NGSetupRequest_t *ngSetupReq =
                &ngapPdu->choice.initiatingMessage->value.choice.NGSetupRequest;
            return (void*)(&ngSetupReq->protocolIEs.list);
        }

        case InitiatingMessage__value_PR_InitialContextSetupRequest: {
            if(ngapPdu->choice.initiatingMessage->procedureCode !=
                    ProcedureCode_id_InitialContextSetup){
                /*asn_VAL_5_id_InitialContextSetup*/
                higLog("Mismatching Procedure Code : %d",
                        ngapPdu->choice.initiatingMessage->procedureCode);
                return NULL;
            }
            InitialContextSetupRequest_t *initialContextSetupReq =
                &ngapPdu->choice.initiatingMessage->value.choice.
                InitialContextSetupRequest;
            return (void*)(&initialContextSetupReq->protocolIEs.list);
        }
        case InitiatingMessage__value_PR_UEContextReleaseCommand: {
            if(ngapPdu->choice.initiatingMessage->procedureCode !=
                    ProcedureCode_id_UEContextRelease){
                /*asn_VAL_16_id_UEContextRelease */
                higLog("Mismatching Procedure Code : %d",
                        ngapPdu->choice.initiatingMessage->procedureCode);
                return NULL;
            }
            UEContextReleaseCommand_t *UEContextReleaseCommand =
                    &ngapPdu->choice.initiatingMessage->value.choice.
                    UEContextReleaseCommand;
            return (void*)(&UEContextReleaseCommand->protocolIEs.list);
        }
        case InitiatingMessage__value_PR_PDUSessionResourceReleaseCommand: {
            if(ngapPdu->choice.initiatingMessage->procedureCode !=
                    ProcedureCode_id_PDUSessionResourceRelease){
                /*asn_VAL_11_id_PDUSessionResourceRelease */
                higLog("Mismatching Procedure Code : %d",
                        ngapPdu->choice.initiatingMessage->procedureCode);
                return NULL;
            }
            PDUSessionResourceReleaseCommand_t  *PDUSessResRelCmd =
                        &ngapPdu->choice.initiatingMessage->value.
                        choice.PDUSessionResourceReleaseCommand;
            return (void*)(&PDUSessResRelCmd->protocolIEs.list);
        }
        break;

        default:
            higLog("Invalid Initiating Message data\n");
            return NULL;
        }
    break; /* end of NGAP_PDU_PR_initiatingMessage */

    case NGAP_PDU_PR_successfulOutcome:
        switch(ngapPdu->choice.successfulOutcome->value.present) {
        case SuccessfulOutcome__value_PR_InitialContextSetupResponse: {
            if(ngapPdu->choice.successfulOutcome->procedureCode != 
                    ProcedureCode_id_InitialContextSetup){
                /*asn_VAL_5_id_InitialContextSetup*/
                higLog("Mismatching Procedure Code : %d",
                        ngapPdu->choice.successfulOutcome->procedureCode);
                return NULL;
            }
            InitialContextSetupResponse_t *initialContextSetupResponse =
                &ngapPdu->choice.successfulOutcome->value.choice.
                InitialContextSetupResponse;
            return (void*)(&initialContextSetupResponse->protocolIEs.list);
        }
        break;

        case SuccessfulOutcome__value_PR_UEContextReleaseComplete: {
            if(ngapPdu->choice.successfulOutcome->procedureCode != 
                    ProcedureCode_id_UEContextRelease){
                /*asn_VAL_16_id_UEContextRelease */
                higLog("Mismatching Procedure Code : %d",
                        ngapPdu->choice.successfulOutcome->procedureCode);
                return NULL;
            }
            UEContextReleaseComplete_t *UEContextReleaseComplete=
                    &ngapPdu->choice.successfulOutcome->value.choice.
                    UEContextReleaseComplete;
            return (void*)(&UEContextReleaseComplete->protocolIEs.list);
        }
        break;

        case SuccessfulOutcome__value_PR_PDUSessionResourceReleaseResponse: {
            if(ngapPdu->choice.successfulOutcome->procedureCode !=
                    ProcedureCode_id_PDUSessionResourceRelease){
                higLog("Mismatching Procedure Code : %d",
                        ngapPdu->choice.successfulOutcome->procedureCode);
                return NULL;
            }
            PDUSessionResourceReleaseResponse_t  *PDUSessResRelResp =
                        &ngapPdu->choice.successfulOutcome->value.
                        choice.PDUSessionResourceReleaseResponse;
            return (void*)(&PDUSessResRelResp->protocolIEs.list);
        }
        break;
        case SuccessfulOutcome__value_PR_PDUSessionResourceSetupResponse: {
            if(ngapPdu->choice.successfulOutcome->procedureCode !=
                    ProcedureCode_id_PDUSessionResourceSetup){
                higLog("Mismatching Procedure Code : %d",
                        ngapPdu->choice.successfulOutcome->procedureCode);
                return NULL;
            }
            PDUSessionResourceSetupResponse_t  *PDUSessResSetupResp =
                        &ngapPdu->choice.successfulOutcome->value.
                        choice.PDUSessionResourceSetupResponse;
            return (void*)(&PDUSessResSetupResp->protocolIEs.list);
        }
        break;
        default:
            higLog("Invalid SuccessMessage Data");
            return NULL;
        }
    break; /* end of NGAP_PDU_PR_successfulOutcome */

    case NGAP_PDU_PR_unsuccessfulOutcome:
        switch(ngapPdu->choice.unsuccessfulOutcome->value.present)
        {
        case UnsuccessfulOutcome__value_PR_InitialContextSetupFailure:{
            if(ngapPdu->choice.unsuccessfulOutcome->procedureCode !=
                ProcedureCode_id_InitialContextSetup){
            /*asn_VAL_5_id_InitialContextSetup*/
            higLog("Mismatching Procedure Code : %d",
                    ngapPdu->choice.unsuccessfulOutcome->procedureCode);
            return NULL;
            }
            InitialContextSetupFailure_t *initialContextSetupFailure =
                &ngapPdu->choice.unsuccessfulOutcome->value.choice.
                InitialContextSetupFailure;
            return (void*)&initialContextSetupFailure->protocolIEs.list;
        }
        break;

        default:
            higLog("Invalid UnsuccessMessage Data");
            return NULL;
        }
    break; /* end of NGAP_PDU_PR_unsuccessfulOutcome */

    default:
        higLog("Invalid NGAP PDU\n");
        return NULL;
    }
}

int ngapGetProcedureCode(int &procedureCode, NGAP_PDU_t* ngapPdu) {
    procedureCode = ngapGetProcedureCode (ngapPdu);
    return SUCCESS;
} 

int ngapGetRanUeNgapId(RAN_UE_NGAP_ID_t &ranUeNgapId, NGAP_PDU_t *ngapPdu) { // NGAP_PDU_t: fixed message type received on interface
    
    RAN_UE_NGAP_ID_t *ranUeId = ngapGetRanUeNgapId (ngapPdu);

    if (ranUeId == NULL) {
        return FAILURE;
    }

    ranUeNgapId = *ranUeId;

    return SUCCESS;
}

int ngapGetAmfUeNgapId(AMF_UE_NGAP_ID_t &amfUeNgapId, NGAP_PDU_t *ngapPdu) {
    
    AMF_UE_NGAP_ID_t* amfUeId = ngapGetAmfUeNgapId (ngapPdu); 

    if (amfUeId == NULL) {
        return FAILURE;
    }

    amfUeNgapId = *amfUeId;

    return SUCCESS;
}

int ngapGetNasPdu(NAS_PDU_t &nasPdu, NGAP_PDU_t *ngapPdu) {
    
    NAS_PDU_t* nas = ngapGetNasPdu (ngapPdu); 

    if (nas == NULL) {
        return FAILURE;
    }

    nasPdu = *nas;

    return SUCCESS;
}

int getGlobalRANId (GlobalRANNodeID_t &gNB, NGAP_PDU_t *ngapPdu) {
    
    GlobalRANNodeID_t* ranId = ngapGetGlobalRANNodeId (ngapPdu); 

    if (ranId == NULL) {
        return FAILURE;
    }

    gNB = *ranId;

    return SUCCESS;
}

int BitStringToNum (int &gnbId, BIT_STRING_t gNBId) {
    int size = gNBId.size;
    int unused = gNBId.bits_unused;
    uint8_t* buff = gNBId.buf;

    gnbId = 0;

    for (int i = 0; i < size-unused; i++) {
        gnbId = gnbId*8 + buff[i];
    }

    return SUCCESS;
}

/* returns SUCCESS or FAILURE */
RAN_UE_NGAP_ID_t* ngapGetRanUeNgapId(NGAP_PDU_t *ngapPdu)
{
    RAN_UE_NGAP_ID_t *ranUeNgapId;
    int seq_itr = 0;
    void *seqHead = ngapGetProtocolIeListPtr(ngapPdu);
    if(seqHead == NULL) {
        return NULL;
    }

    int seqCount = ASN_SEQUENCE_GET_COUNT(seqHead);

    ProcedureCode_t procedureCode = ngapGetProcedureCode(ngapPdu);

    switch(procedureCode)
    {
    case ProcedureCode_id_InitialUEMessage: {
        FETCH_IE_PTR(InitialUEMessage_IEs, RAN_UE_NGAP_ID, ranUeNgapId);
    }
    break;

    case ProcedureCode_id_UplinkNASTransport: {
        FETCH_IE_PTR(UplinkNASTransport_IEs, RAN_UE_NGAP_ID, ranUeNgapId);
    }
    break;

    case ProcedureCode_id_DownlinkNASTransport: {
        FETCH_IE_PTR(DownlinkNASTransport_IEs, RAN_UE_NGAP_ID, ranUeNgapId);
    }
    break;

    case ProcedureCode_id_InitialContextSetup: {
        switch(ngapPdu->present) {
        case NGAP_PDU_PR_initiatingMessage: {
            FETCH_IE_PTR(InitialContextSetupRequestIEs, RAN_UE_NGAP_ID,
                            ranUeNgapId);
        }
        break;
        default: {
            higLog("Invalid procedureCode %d", procedureCode);
            return NULL;
        }
        }
    }
    break;

    case ProcedureCode_id_UEContextRelease: {
        switch(ngapPdu->present) {
        case NGAP_PDU_PR_successfulOutcome: {
            FETCH_IE_PTR(UEContextReleaseComplete_IEs, RAN_UE_NGAP_ID,
                            ranUeNgapId);
        }
        break;
        default: {
            higLog("Invalid procedureCode %d", procedureCode);
            return NULL;
        }
        }
    }
    break;

    case ProcedureCode_id_PDUSessionResourceSetup: {
        switch(ngapPdu->present) {
        case NGAP_PDU_PR_initiatingMessage: {
            FETCH_IE_PTR(PDUSessionResourceSetupRequestIEs , RAN_UE_NGAP_ID,
                            ranUeNgapId);
        }
        break;
        case NGAP_PDU_PR_successfulOutcome: {
            FETCH_IE_PTR(PDUSessionResourceSetupResponseIEs , RAN_UE_NGAP_ID,
                            ranUeNgapId);
        }
        break;
        default: {
            higLog("Invalid procedureCode %d", procedureCode);
            return NULL;
        }
        }
    }
    break;

    case ProcedureCode_id_PDUSessionResourceRelease: {
        switch(ngapPdu->present) {
        case NGAP_PDU_PR_initiatingMessage: {
            FETCH_IE_PTR(PDUSessionResourceReleaseCommandIEs , RAN_UE_NGAP_ID,
                            ranUeNgapId);
        }
        break;
        case NGAP_PDU_PR_successfulOutcome: {
            FETCH_IE_PTR(PDUSessionResourceReleaseResponseIEs, RAN_UE_NGAP_ID,
                            ranUeNgapId);
        }
        break;
        default: {
            higLog("Invalid procedureCode %d", procedureCode);
            return NULL;
        }
        }
    }
    break;

    default:
        higLog("Invalid procedureCode %d", procedureCode);
        return NULL;
    }
    return ranUeNgapId;
}

/* returns SUCCESS or FAILURE */
AMF_UE_NGAP_ID_t *ngapGetAmfUeNgapId(NGAP_PDU_t *ngapPdu)
{
    AMF_UE_NGAP_ID_t *amfUeNgapId;
    int seq_itr = 0;
    void *seqHead = ngapGetProtocolIeListPtr(ngapPdu);
    if(seqHead == NULL) {
        return NULL;
    }

    int seqCount = ASN_SEQUENCE_GET_COUNT(seqHead);

    ProcedureCode_t procedureCode = ngapGetProcedureCode(ngapPdu);

    switch(procedureCode)
    {
        case ProcedureCode_id_UplinkNASTransport: {
            FETCH_IE_PTR(UplinkNASTransport_IEs, AMF_UE_NGAP_ID, amfUeNgapId);
            break;
        }

        case ProcedureCode_id_DownlinkNASTransport: {
            FETCH_IE_PTR(DownlinkNASTransport_IEs, AMF_UE_NGAP_ID, amfUeNgapId);
        }
        break;

        case ProcedureCode_id_InitialContextSetup: {
            switch(ngapPdu->present) {
            case NGAP_PDU_PR_initiatingMessage: {
                FETCH_IE_PTR(InitialContextSetupRequestIEs, AMF_UE_NGAP_ID,
                            amfUeNgapId);
            }
            break;
                        case NGAP_PDU_PR_successfulOutcome: {
                FETCH_IE_PTR(InitialContextSetupResponseIEs, AMF_UE_NGAP_ID,
                            amfUeNgapId);
            }
            break;
            default: {
                higLog("Invalid procedureCode %d", procedureCode);
                return NULL;
            }
            }
        }
        break;

        case ProcedureCode_id_UEContextRelease: {
            switch(ngapPdu->present) {
            case NGAP_PDU_PR_successfulOutcome: {
                FETCH_IE_PTR(UEContextReleaseComplete_IEs, AMF_UE_NGAP_ID,
                            amfUeNgapId);
            }
            break;
            default: {
                higLog("Invalid procedureCode %d", procedureCode);
                return NULL;
            }
            }
        }
        break;

        case ProcedureCode_id_PDUSessionResourceSetup: {
            switch(ngapPdu->present) {
            case NGAP_PDU_PR_initiatingMessage: {
                FETCH_IE_PTR(PDUSessionResourceSetupRequestIEs , AMF_UE_NGAP_ID,
                                amfUeNgapId);
            }
            break;
            case NGAP_PDU_PR_successfulOutcome: {
                FETCH_IE_PTR(PDUSessionResourceSetupResponseIEs , AMF_UE_NGAP_ID,
                                amfUeNgapId);
            }
            break;
            default: {
                higLog("Invalid procedureCode %d", procedureCode);
                return NULL;
            }
            }
        }
        break;

        case ProcedureCode_id_PDUSessionResourceRelease: {
            switch(ngapPdu->present) {
            case NGAP_PDU_PR_initiatingMessage: {
                FETCH_IE_PTR(PDUSessionResourceReleaseCommandIEs , AMF_UE_NGAP_ID,
                                amfUeNgapId);
            }
            break;
            case NGAP_PDU_PR_successfulOutcome: {
                FETCH_IE_PTR(PDUSessionResourceReleaseResponseIEs, AMF_UE_NGAP_ID,
                                amfUeNgapId);
            }
            break;
            default: {
                higLog("Invalid procedureCode %d", procedureCode);
                return NULL;
            }
            }
        }
        break;

        default: {
            higLog("Invalid procedureCode %d", procedureCode);
            return NULL;
        }
    }
    return amfUeNgapId;
}

/* returns SUCCESS or FAILURE */
NAS_PDU_t *ngapGetNasPdu(NGAP_PDU_t *ngapPdu)
{
    NAS_PDU_t *nasPdu;
    int seq_itr = 0;
    void *seqHead = ngapGetProtocolIeListPtr(ngapPdu);
    if(seqHead == NULL) {
        return NULL;
    }

    int seqCount = ASN_SEQUENCE_GET_COUNT(seqHead);

    ProcedureCode_t procedureCode = ngapGetProcedureCode(ngapPdu);

    switch(procedureCode)
    {
        case ProcedureCode_id_InitialUEMessage: {
            FETCH_IE_PTR(InitialUEMessage_IEs, NAS_PDU, nasPdu);
        }
        break;

        case ProcedureCode_id_UplinkNASTransport: {
            FETCH_IE_PTR(UplinkNASTransport_IEs, NAS_PDU, nasPdu);
        }
        break;

        case ProcedureCode_id_DownlinkNASTransport: {
            FETCH_IE_PTR(DownlinkNASTransport_IEs, NAS_PDU, nasPdu);
        }
        break;

        case ProcedureCode_id_InitialContextSetup: {
            switch(ngapPdu->present) {
            case NGAP_PDU_PR_initiatingMessage: {
                FETCH_IE_PTR(InitialContextSetupRequestIEs, NAS_PDU, nasPdu);
            }
            break;
            default: {
                higLog("Invalid procedureCode %d", procedureCode);
                return NULL;
            }
            }
        }
        break;

        case ProcedureCode_id_PDUSessionResourceRelease: {
            switch(ngapPdu->present) {
            case NGAP_PDU_PR_initiatingMessage: {
                FETCH_IE_PTR(PDUSessionResourceReleaseCommandIEs , NAS_PDU,
                                nasPdu);
            }
            break;
            default: {
                higLog("Invalid procedureCode %d", procedureCode);
                return NULL;
            }
            }
        }
        break;

        default: {
            higLog("Invalid procedureCode %d", procedureCode);
            return NULL;
        }
    }
    return nasPdu;
}

void ngapFree(NGAP_PDU_t *ngapPdu)
{
	ASN_STRUCT_FREE(asn_DEF_NGAP_PDU, ngapPdu);
}

Cause_PR getCausePR(ngap_error_cause_t errNum) {
    if(errNum >= E_RADIO_NETWORK_LAYER_UNSPECIFIED
        && errNum <= E_RADIO_NETWORK_LAYER_RELEASE_DUE_TO_CN_DETECTED_MOBILITY)
    {
        return Cause_PR_radioNetwork; 
    } else if (errNum >= E_TRANSPORT_LAYER_TRANSPORT_RESOURCE_UNAVAILABLE
        && errNum <= E_TRANSPORT_LAYER_UNSPECIFIED) {
        return Cause_PR_transport;
    } else if (errNum >= E_NAS_NORMAL_RELEASE
        && errNum <= E_NAS_UNSPECIFIED) {
        return Cause_PR_nas;
    } else if (errNum >= E_PROTOCOL_TRANSFER_SYNTAX_ERROR
        && errNum <= E_PROTOCOL_UNSPECIFIED) {
        return Cause_PR_protocol;
    } else if (errNum >= E_MISCELLANEOUS_CONTROL_PROCESSING_OVERLOAD
        && errNum <= E_MISCELLANEOUS_UNSPECIFIED) {
        return Cause_PR_misc;
    }
    return Cause_PR_NOTHING;
}

int setFailureCause(Cause_t &Cause, int errNum) {

    LOG_ENTRY;

    /* Initialized to Misc Unspecified error by default */
    Cause.present = Cause_PR_misc;
    Cause.choice.misc = CauseMisc_unspecified;  

    Cause_t cause = {};
    cause.present = getCausePR((ngap_error_cause_t)errNum);
    if(cause.present ==  Cause_PR_NOTHING) {
        higLog("Unknown Cause. This should not have happened for a valid errno");
        LOG_EXIT;
        return FAILURE;
    }

    switch(cause.present)
    {
        case Cause_PR_radioNetwork:
        {
            higLog("Not supporting radio Network Failure Intimation");
        }
        break;
        case Cause_PR_transport:
        {
            higLog("Not supporting transport Failure Intimation");
        }
        break;
        case Cause_PR_nas:
        {
            higLog("Not supporting nas Failure Intimation");
        }
        break;
        case Cause_PR_protocol:
        {
            higLog("Not supporting protocol Failure Intimation");
        }
        break;
        case Cause_PR_misc:
        {
            higLog("It is misc Failure");
            if(errno == E_MISCELLANEOUS_UNKNOWN_PLMN) {
                cause.choice.misc = CauseMisc_unknown_PLMN;
                higLog("Of type Unknown PLMN");
                Cause = cause;
            } else if(errno == E_MISCELLANEOUS_UNSPECIFIED) {
                cause.choice.misc = CauseMisc_unspecified;
                higLog("Of type Miscellaneous Unspecified");
                Cause = cause;
            } else {
                higLog("Of type which is unknown though");
            }
        }
        break;
        default:
        {
            higLog("Unknown Failure Cause");
            LOG_EXIT;
            return FAILURE;
        }
    }

    LOG_EXIT;
    return SUCCESS;
}



int asn_INTEGER2ulong(AmfUeNgapId_t *l, const INTEGER_t *iptr) {
    intmax_t v;
    if(asn_INTEGER2imax(iptr, &v) == 0) {
        if(v < LONG_MIN || v > LONG_MAX) {
            errno = ERANGE;
            return -1;
        }
        *l = v;
        return 0;
    } else {
        return -1;
    }
}

static unsigned long ids = 0;

int generateAmfUeNgapId(AmfUeNgapId_t &amfUeNgapId) {
    amfUeNgapId = ids;
    ids++;
    return SUCCESS;
}

int increment(uint8_t &num, int inc){
    num = num + inc;
    return SUCCESS;
}

int retrieveMobileIdentity(suci_t &_suci, RegistrationRequest_t *regRequest)
{
    LOG_ENTRY;
    uint8_t routingIncLSB = 0x00;
    uint8_t routingIncMSB = 0x00;

    /*TODO - Add the remaining parameters of SUCI - Table 9.11.3.4.2 in 24.501 */
    /* suci5gMobileId and guti5gMobileId structures are union in
     * 5gmobileId structure. So can get identityType from any one of them */
    // if (regRequest->_5gmobileId.suci5gMobileId.identityType == E_5G_GUTI)
    // {
    //     lowLog("RegReq has a GUTI, get suci from GutiMap");
    //     if (getFromGutiMap(regRequest->_5gmobileId.guti5gMobileId, &_suci) == FAILURE)
    //     {
    //         higLog("Error: GUTI not found");
    //         LOG_EXIT;
    //         return FAILURE;
    //     }
    // }
    if (regRequest->_5gmobileId.suci5gMobileId.identityType == E_SUCI)
    {
        _suci.mcc_1 = (regRequest->_5gmobileId.suci5gMobileId.mccDigit1);
        _suci.mcc_2 = regRequest->_5gmobileId.suci5gMobileId.mccDigit2;
        _suci.mcc_3 = (regRequest->_5gmobileId.suci5gMobileId.mccDigit3);
        _suci.mnc_1 = regRequest->_5gmobileId.suci5gMobileId.mncDigit1;
        _suci.mnc_2 = (regRequest->_5gmobileId.suci5gMobileId.mncDigit2);
        _suci.mnc_3 = regRequest->_5gmobileId.suci5gMobileId.mncDigit3;

        routingIncLSB = (regRequest->_5gmobileId.suci5gMobileId.routingInc2) |
                        (regRequest->_5gmobileId.suci5gMobileId.routingInc1);
        routingIncMSB = (regRequest->_5gmobileId.suci5gMobileId.routingInc4) |
                        (regRequest->_5gmobileId.suci5gMobileId.routingInc3);

        _suci.routingIndicator = (routingIncMSB << 8) | routingIncLSB;
        _suci.protectionSchemeId = (regRequest->_5gmobileId.suci5gMobileId.protectionSchId);

        _suci.homeNtwrkPKI =
            regRequest->_5gmobileId.suci5gMobileId.homeNtwrkPKI;

        memcpy(&(_suci.schemeOutput[0]),
               &(regRequest->_5gmobileId.suci5gMobileId.schemeOutput[0]),
               sizeof(_suci.schemeOutput));
        lowLog("Extracted Suci from regRequest");
    }

    // print_SUCI(_suci);

    LOG_EXIT;
    return SUCCESS;
}


int suciToString(string &suci_str, suci_t &SUCI) {
    suci_str = SUCI.to_string();
    return SUCCESS;
}

int suciSchemeToImsi(string &suci_imsi, suci_t &SUCI) {
    suci_imsi = SUCI.scheme_to_imsi();
    return SUCCESS;
}

int nasMessagePlainDecode(nasMessage_t &nasMessage, uint8_t *buffer, uint32_t decodedLen)
{
    nasLogENTRY;

    int epd = buffer[0];
    int rc;

    if(epd == _5GS_MOBILITY_MANAGEMENT_MESSAGE) {
        rc = _5gmmMsgDecode(buffer, &(nasMessage.plain._5gmmMsg),decodedLen);
        if(rc == FAILURE) {
            higLog("%s","_5gmmMsgDecode encode function failed");
            nasLogEXIT;
            return FAILURE;
        }
    }else if(epd == _5GS_SESSION_MANAGEMENT_MESSAGE) {
        rc = _5gsmMsgDecode(buffer, &(nasMessage.plain._5gsmMsg),decodedLen);   /*arguments TODO:(ddeka)*/
        if(rc == FAILURE) {
            higLog("%s","_5gsmMsgDecode decode function failed");
            nasLogEXIT;
            return FAILURE;
        }
    }else {
        higLog("%s","Unsupported ExtendedProtocolDiscriminator");
        errno = E_NAS_ERROR_INVALID_PDU;
        nasLogEXIT;
        return FAILURE;
    }

    nasLog("decoded plainMsg Len = %d", decodedLen);
    nasLogEXIT;
    return SUCCESS;
}

GUAMI_t generateGuami()
{
    GUAMI_t guami = {};
    ifstream ifs("amfconfig.json");
    Json::Reader reader;
    Json::Value amfConfig;
    reader.parse(ifs, amfConfig);
    /* Dummy value for PLMN ID in GUAMI */
    uint16_t mcc = amfConfig["guamiAndGutiInfo"]["plmn-mcc"].asInt();
    uint16_t mnc = amfConfig["guamiAndGutiInfo"]["plmn-mnc"].asInt();
    uint8_t mnc_digit_length = amfConfig["guamiAndGutiInfo"]["plmn-mnc-size"].asInt();

    char plmnBuf[PLMN_SIZE] = {};
    plmnBuf[0] = MCC_HUNDREDS(mcc) | (MCC_MNC_TENS(mcc) << 4);
    plmnBuf[1] = MCC_MNC_DIGIT(mcc) | (MNC_HUNDREDS(mnc, mnc_digit_length) << 4);
    plmnBuf[2] = MCC_MNC_TENS(mnc) | (MCC_MNC_DIGIT(mnc) << 4);

    OCTET_STRING_fromBuf(&guami.pLMNIdentity, plmnBuf, PLMN_SIZE);

    uint8_t amfRegId = amfConfig["guamiAndGutiInfo"]["amfRegionId"].asInt();
    BIT_STRING_fromNum((BIT_STRING_t *)&guami.aMFRegionID, amfRegId, 8);

    uint16_t amfSetId = (amfConfig["guamiAndGutiInfo"]["amfSetId"].asInt() & 0x03FF);
    BIT_STRING_fromNum((BIT_STRING_t *)&guami.aMFSetID, amfSetId, 10);

    uint8_t amfPointer = (amfConfig["guamiAndGutiInfo"]["amfPointer"].asInt() & 0x3F);
    BIT_STRING_fromNum((BIT_STRING_t *)&guami.aMFPointer, amfPointer, 6);
    return guami;
}




guti_5gMobileId_t generateGuti()
{

    guti_5gMobileId_t _guti = {};
    
    ifstream ifs("amfconfig.json");
    Json::Reader reader;
    Json::Value amfConfig;
    reader.parse(ifs, amfConfig);

    if (_5gTMSIFreeQ.empty())
        for (long long i = amfConfig["guamiAndGutiInfo"]["5gTMSI-start"].asInt(); i <= amfConfig["maxNumOfUEsSupported"].asInt(); i++)
            _5gTMSIFreeQ.push(i);

    _guti._5gTMSI = _5gTMSIFreeQ.front();
    _5gTMSIFreeQ.pop();

    _guti.reserved = 0xF;
    _guti.identityType = E_5G_GUTI;

    uint16_t tempMCC = amfConfig["guamiAndGutiInfo"]["plmn-mcc"].asInt();
    uint16_t tempMNC = amfConfig["guamiAndGutiInfo"]["plmn-mnc"].asInt();

    uint8_t mcc1 = tempMCC / 100;
    uint8_t mcc2 = (tempMCC % 100) / 10;
    uint8_t mcc3 = (tempMCC % 100) % 10;
    _guti.mccDigit1 = mcc1;
    _guti.mccDigit2 = mcc2;
    _guti.mccDigit3 = mcc3;

    if (amfConfig["guamiAndGutiInfo"]["plmn-mnc-size"].asInt() == 2)
    {
        uint8_t mnc1 = tempMNC / 10;
        uint8_t mnc2 = tempMNC % 10;
        uint8_t mnc3 = 0xF;
        _guti.mncDigit1 = mnc1;
        _guti.mncDigit2 = mnc2;
        _guti.mncDigit3 = mnc3;
    }
    else if (amfConfig["guamiAndGutiInfo"]["plmn-mnc-size"].asInt() == 3)
    {
        uint8_t mnc1 = tempMNC / 100;
        uint8_t mnc2 = (tempMNC % 100) / 10;
        uint8_t mnc3 = tempMNC % 10;
        _guti.mncDigit1 = mnc1;
        _guti.mncDigit2 = mnc2;
        _guti.mncDigit3 = mnc3;
    }
    _guti.amfRegionId = amfConfig["guamiAndGutiInfo"]["amfRegionId"].asInt();
    _guti.amfSetId = amfConfig["guamiAndGutiInfo"]["amfSetId"].asInt();
    _guti.amfPointer = amfConfig["guamiAndGutiInfo"]["amfPointer"].asInt();
    return _guti;
}

string getSnName()
{
    // char snName[SERVING_NETWORK_NAME_LEN];
    string snName="";
    ifstream ifs("amfconfig.json");
    Json::Reader reader;
    Json::Value amfConfig;
    reader.parse(ifs, amfConfig);

    uint16_t mcc = amfConfig["guamiAndGutiInfo"]["plmn-mcc"].asInt();
    uint16_t mnc = amfConfig["guamiAndGutiInfo"]["plmn-mnc"].asInt();

    std::string mcc_str = std::to_string(mcc);
    //mnc_digit_length in snName is always 3 digits
    std::string mnc_str = std::to_string(MNC_HUNDREDS(mnc,3));
    mnc_str += std::to_string(MCC_MNC_TENS(mnc));
    mnc_str += std::to_string(MCC_MNC_DIGIT(mnc));
    lowLog("mnc_str:%s", mnc_str.c_str());

    std::string buf = "5G:";
    buf += "mnc";
    buf += mnc_str;
    buf += "." ;
    buf += "mcc";
    buf += mcc_str ;
    buf += "." ;
    buf += amfConfig["networkName"].asString();
    /* Ref 24.501 9.12.1, expected snName = "5G:mnc015.mcc234.3gppnetwork.org"*/
    // memset(snName, 0, SERVING_NETWORK_NAME_LEN);
    // strncpy(snName, buf.c_str(), buf.length());
    snName=buf;

    return snName;
}

int hexCopyFromStrings(uint8_t arr[], uint size, std::string hexS)
{
    LOG_ENTRY;
    for(uint i=0; i < size; i++) {
        string temp = hexS.substr(2*i, 2);
        arr[i] = (uint8_t) strtol(temp.c_str(), NULL, 16);
    }
    LOG_EXIT;
    return SUCCESS;
}

int hexCopyToStrings(std::string &hexS, uint8_t *arr, uint size)
{
    char temp[size*2] = {}; /* each octet will be two */
    for(uint i=0; i< size ; i++) {
        sprintf(temp+ 2*i,"%02X", *(arr+i));
    }
    hexS = temp;
    return SUCCESS;
}


/* returns SUCCESS or FAILURE */
GlobalRANNodeID_t* ngapGetGlobalRANNodeId(NGAP_PDU_t *ngapPdu)
{
    GlobalRANNodeID_t *gRANNodeId = 0;
    int seq_itr = 0;
    void *seqHead = ngapGetProtocolIeListPtr(ngapPdu);
    if(seqHead == NULL) {
        return NULL;
    }

    int seqCount = ASN_SEQUENCE_GET_COUNT(seqHead);

    ProcedureCode_t procedureCode = ngapGetProcedureCode(ngapPdu);

    switch(procedureCode)
    {
        case ProcedureCode_id_NGSetup: {
            switch(ngapPdu->present) {
                case NGAP_PDU_PR_initiatingMessage: {
                    FETCH_IE_PTR(NGSetupRequestIEs, GlobalRANNodeID, gRANNodeId);
                }
                break;
                default: {
                    higLog("Invalid procedureCode %d", procedureCode);
                    return NULL;
                }
            }
        }
        break;

        default: {
            higLog("Invalid procedureCode %d", procedureCode);
            return NULL;
        }
    }
    return gRANNodeId;
}


// int asn_ulong2INTEGER(INTEGER_t *st, unsigned long value) {
//    	uint8_t *buf, *bp;
// 	uint8_t *p;
// 	uint8_t *pstart;
// 	uint8_t *pend1;
// 	int littleEndian = 1;	/* Run-time detection */
// 	int add;

// 	if(!st) {
// 		errno = EINVAL;
// 		return -1;
// 	}

// 	buf = (uint8_t *)(long *)MALLOC(sizeof(value));
// 	if(!buf) return -1;

// 	if(*(char *)&littleEndian) {
// 		pstart = (uint8_t *)&value + sizeof(value) - 1;
// 		pend1 = (uint8_t *)&value;
// 		add = -1;
// 	} else {
// 		pstart = (uint8_t *)&value;
// 		pend1 = pstart + sizeof(value) - 1;
// 		add = 1;
// 	}

// 	/*
// 	 * If the contents octet consists of more than one octet,
// 	 * then bits of the first octet and bit 8 of the second octet:
// 	 * a) shall not all be ones; and
// 	 * b) shall not all be zero.
// 	 */
// 	for(p = pstart; p != pend1; p += add) {
// 		switch(*p) {
// 		case 0x00: if((*(p+add) & 0x80) == 0)
// 				continue;
// 			break;
// 		case 0xff: if((*(p+add) & 0x80))
// 				continue;
// 			break;
// 		}
// 		break;
// 	}
// 	/* Copy the integer body */
// 	for(bp = buf, pend1 += add; p != pend1; p += add)
// 		*bp++ = *p;

// 	if(st->buf) FREEMEM(st->buf);
// 	st->buf = buf;
// 	st->size = bp - buf;

// 	return 0;
// }

// /* returns SUCCESS or FAILURE */
// SupportedTAList_t* ngapGetSupportedTAList(NGAP_PDU_t *ngapPdu)
// {
//     SupportedTAList_t *supportedTAList = 0;
//     int seq_itr = 0;
//     void *seqHead = ngapGetProtocolIeListPtr(ngapPdu);
//     if(seqHead == NULL) {
//         return NULL;
//     }

//     int seqCount = ASN_SEQUENCE_GET_COUNT(seqHead);

//     ProcedureCode_t procedureCode = ngapGetProcedureCode(ngapPdu);

//     switch(procedureCode)
//     {
//         case ProcedureCode_id_NGSetup: {
//             switch(ngapPdu->present) {
//             case NGAP_PDU_PR_initiatingMessage: {
//                 FETCH_IE_PTR(NGSetupRequestIEs, SupportedTAList,
//                                 supportedTAList);
//             }
//             break;
//             default: {
//                 higLog("Invalid procedureCode %d", procedureCode);
//                 return NULL;
//             }
//             }
//         }
//         break;

//         {
//         default:
//             higLog("Invalid procedureCode %d", procedureCode);
//             return NULL;
//         }
//     }
//     return supportedTAList;
// }

// /* returns SUCCESS or FAILURE */
// RANNodeName_t* ngapGetRANNodeName(NGAP_PDU_t *ngapPdu)
// {
//     RANNodeName_t* ranNodeName = 0;
//     int seq_itr = 0;
//     void *seqHead = ngapGetProtocolIeListPtr(ngapPdu);
//     if(seqHead == NULL) {
//         return NULL;
//     }

//     int seqCount = ASN_SEQUENCE_GET_COUNT(seqHead);

//     ProcedureCode_t procedureCode = ngapGetProcedureCode(ngapPdu);

//     switch(procedureCode)
//     {
//         case ProcedureCode_id_NGSetup: {
//             switch(ngapPdu->present) {
//             case NGAP_PDU_PR_initiatingMessage: {
//                 FETCH_IE_PTR(NGSetupRequestIEs, RANNodeName, ranNodeName);
//             }
//             break;
//             default: {
//                 higLog("Invalid procedureCode %d", procedureCode);
//                 return NULL;
//             }
//             }
//         }
//         break;

//         {
//         default:
//             higLog("Invalid procedureCode %d", procedureCode);
//             return NULL;
//         }
//     }
//     return ranNodeName;
// }

// /* returns SUCCESS or FAILURE */
// PagingDRX_t* ngapGetPagingDRX(NGAP_PDU_t *ngapPdu)
// {
//     PagingDRX_t* pagingDRX = 0;
//     int seq_itr = 0;
//     void *seqHead = ngapGetProtocolIeListPtr(ngapPdu);
//     if(seqHead == NULL) {
//         return NULL;
//     }

//     int seqCount = ASN_SEQUENCE_GET_COUNT(seqHead);

//     ProcedureCode_t procedureCode = ngapGetProcedureCode(ngapPdu);

//     switch(procedureCode)
//     {
//         case ProcedureCode_id_NGSetup: {
//             switch(ngapPdu->present) {
//             case NGAP_PDU_PR_initiatingMessage: {
//                 FETCH_IE_PTR(NGSetupRequestIEs, PagingDRX, pagingDRX);
//             }
//             break;
//             default: {
//                 higLog("Invalid procedureCode %d", procedureCode);
//                 return NULL;
//             }
//             }
//         }
//         {
//         default:
//             higLog("Invalid procedureCode %d", procedureCode);
//             return NULL;
//         }
//     }
//     return pagingDRX;
// }

// GUAMI_t* ngapGetGuami(NGAP_PDU_t* ngapPdu)
// {
//     GUAMI_t* gUAMI = 0;
//     int seq_itr = 0;
//     void *seqHead = ngapGetProtocolIeListPtr(ngapPdu);
//     if(seqHead == NULL) {
//         return NULL;
//     }
//     int seqCount = ASN_SEQUENCE_GET_COUNT(seqHead);

//     ProcedureCode_t procedureCode = ngapGetProcedureCode(ngapPdu);

//     switch(procedureCode)
//     {
//         case ProcedureCode_id_InitialContextSetup: {
//             switch(ngapPdu->present) {
//             case NGAP_PDU_PR_initiatingMessage: {
//                 FETCH_IE_PTR(InitialContextSetupRequestIEs, GUAMI, gUAMI);
//             }
//             break;
//             default: {
//                 higLog("Invalid procedureCode %d", procedureCode);
//                 return NULL;
//             }
//             }
//         }
//         break;

//         {
//         default:
//             higLog("Invalid procedureCode %d", procedureCode);
//             return NULL;
//         }
//     }
//     return gUAMI;
// }

// UESecurityCapabilities_t* ngapGetUeSecurityCapabilities(NGAP_PDU_t* ngapPdu)
// {
//     UESecurityCapabilities_t* uESecurityCapabilities = 0;
//     int seq_itr = 0;
//     void *seqHead = ngapGetProtocolIeListPtr(ngapPdu);
//     if(seqHead == NULL) {
//         return NULL;
//     }
//     int seqCount = ASN_SEQUENCE_GET_COUNT(seqHead);

//     ProcedureCode_t procedureCode = ngapGetProcedureCode(ngapPdu);

//     switch(procedureCode)
//     {
//     case ProcedureCode_id_InitialContextSetup: {
//         switch(ngapPdu->present) {
//         case NGAP_PDU_PR_initiatingMessage: {
//         FETCH_IE_PTR(InitialContextSetupRequestIEs, UESecurityCapabilities,
//                         uESecurityCapabilities);
//         }
//         break;
//         default: {
//             higLog("Invalid procedureCode %d", procedureCode);
//             return NULL;
//         }
//         }
//     }
//     break;

//     default:
//     higLog("Invalid procedureCode %d", procedureCode);
//     return NULL;
//     }

//     return uESecurityCapabilities;
// }



// PDUSessionResourceSetupListSURes_t*
// ngapGetpduSessionResourceSetupListSURes(NGAP_PDU_t *ngapPdu)
// {
//     PDUSessionResourceSetupListSURes_t* pduSessRSRList = 0;
//     int seq_itr = 0;
//     void *seqHead = ngapGetProtocolIeListPtr(ngapPdu);
//     if(seqHead == NULL) {
//         return NULL;
//     }
//     int seqCount = ASN_SEQUENCE_GET_COUNT(seqHead);

//     ProcedureCode_t procedureCode = ngapGetProcedureCode(ngapPdu);

//     switch(procedureCode)
//     {
//     case ProcedureCode_id_PDUSessionResourceSetup:
//     {
//         switch(ngapPdu->present) {
//         case NGAP_PDU_PR_successfulOutcome: {
//             FETCH_IE_PTR(PDUSessionResourceSetupResponseIEs,
//                      PDUSessionResourceSetupListSURes, pduSessRSRList);
//         }
//         break;
//         default: {
//             higLog("Invalid procedureCode %d", procedureCode);
//             return NULL;
//         }
//         }
//     }
//     break;

//     default:
//     higLog("Invalid procedureCode %d", procedureCode);
//     return NULL;
//     }
//     return pduSessRSRList;
// }

// Cause_t* ngapGetCause(NGAP_PDU_t *ngapPdu)
// {
//     Cause_t* cause = 0;
//     int seq_itr = 0;
//     void *seqHead = ngapGetProtocolIeListPtr(ngapPdu);
//     if(seqHead == NULL) {
//         return NULL;
//     }
//     int seqCount = ASN_SEQUENCE_GET_COUNT(seqHead);

//     ProcedureCode_t procedureCode = ngapGetProcedureCode(ngapPdu);

//     switch(procedureCode)
//     {
//     case ProcedureCode_id_InitialContextSetup: {
//         switch(ngapPdu->present) {
//         case NGAP_PDU_PR_unsuccessfulOutcome: {
//             FETCH_IE_PTR(InitialContextSetupFailureIEs, Cause, cause);
//         }
//         break;
//         default: {
//             higLog("Invalid procedureCode %d", procedureCode);
//             return NULL;
//         }
//         }
//     }
//     break;

//     case ProcedureCode_id_UEContextRelease: {
//         switch(ngapPdu->present) {
//         case NGAP_PDU_PR_initiatingMessage: {
//             FETCH_IE_PTR(UEContextReleaseCommand_IEs, Cause, cause);
//         }
//         break;
//         default: {
//             higLog("Invalid procedureCode %d", procedureCode);
//             return NULL;
//         }
//         }
//     }
//     break;

//     default:
//     higLog("Invalid procedureCode %d", procedureCode);
//     return NULL;
//     }
//     return cause;
// }

// UE_NGAP_IDs_t* ngapGetUeNgapIDs(NGAP_PDU_t *ngapPdu)
// {
//     UE_NGAP_IDs_t* ueNgapID = 0;
//     int seq_itr = 0;
//     void *seqHead = ngapGetProtocolIeListPtr(ngapPdu);
//     if(seqHead == NULL) {
//         return NULL;
//     }
//     int seqCount = ASN_SEQUENCE_GET_COUNT(seqHead);

//     ProcedureCode_t procedureCode = ngapGetProcedureCode(ngapPdu);

//     switch(procedureCode)
//     {
//     case ProcedureCode_id_UEContextRelease: {
//         switch(ngapPdu->present) {
//         case NGAP_PDU_PR_initiatingMessage: {
//             FETCH_IE_PTR(UEContextReleaseCommand_IEs, UE_NGAP_IDs, ueNgapID);
//         }
//         break;
//         default: {
//             higLog("Invalid procedureCode %d", procedureCode);
//             return NULL;
//         }
//         }
//     }
//     break;

//     default:
//     higLog("Invalid procedureCode %d", procedureCode);
//     return NULL;
//     }
//     return ueNgapID;
// }

// PDUSessionResourceToReleaseListRelCmd_t*
//         PDUSessResToRelListRelCmd(NGAP_PDU_t *ngapPdu)
// {
//     PDUSessionResourceToReleaseListRelCmd_t* resToRelList;
//     int seq_itr = 0;
//     void *seqHead = ngapGetProtocolIeListPtr(ngapPdu);
//     if(seqHead == NULL) {
//         return NULL;
//     }
//     int seqCount = ASN_SEQUENCE_GET_COUNT(seqHead);
//     ProcedureCode_t procedureCode = ngapGetProcedureCode(ngapPdu);

//     switch(procedureCode)
//     {
//     case ProcedureCode_id_PDUSessionResourceRelease: {
//         switch(ngapPdu->present) {
//         case NGAP_PDU_PR_initiatingMessage: {
//             FETCH_IE_PTR(PDUSessionResourceReleaseCommandIEs,
//                     PDUSessionResourceToReleaseListRelCmd, resToRelList);
//         }
//         break;
//         default: {
//             higLog("Invalid procedureCode %d", procedureCode);
//             return NULL;
//         }
//         }
//     }
//     break;

//     default:
//     higLog("Invalid procedureCode %d", procedureCode);
//     return NULL;
//     }
//     return resToRelList;
// }

// PDUSessionResourceSetupListSUReq_t*
//         ngapGetPDUSessionResourceSetupListSUReq(NGAP_PDU_t *ngapPdu)
// {
//     PDUSessionResourceSetupListSUReq_t* setupList;
//     int seq_itr = 0;
//     void *seqHead = ngapGetProtocolIeListPtr(ngapPdu);
//     if(seqHead == NULL) {
//         return NULL;
//     }
//     int seqCount = ASN_SEQUENCE_GET_COUNT(seqHead);
//     ProcedureCode_t procedureCode = ngapGetProcedureCode(ngapPdu);

//     switch(procedureCode)
//     {
//     case ProcedureCode_id_PDUSessionResourceSetup: {
//         switch(ngapPdu->present) {
//         case NGAP_PDU_PR_initiatingMessage: {
//             FETCH_IE_PTR(PDUSessionResourceSetupRequestIEs ,
//                     PDUSessionResourceSetupListSUReq, setupList);
//         }
//         break;
//         default: {
//             higLog("Invalid ngapPdu->present val %d", ngapPdu->present);
//             return NULL;
//         }
//         }
//     }
//     break;

//     default:
//     higLog("Invalid procedureCode %d", procedureCode);
//     return NULL;
//     }
//     return setupList;
// }

// int ngapGetPDUSessionResourceSetupListSURes(PDUSessionResourceSetupListSURes_t* setupList, NGAP_PDU_t *ngapPdu)
// {
//     setupList = 0;
//     int seq_itr = 0;
//     void *seqHead = ngapGetProtocolIeListPtr(ngapPdu);
//     if(seqHead == NULL) {
//         return FAILURE;
//     }
//     int seqCount = ASN_SEQUENCE_GET_COUNT(seqHead);
//     ProcedureCode_t procedureCode = ngapGetProcedureCode(ngapPdu);

//     switch(procedureCode)
//     {
//     case ProcedureCode_id_PDUSessionResourceSetup: {
//         switch(ngapPdu->present) {
//         case NGAP_PDU_PR_successfulOutcome: {
//             FETCH_IE_PTR(PDUSessionResourceSetupResponseIEs ,
//                     PDUSessionResourceSetupListSURes, setupList);
//         }
//         break;
//         default: {
//             higLog("Invalid ngapPdu->present val %d", ngapPdu->present);
//             return FAILURE;
//         }
//         }
//     }
//     break;

//     default:
//     higLog("Invalid procedureCode %d", procedureCode);
//     return FAILURE;
//     }

//     return SUCCESS;
// }


// int ngapGetPDUSessionResourceReleasedListRelRes(PDUSessionResourceReleasedListRelRes_t *setupList, NGAP_PDU_t *ngapPdu)
// {
//     setupList = 0;
//     int seq_itr = 0;
//     void *seqHead = ngapGetProtocolIeListPtr(ngapPdu);
//     if(seqHead == NULL) {
//         return FAILURE;
//     }
//     int seqCount = ASN_SEQUENCE_GET_COUNT(seqHead);
//     ProcedureCode_t procedureCode = ngapGetProcedureCode(ngapPdu);

//     switch(procedureCode)
//     {
//     case ProcedureCode_id_PDUSessionResourceRelease: {
//         switch(ngapPdu->present) {
//         case NGAP_PDU_PR_successfulOutcome: {
//             FETCH_IE_PTR(PDUSessionResourceReleaseResponseIEs ,
//                     PDUSessionResourceReleasedListRelRes, setupList);
//         }
//         break;
//         default: {
//             higLog("Invalid ngapPdu->present val %d", ngapPdu->present);
//             return FAILURE;
//         }
//         }
//     }
//     break;

//     default:
//     higLog("Invalid procedureCode %d", procedureCode);
//     return FAILURE;
//     }

//     return SUCCESS;
// }
/* Free the whole NGAP PDU struct.
 */