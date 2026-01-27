#include "linkingHeader.h"
void sbiIncoming(char *message, int len, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst){
LOG_ENTRY;
	json messageBody;
	decode_sbi_message(messageBody,message, len);

	json header;
	decode_sbi_json_header(header,message, len);

	pthread_mutex_lock(&fdToKeyMapLock);
	int amfUeNgapId = fdToKeyMap[fd];
	pthread_mutex_unlock(&fdToKeyMapLock);

	pthread_mutex_lock(&UeContextMapLock);
	state_type state = UeContextMap[amfUeNgapId].state;
	pthread_mutex_unlock(&UeContextMapLock);
	
	if (state=="nrfDiscovery") 
	{
		nrfDiscoveryResponse (messageBody, fd, client_ip, nfvInst);
	}
	if (state=="ueAuthentication") 
	{
		ueAuthenticationResponse (messageBody, fd, client_ip, nfvInst);
	}
	if (state=="ueAuthenticationUpdate") 
	{
		ueAuthenticationUpdateResponse (messageBody, fd, client_ip, nfvInst);
	}
	if (state=="uecmRegistration") 
	{
		uecmRegistrationResponse (messageBody, fd, client_ip, nfvInst);
	}
	if (state=="udmSDMGet") 
	{
		udmSDMGetResponse (messageBody, fd, client_ip, nfvInst);
	}

LOG_EXIT;
}

void sbiIncomingRequestJSON(char* header, int len, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst) {
LOG_ENTRY;
LOG_EXIT;
}

void ngapIncoming(char* message, int len, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst) {
LOG_ENTRY;
	higLog("in ngapIncoming");
	
	NGAP_PDU_t *messageBody;
	decodeNgapPdu(&messageBody,message, len);

	if (messageBody) 
	{
	failure (message, fd, client_ip, nfvInst);
	}

	int procedureCode;
	int status = ngapGetProcedureCode(procedureCode,messageBody);

	// Procedurecode extracted from NGAP registration request.
	if (procedureCode==ProcedureCode_id_UplinkNASTransport) 
	{
	handleUPLN (messageBody, fd, client_ip, nfvInst);
	}
	if (procedureCode==ProcedureCode_id_DownlinkNASTransport) 
	{
	handleDNLN (messageBody, fd, client_ip, nfvInst);
	}
	if (procedureCode==ProcedureCode_id_InitialUEMessage) 
	{
	handleINITUE (messageBody, fd, client_ip, nfvInst);
	}
	if (procedureCode==ProcedureCode_id_NGSetup) 
	{
	NGSetupRequest (messageBody, fd, client_ip, nfvInst);
	}
	if (procedureCode==ProcedureCode_id_InitialContextSetup) 
	{
	initialContextSetupResponse (messageBody, fd, client_ip, nfvInst);
	}

LOG_EXIT;
}

void failure(char* message, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst){
LOG_ENTRY;
LOG_EXIT;
}

void handleUPLN(NGAP_PDU_t* messageBody, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst){
LOG_ENTRY;
	
	NAS_PDU_t nasPDU;
	int status1 = ngapGetNasPdu(nasPDU,messageBody);

	nasMessage_t nasMsg;
	int status2 = nasMessagePlainDecode(nasMsg,nasPDU.buf,nasPDU.size);

	if (nasMsg.plain._5gmmMsg.mmheader.msgType==AUTHENTICATION_RESPONSE) 
	{
	NasAuthenticationResponse (messageBody,nasMsg, fd, client_ip, nfvInst);
	}
	if (nasMsg.plain._5gmmMsg.mmheader.msgType==IDENTITY_RESPONSE) 
	{
	identityResponse (messageBody,nasMsg, fd, client_ip, nfvInst);
	}
	if (nasMsg.plain._5gmmMsg.mmheader.msgType==SECURITY_MODE_COMPLETE) 
	{
	NasSecurityInitiationResponse (messageBody,nasMsg, fd, client_ip, nfvInst);
	}
	if (nasMsg.plain._5gmmMsg.mmheader.msgType==REGISTRATION_ACCEPT)  // final message from RAN.
	{
	registrationAcceptResponse (messageBody,nasMsg, fd, client_ip, nfvInst);
	}

LOG_EXIT;
}
void handleDNLN(NGAP_PDU_t* messageBody, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst){
LOG_ENTRY;
LOG_EXIT;
}

void handleINITUE(NGAP_PDU_t* messageBody, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst){
LOG_ENTRY;
	higLog("In handleINITUE");
	
	NAS_PDU_t nasPDU;
	int status1 = ngapGetNasPdu(nasPDU,messageBody);

	nasMessage_t nasMsg;
	int status2 = nasMessagePlainDecode(nasMsg,nasPDU.buf,nasPDU.size);

	if (nasMsg.plain._5gmmMsg.mmheader.msgType==REGISTRATION_REQUEST) 
	{
	initialRegistrationRequest (messageBody,nasMsg, fd, client_ip, nfvInst);
	}

LOG_EXIT;
}

void NGSetupRequest(NGAP_PDU_t* messageBody, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst){
LOG_ENTRY;
	higLog("In NGSetupRequest");
	
	GlobalRANNodeID_t gNId;
	int status = getGlobalRANId(gNId,messageBody);

	
	int gNId_num;
	int status1 = BitStringToNum(gNId_num,gNId.choice.globalGNB_ID->gNB_ID.choice.gNB_ID);

	pthread_mutex_lock(&keyToFdMapLock);
	keyToFdMap[gNId_num] = fd;
	struct sockaddr_in addr = {};
	memcpy (&addr, client_ip, sizeof(client_ip));
	keyToIpFdMap[gNId_num] = make_pair(addr, fd);
	pthread_mutex_unlock(&keyToFdMapLock);
	asnLog(&asn_DEF_NGAP_PDU, messageBody);

	NGSetupResponse (messageBody, fd, client_ip, nfvInst);

LOG_EXIT;
}

void NGSetupResponse(NGAP_PDU_t* messageBody, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst){
LOG_ENTRY;
	NGAP_PDU_t ngapPdu_m = {};
	
	SuccessfulOutcome_t succ_m = {};
	
	NGSetupResponse_t ngsr_m = {};

	ngapPdu_m.present = NGAP_PDU_PR_successfulOutcome;
	
	ngapPdu_m.choice.successfulOutcome= &succ_m;

	succ_m.procedureCode = ProcedureCode_id_NGSetup;
	succ_m.criticality = Criticality_reject;
	succ_m.value.present = SuccessfulOutcome__value_PR_NGSetupResponse;
	
	NGSetupResponseIEs_t amfName = {};
	amfName.id = ProtocolIE_ID_id_AMFName;
	amfName.criticality = Criticality_reject;
	amfName.value.present = NGSetupResponseIEs__value_PR_AMFName;
	
	ifstream ifs("amfconfig.json");
	Json::Reader reader;
	Json::Value amfConfig= {};
	reader.parse(ifs,amfConfig);
	OCTET_STRING_t amf_config_amfname = toOctetString(amfConfig["AMFName"].asString().c_str());
	amfName.value.choice.AMFName = amf_config_amfname;
	
	//OCTET_STRING_fromBuf(&amfName.value.choice.AMFName,amfConfig["AMFName"].asString().c_str(),strlen(amfConfig["AMFName"].asString().c_str()));

	ASN_SEQUENCE_ADD(&ngsr_m.protocolIEs.list, &amfName);
		
	NGSetupResponseIEs_t sGuami_m = {};
	
	ServedGUAMIList_t sGuamiIE = {};

	sGuami_m.id = ProtocolIE_ID_id_ServedGUAMIList;
	sGuami_m.criticality = Criticality_reject;
	sGuami_m.value.present = NGSetupResponseIEs__value_PR_ServedGUAMIList;
	
	ServedGUAMIItem_t sGuamiItem = {};
	sGuamiItem.gUAMI = generateGuami();

	ASN_SEQUENCE_ADD(&sGuamiIE.list, &sGuamiItem);

	sGuami_m.value.choice.ServedGUAMIList = sGuamiIE;

	ASN_SEQUENCE_ADD(&ngsr_m.protocolIEs.list, &sGuami_m);
	
	NGSetupResponseIEs_t relAmfCap = {};

	relAmfCap.id = ProtocolIE_ID_id_RelativeAMFCapacity;
	relAmfCap.criticality = Criticality_ignore;
	relAmfCap.value.present = NGSetupResponseIEs__value_PR_RelativeAMFCapacity;
	relAmfCap.value.choice.RelativeAMFCapacity = amfConfig["relativeAMFcapacity"].asInt();
	
	ASN_SEQUENCE_ADD(&ngsr_m.protocolIEs.list, &relAmfCap);
	
	NGSetupResponseIEs_t pLMNSList = {};

	pLMNSList.id = ProtocolIE_ID_id_PLMNSupportList;
	pLMNSList.criticality = Criticality_reject;
	pLMNSList.value.present = NGSetupResponseIEs__value_PR_PLMNSupportList;
	
	PLMNSupportList_t pLMNIEs = {};
	
	PLMNSupportItem_t pLMNSItem = {};
	
	char plmnBUF[3] = {};
	
	OCTET_STRING_t oct_str_plmnBuf = toOctetString(plmnBUF, 3);
	//OCTET_STRING_fromBuf(&pLMNSItem.pLMNIdentity,plmnBUF,3);
	pLMNSItem.pLMNIdentity = oct_str_plmnBuf;
	lowLog("pLMNSItem updated with %s\n", (char *)pLMNSItem.pLMNIdentity.buf);
	

	SliceSupportList_t sSuppList = {};
	
	SliceSupportItem_t sSuppItem[2] = {};
	
	for (int itr=0;itr<2;itr++) 
	{
		S_NSSAI_t snssai = {};
	
		char sst[1] = {};

		sst[0] = amfConfig["amf-s-nssai-list"]["amf-nssai"][itr]["snssai"]["sst"].asInt();

		OCTET_STRING_t oct_str_sst = toOctetString(sst, 1);
		snssai.sST = oct_str_sst;
		lowLog("snssai.sst updated with %s\n", (char *)snssai.sST.buf);
		//int stat1 = OCTET_STRING_fromBuf(&snssai.sST,sst,1);

		sSuppItem[itr].s_NSSAI = snssai;

		ASN_SEQUENCE_ADD(&sSuppList.list, &sSuppItem[itr]);
	}

	pLMNSItem.sliceSupportList = sSuppList;

	ASN_SEQUENCE_ADD(&pLMNIEs.list, &pLMNSItem);

	pLMNSList.value.choice.PLMNSupportList = pLMNIEs;

	ASN_SEQUENCE_ADD(&ngsr_m.protocolIEs.list, &pLMNSList);
	
	NGSetupResponseIEs_t critDiag_m = {};

	critDiag_m.id = ProtocolIE_ID_id_CriticalityDiagnostics;
	critDiag_m.criticality = Criticality_ignore;
	critDiag_m.value.present = NGSetupResponseIEs__value_PR_CriticalityDiagnostics;
	
	ASN_SEQUENCE_ADD(&ngsr_m.protocolIEs.list, &critDiag_m);
	
	succ_m.value.choice.NGSetupResponse = ngsr_m;
	
	GlobalRANNodeID_t gNId;
	int status = getGlobalRANId(gNId,messageBody);

	int gNId_num;
	int status1 = BitStringToNum(gNId_num,gNId.choice.globalGNB_ID->gNB_ID.choice.gNB_ID);
	asnLog(&asn_DEF_NGAP_PDU, messageBody);
	size_t ngapPdu_m_enc_sz = BUF_SIZE;
	char ngapPdu_m_enc[ngapPdu_m_enc_sz] = {}; // on stack, only reqd till msg sent.
	
	asnLog(&asn_DEF_NGAP_PDU, &ngapPdu_m);
	encodeNgap(ngapPdu_m_enc, &ngapPdu_m, ngapPdu_m_enc_sz); // buff size

	
	pthread_mutex_lock (&keyToFdMapLock);
	int fd1 = keyToFdMap[gNId_num];
	pair<struct sockaddr_in, int> ipFdPair = keyToIpFdMap[gNId_num];
	pthread_mutex_unlock (&keyToFdMapLock);
    sendData("127.0.0.1", 38413, ngapPdu_m_enc, false, SCTP_PROTOCOL, RAN, ngapPdu_m_enc_sz, fd1, NULL, &ipFdPair.first, nfvInst);

LOG_EXIT;
}

void initialRegistrationRequest(NGAP_PDU_t* messageBody,nasMessage_t nasMsg, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst){
LOG_ENTRY;
	higLog("In initialRegistrationRrequest");
	
	RAN_UE_NGAP_ID_t ranUeNgapId;
	int status1 = ngapGetRanUeNgapId(ranUeNgapId,messageBody);

	pthread_mutex_lock(&UeContextMapTempLock);
	UeContextMapTemp[ranUeNgapId]._5gregType= nasMsg.plain._5gmmMsg.regReqMsg._5gregType;
	UeContextMapTemp[ranUeNgapId].ngKsi= nasMsg.plain._5gmmMsg.regReqMsg.ngKsi;
	pthread_mutex_unlock(&UeContextMapTempLock);

	nssai_t requestedNSSAI = {};

	requestedNSSAI.no_of_slices = nasMsg.plain._5gmmMsg.regReqMsg.requestedNssai.no_of_slices;

	for (int itr=0;itr<nasMsg.plain._5gmmMsg.regReqMsg.requestedNssai.no_of_slices;itr++) 
	{
		if (nasMsg.plain._5gmmMsg.regReqMsg.requestedNssai.Nssai[itr].len_s_nssai==LEN_ONLY_SST) 
		{
			requestedNSSAI.Nssai[itr].len_s_nssai = nasMsg.plain._5gmmMsg.regReqMsg.requestedNssai.Nssai[itr].len_s_nssai;
			requestedNSSAI.Nssai[itr].sST = nasMsg.plain._5gmmMsg.regReqMsg.requestedNssai.Nssai[itr].sST;
		}
		if (nasMsg.plain._5gmmMsg.regReqMsg.requestedNssai.Nssai[itr].len_s_nssai==LEN_SST_AND_SD) 
		{
			requestedNSSAI.Nssai[itr].len_s_nssai = nasMsg.plain._5gmmMsg.regReqMsg.requestedNssai.Nssai[itr].len_s_nssai;
			requestedNSSAI.Nssai[itr].sST = nasMsg.plain._5gmmMsg.regReqMsg.requestedNssai.Nssai[itr].sST;
			requestedNSSAI.Nssai[itr].sD = nasMsg.plain._5gmmMsg.regReqMsg.requestedNssai.Nssai[itr].sD;
		}
	}

	pthread_mutex_lock(&UeContextMapTempLock);
	UeContextMapTemp[ranUeNgapId].requestedNssai= requestedNSSAI;
	pthread_mutex_unlock(&UeContextMapTempLock);

	suci_t suci_;
	int status2 = retrieveMobileIdentity(suci_,&nasMsg.plain._5gmmMsg.regReqMsg);

	if (status2==FAILURE) 
	{
		higLog("Retrieve mobile identity failure.");
		identityRequest (messageBody,nasMsg, fd, client_ip, nfvInst);
	}
	else 
	{
		string SUCI;
		int status3 = suciSchemeToImsi(SUCI,suci_);

	
		AmfUeNgapId_t amfUeNgapId;
		int status4 = generateAmfUeNgapId(amfUeNgapId);

		pthread_mutex_lock(&UeContextMapLock);
		UeContextMap[amfUeNgapId].ranUeNgapId= ranUeNgapId;
		UeContextMap[amfUeNgapId].suci= SUCI;
		pthread_mutex_unlock(&UeContextMapLock);
		
		pthread_mutex_lock(&SuciAmfUeNgapIdMapLock);
		SuciAmfUeNgapIdMap[SUCI].amfUeNgapId= amfUeNgapId;
		pthread_mutex_unlock(&SuciAmfUeNgapIdMapLock);
	
		pthread_mutex_lock(&UeContextMapLock);
		UeContextMap[amfUeNgapId]._5gregType= nasMsg.plain._5gmmMsg.regReqMsg._5gregType;
		UeContextMap[amfUeNgapId].ngKsi= nasMsg.plain._5gmmMsg.regReqMsg.ngKsi;
		UeContextMap[amfUeNgapId].requestedNssai= requestedNSSAI;
		UeContextMap[amfUeNgapId].ueSecurityCapability= nasMsg.plain._5gmmMsg.regReqMsg.ueSecuCapability;
		pthread_mutex_unlock(&UeContextMapLock);
		
		pthread_mutex_lock(&keyToFdMapLock);
		keyToFdMap[amfUeNgapId] = fd; // important. fd is the datafd in platform that recd the message. key is the UE identity. thus datafd is linked to UE.
		struct sockaddr_in addr = {};
		memcpy (&addr, client_ip, sizeof(client_ip));
		keyToIpFdMap[amfUeNgapId] = make_pair(addr, fd);
		pthread_mutex_unlock(&keyToFdMapLock);

		higLog("amfuengapid: %d\n",amfUeNgapId);
		AUSFSelection (amfUeNgapId, fd, client_ip, nfvInst);
	}

LOG_EXIT;
}

void identityRequest(NGAP_PDU_t* messageBody,nasMessage_t nasMsg, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst){
LOG_ENTRY;
LOG_EXIT;
}

void identityResponse(NGAP_PDU_t* messageBody,nasMessage_t nasMsg, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst){
LOG_ENTRY;
	RAN_UE_NGAP_ID_t ranUeNgapId;
	int status1 = ngapGetRanUeNgapId(ranUeNgapId,messageBody);

	suci_t suci_;
	int status2 = retrieveMobileIdentity(suci_,&nasMsg.plain._5gmmMsg.regReqMsg);

	string SUCI;
	int status3 = suciToString(SUCI,suci_);

	AmfUeNgapId_t amfUeNgapId;
	int status4 = generateAmfUeNgapId(amfUeNgapId);

	pthread_mutex_lock(&UeContextMapTempLock);
	UeContextMapTemp[ranUeNgapId].suci= SUCI;
	pthread_mutex_unlock(&UeContextMapTempLock);

	pthread_mutex_lock(&SuciAmfUeNgapIdMapLock);
	SuciAmfUeNgapIdMap[SUCI].amfUeNgapId= amfUeNgapId;
	pthread_mutex_unlock(&SuciAmfUeNgapIdMapLock);

	pthread_mutex_lock(&UeContextMapTempLock);
	_5gRegistrationType_t regType = UeContextMapTemp[ranUeNgapId]._5gregType;
	pthread_mutex_unlock(&UeContextMapTempLock);

	pthread_mutex_lock(&UeContextMapLock);
	UeContextMap[amfUeNgapId]._5gregType= regType;
	pthread_mutex_unlock(&UeContextMapLock);

	pthread_mutex_lock(&UeContextMapTempLock);
	NaskeysetId_t ngKsi_ = UeContextMapTemp[ranUeNgapId].ngKsi;
	pthread_mutex_unlock(&UeContextMapTempLock);

	pthread_mutex_lock(&UeContextMapLock);
	UeContextMap[amfUeNgapId].ngKsi= ngKsi_;
	pthread_mutex_unlock(&UeContextMapLock);

	pthread_mutex_lock(&UeContextMapTempLock);
	nssai_t _requestedNssai = UeContextMapTemp[ranUeNgapId].requestedNssai;
	pthread_mutex_unlock(&UeContextMapTempLock);

	pthread_mutex_lock(&UeContextMapLock);
	UeContextMap[amfUeNgapId].requestedNssai= _requestedNssai;
	pthread_mutex_unlock(&UeContextMapLock);

	AUSFSelection (amfUeNgapId, fd, client_ip, nfvInst);

LOG_EXIT;
}

void nrfDiscoveryResponse(json messageBody, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst){
LOG_ENTRY;
	pthread_mutex_lock(&fdToKeyMapLock);
	int amfUeNgapId = fdToKeyMap[fd];
	pthread_mutex_unlock(&fdToKeyMapLock);
    

	if (messageBody["nfInstances"][0]["nfType"].get<string>()=="AUSF") 
	{
		pthread_mutex_lock(&globalContextMapLock);
		globalContextMap["structEntry"].ausf_ip= messageBody["nfInstances"][0]["ipv4addresses"][0];
		pthread_mutex_unlock(&globalContextMapLock);
		
		ueAuthentication (amfUeNgapId, fd, client_ip, nfvInst);
	}

	if (messageBody["nfInstances"][0]["nfType"].get<string>()=="UDM") 
	{
		pthread_mutex_lock(&globalContextMapLock);
		globalContextMap["structEntry"].udm_ip= messageBody["nfInstances"][0]["ipv4addresses"][0];
		pthread_mutex_unlock(&globalContextMapLock);
		
		uecmRegistration (amfUeNgapId, fd, client_ip, nfvInst);
	}

LOG_EXIT;
}

void AUSFSelection(AmfUeNgapId_t amfUeNgapId, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst){
LOG_ENTRY;
	higLog("In AUSFSELECTION.");
	pthread_mutex_lock(&globalContextMapLock);
	string ausf_ip = globalContextMap["structEntry"].ausf_ip;
	pthread_mutex_unlock(&globalContextMapLock);
	
	if (ausf_ip=="") 
	{
		HttpRequest nnrf_disc = {};
		nnrf_disc.options.insert({"Host", "127.0.0.1"});
		nnrf_disc.options.insert({"User-Agent","cpprestsdk/2.10.15"});
		nnrf_disc.options.insert({"Connection","Keep-Alive"});

		nnrf_disc.method = GET;
		nnrf_disc.version = HTTP_2_0;
		nnrf_disc.uri = "/nnrf-disc/v1/nf-instances";
		nnrf_disc.queryParams["target-nf-type"] = "AUSF";
		nnrf_disc.queryParams["requester-nf-type"] = "AMF";
		nnrf_disc.queryParams["service-names"] = "nausf-auth";

		pthread_mutex_lock(&UeContextMapLock);
		UeContextMap[amfUeNgapId].state= "nrfDiscovery";
		pthread_mutex_unlock(&UeContextMapLock);

		size_t nnrf_disc_enc_sz = BUF_SIZE;
		string nnrf_disc_enc;
		encodeHTTP(nnrf_disc_enc, nnrf_disc, nnrf_disc_enc_sz);

		sendData("127.0.0.1", 6666, (char *)nnrf_disc_enc.c_str(), true, TCP_PROTOCOL, NRF, nnrf_disc_enc_sz, amfUeNgapId, sbiIncoming,NULL, nfvInst);

		// START_TIMER(name, timeoutsec, EVENT_callback)
		// STOP_TIMER(name)
		// UEContextMap will also store epollfd thats handling this timerfd
		// or single epollfd per UE. each UE can thus react to multiple timer instances.
	}
	else 
	{
		ueAuthentication (amfUeNgapId, fd, client_ip, nfvInst);
	}

LOG_EXIT;
}

void ueAuthentication(AmfUeNgapId_t amfUeNgapId, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst){
LOG_ENTRY;
	
	HttpRequest nausf_auth_ueAuth = {};
	nausf_auth_ueAuth.options.insert({"Host", "127.0.0.1"});
	nausf_auth_ueAuth.options.insert({"User-Agent","cpprestsdk/2.10.15"});
	nausf_auth_ueAuth.options.insert({"Connection","Keep-Alive"});

	nausf_auth_ueAuth.method = POST;
	nausf_auth_ueAuth.version = HTTP_2_0;
	nausf_auth_ueAuth.uri = "/nausf-auth/v1/ue-authentications";
	
	ifstream ifs("amfconfig.json");
	Json::Reader reader;
	Json::Value amfConfig= {};
	reader.parse(ifs,amfConfig);

	nausf_auth_ueAuth.body["amfInstanceId"] = amfConfig["amf-id"].asString().c_str();
	nausf_auth_ueAuth.body["servingNetworkName"] = getSnName();
	
	pthread_mutex_lock(&UeContextMapLock);
	string suciTemp = UeContextMap[amfUeNgapId].suci;
	pthread_mutex_unlock(&UeContextMapLock);

	nausf_auth_ueAuth.body["supiOrSuci"] = suciTemp;

	pthread_mutex_lock(&UeContextMapLock);
	UeContextMap[amfUeNgapId].state= "ueAuthentication";
	pthread_mutex_unlock(&UeContextMapLock);

	pthread_mutex_lock(&globalContextMapLock);
	string ausf_ip = globalContextMap["structEntry"].ausf_ip;
	pthread_mutex_unlock(&globalContextMapLock);

	size_t nausf_auth_ueAuth_enc_sz = BUF_SIZE;
	string nausf_auth_ueAuth_enc;
	encodeHTTP(nausf_auth_ueAuth_enc, nausf_auth_ueAuth, nausf_auth_ueAuth_enc_sz);

	// nausf_auth_ueAuth.options.insert({"Content-Type", "application/json"});
	// nausf_auth_ueAuth.SetContentLength();
	// string nausf_auth_ueAuth_enc = nausf_auth_ueAuth.message_to_string();
	//sendData(ausf_ip, 65533, (char *)nausf_auth_ueAuth_enc.c_str(), true, TCP_PROTOCOL, AUSF, strlen((char *)nausf_auth_ueAuth_enc.c_str()), amfUeNgapId, sbiIncoming, &ipFdPair.first, nfvInst);
	sendData(ausf_ip, 2222, (char *)nausf_auth_ueAuth_enc.c_str(), true, TCP_PROTOCOL, AUSF, nausf_auth_ueAuth_enc_sz, amfUeNgapId, sbiIncoming, NULL, nfvInst);
	
LOG_EXIT;
}

void ueAuthenticationResponse(json messageBody, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst){
LOG_ENTRY;
	pthread_mutex_lock(&fdToKeyMapLock);
	int amfUeNgapId = fdToKeyMap[fd];
	pthread_mutex_unlock(&fdToKeyMapLock);

	if (messageBody["authType"].get<string>()=="5G_AKA") 
	{
		pthread_mutex_lock(&UeContextMapLock);
		UeContextMap[amfUeNgapId].RAND= messageBody["5gAuthData"]["rand"];
		UeContextMap[amfUeNgapId].hxresStar= messageBody["5gAuthData"]["hxresStar"];
		UeContextMap[amfUeNgapId].kSeaf= messageBody["5gAuthData"]["kSeaf"];
		UeContextMap[amfUeNgapId].autn= messageBody["5gAuthData"]["autn"];
		pthread_mutex_unlock(&UeContextMapLock);
	}
	else 
	{
		;
	}
	pthread_mutex_lock(&UeContextMapLock);
	UeContextMap[amfUeNgapId].authCtxId= messageBody["_links"][0];
	pthread_mutex_unlock(&UeContextMapLock);
	
	NasAuthentication (amfUeNgapId, fd, client_ip, nfvInst);
LOG_EXIT;
}

void NasAuthentication(int amfUeNgapId, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst){
LOG_ENTRY;
	
	nasMessage_t nas_m = {};
	
	AuthenticationRequestMsg_t authReq_m = {};
	
	authReq_m.mmHeader.epd = _5GS_MOBILITY_MANAGEMENT_MESSAGE;
	authReq_m.mmHeader.secuHeader = SECURITY_HEADER_TYPE_NOT_PROTECTED;
	authReq_m.mmHeader.msgType = AUTHENTICATION_REQUEST;
	
	secContext_t secCtxt = {};

	pthread_mutex_lock(&UeContextMapLock);
	NaskeysetId_t ngKSI = UeContextMap[amfUeNgapId].ngKsi;
	pthread_mutex_unlock(&UeContextMapLock);
	
	authReq_m.ngKsi = ngKSI;
	authReq_m.abba.len = ABBA_LEN_MIN;
	
	// in SET: if RHS is arr, memcpy.
	uint8_t contents[ABBA_CONTENTS_MAX_SIZE] = {};
	memcpy(authReq_m.abba.contents,contents, sizeof(contents));

	authReq_m.presenceMask = 0;
	authReq_m.presenceMask = authReq_m.presenceMask|NAS_AUTH_REQUEST_OPT_RAND_PRESENT;

	pthread_mutex_lock(&UeContextMapLock);
	string rand = UeContextMap[amfUeNgapId].RAND;
	pthread_mutex_unlock(&UeContextMapLock);

	int status1 = hexCopyFromStrings(authReq_m.rand.RAND,RAND_SIZE,rand);

	authReq_m.presenceMask = authReq_m.presenceMask|NAS_AUTH_REQUEST_OPT_AUTN_PRESENT;
	authReq_m.autn.len = 16;

	pthread_mutex_lock(&UeContextMapLock);
	string autn = UeContextMap[amfUeNgapId].autn;
	pthread_mutex_unlock(&UeContextMapLock);

	int status2 = hexCopyFromStrings(authReq_m.autn.AUTN,AUTN_SIZE,autn);

	nas_m.plain._5gmmMsg.authReqMsg = authReq_m;
	
	NGAP_PDU_t ngapPdu_m = {};
	
	InitiatingMessage_t iniMsg_m = {};
	
	DownlinkNASTransport_t dln_m = {};

	ngapPdu_m.present = NGAP_PDU_PR_initiatingMessage;
	ngapPdu_m.choice.initiatingMessage= &iniMsg_m;

	iniMsg_m.procedureCode = ProcedureCode_id_DownlinkNASTransport;
	iniMsg_m.criticality = Criticality_ignore;
	iniMsg_m.value.present = InitiatingMessage__value_PR_DownlinkNASTransport;
	
	DownlinkNASTransport_IEs_t amfid = {};

	amfid.id = ProtocolIE_ID_id_AMF_UE_NGAP_ID;
	amfid.criticality = Criticality_reject;
	amfid.value.present = DownlinkNASTransport_IEs__value_PR_AMF_UE_NGAP_ID;
	
	int status3 = asn_ulong2INTEGER(&amfid.value.choice.AMF_UE_NGAP_ID,amfUeNgapId);

	ASN_SEQUENCE_ADD(&dln_m.protocolIEs.list, &amfid);
	
	DownlinkNASTransport_IEs_t ranid = {};

	ranid.id = ProtocolIE_ID_id_RAN_UE_NGAP_ID;
	ranid.criticality = Criticality_reject;
	ranid.value.present = DownlinkNASTransport_IEs__value_PR_RAN_UE_NGAP_ID;

	pthread_mutex_lock(&UeContextMapLock);
	RAN_UE_NGAP_ID_t ranUeId = UeContextMap[amfUeNgapId].ranUeNgapId;
	pthread_mutex_unlock(&UeContextMapLock);
	
	ranid.value.choice.RAN_UE_NGAP_ID = ranUeId;
	
	ASN_SEQUENCE_ADD(&dln_m.protocolIEs.list, &ranid);
	
	DownlinkNASTransport_IEs_t amfName = {};

	amfName.id = ProtocolIE_ID_id_OldAMF;
	amfName.criticality = Criticality_reject;
	amfName.value.present = DownlinkNASTransport_IEs__value_PR_AMFName;
	
	ifstream ifs("amfconfig.json");
	Json::Reader reader;
	Json::Value amfConfig= {};
	reader.parse(ifs,amfConfig);
	
	// UDF
	OCTET_STRING_t amf_config_amfname = toOctetString(amfConfig["AMFName"].asString().c_str());
	
	amfName.value.choice.AMFName = amf_config_amfname;

	ASN_SEQUENCE_ADD(&dln_m.protocolIEs.list, &amfName);
	
	DownlinkNASTransport_IEs_t naspdu = {};
	naspdu.id = ProtocolIE_ID_id_NAS_PDU;
	naspdu.criticality = Criticality_reject;
	naspdu.value.present = DownlinkNASTransport_IEs__value_PR_NAS_PDU;

    //UDF + SET. octet_s_f_b goes into a nasmessgaetooctetstring udf
	OCTET_STRING_t nas_octet_string = nasMessagetoOctetString(&nas_m, &secCtxt);
	
	naspdu.value.choice.NAS_PDU = nas_octet_string;

	ASN_SEQUENCE_ADD(&dln_m.protocolIEs.list, &naspdu);

	iniMsg_m.value.choice.DownlinkNASTransport = dln_m;

	//ENCODE(encodeNgap, ngapPdu_m_enc, ngapPdu_m, ngapPdu_m_enc_sz)s
	size_t ngapPdu_m_enc_sz = BUF_SIZE;
	char ngapPdu_m_enc[ngapPdu_m_enc_sz] = {}; // on stack, only reqd till msg sent.
	encodeNgap(ngapPdu_m_enc, &ngapPdu_m, ngapPdu_m_enc_sz); // buff size

	pthread_mutex_lock (&keyToFdMapLock);
	int fd1 = keyToFdMap[amfUeNgapId];
	pair<struct sockaddr_in, int> ipFdPair = keyToIpFdMap[amfUeNgapId];
	pthread_mutex_unlock (&keyToFdMapLock);

	sendData("127.0.0.1", 38413, ngapPdu_m_enc, false, SCTP_PROTOCOL, RAN, ngapPdu_m_enc_sz, fd1, NULL, &ipFdPair.first, nfvInst);

LOG_EXIT;
}

void NasAuthenticationResponse(NGAP_PDU_t* messageBody,nasMessage_t nasMsg, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst){
LOG_ENTRY;
	
	AMF_UE_NGAP_ID_t _amfUeNgapId;
	int status = ngapGetAmfUeNgapId(_amfUeNgapId,messageBody);

	
	AmfUeNgapId_t amfUeNgapId;
	int status1 = asn_INTEGER2ulong(&amfUeNgapId,&_amfUeNgapId);

	pthread_mutex_lock(&UeContextMapLock);
	UeContextMap[amfUeNgapId].resStar = (uint8_t *)malloc(sizeof(nasMsg.plain._5gmmMsg.authRespMsg.authRespParam.RESstar));
	memcpy(UeContextMap[amfUeNgapId].resStar, nasMsg.plain._5gmmMsg.authRespMsg.authRespParam.RESstar, sizeof(nasMsg.plain._5gmmMsg.authRespMsg.authRespParam.RESstar)/sizeof(uint8_t));
	pthread_mutex_unlock(&UeContextMapLock);
	
	ueAuthenticationUpdate (amfUeNgapId, fd, client_ip, nfvInst);
LOG_EXIT;
}

void ueAuthenticationUpdate(AmfUeNgapId_t amfUeNgapId, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst){
LOG_ENTRY;
	
	HttpRequest nausf_auth_ueAuth = {};
	nausf_auth_ueAuth.options.insert({"Host", "127.0.0.1"});
	nausf_auth_ueAuth.options.insert({"User-Agent","cpprestsdk/2.10.15"});
	nausf_auth_ueAuth.options.insert({"Connection","Keep-Alive"});
	
	nausf_auth_ueAuth.method = PUT;
	nausf_auth_ueAuth.version = HTTP_2_0;
	pthread_mutex_lock(&UeContextMapLock);
	string cntxId = UeContextMap[amfUeNgapId].authCtxId;
	pthread_mutex_unlock(&UeContextMapLock);
	
	nausf_auth_ueAuth.uri = "/nausf-auth/v1/ue-authentications/"+cntxId+"/5g-aka-confirmation";

	pthread_mutex_lock(&UeContextMapLock);
	string suciTemp = UeContextMap[amfUeNgapId].suci;
	pthread_mutex_unlock(&UeContextMapLock);
	
	nausf_auth_ueAuth.body["supiOrSuci"] = suciTemp;

	pthread_mutex_lock(&UeContextMapLock);
	uint8_t* resStar = UeContextMap[amfUeNgapId].resStar;
	pthread_mutex_unlock(&UeContextMapLock);

	std::string hexS;
	int status1 = hexCopyToStrings(hexS,resStar,16);

	nausf_auth_ueAuth.body["resStar"] = hexS;

	pthread_mutex_lock(&UeContextMapLock);
	UeContextMap[amfUeNgapId].state= "ueAuthenticationUpdate";
	pthread_mutex_unlock(&UeContextMapLock);

	pthread_mutex_lock(&globalContextMapLock);
	string ausf_ip = globalContextMap["structEntry"].ausf_ip;
	pthread_mutex_unlock(&globalContextMapLock);

	size_t nausf_auth_ueAuth_sz = BUF_SIZE;
	string nausf_auth_ueAuth_enc;
	encodeHTTP(nausf_auth_ueAuth_enc, nausf_auth_ueAuth, nausf_auth_ueAuth_sz);

	sendData(ausf_ip, 2222, (char *)nausf_auth_ueAuth_enc.c_str(), true, TCP_PROTOCOL, AUSF, nausf_auth_ueAuth_sz, amfUeNgapId, sbiIncoming, NULL, nfvInst);

LOG_EXIT;
}

void ueAuthenticationUpdateResponse(json messageBody, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst){
LOG_ENTRY;
	pthread_mutex_lock(&fdToKeyMapLock);
	int amfUeNgapId = fdToKeyMap[fd];
	pthread_mutex_unlock(&fdToKeyMapLock);

	pthread_mutex_lock(&UeContextMapLock);
	UeContextMap[amfUeNgapId].supi= messageBody["supi"];
	pthread_mutex_unlock(&UeContextMapLock);
	
	pthread_mutex_lock(&SupiAmfUeNgapIdMapLock);
	SupiAmfUeNgapIdMap[messageBody["supi"]].amfUeNgapId= amfUeNgapId;
	pthread_mutex_unlock(&SupiAmfUeNgapIdMapLock);
	
	NasSecurityModeCommand (amfUeNgapId, fd, client_ip, nfvInst);
LOG_EXIT;
}
 
void NasSecurityModeCommand(int amfUeNgapId, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst){
LOG_ENTRY;
	
	nasMessage_t nas_m = {};
	
	SecurityModeCommand_t secMC_m = {};

	secMC_m.mmHeader.epd = _5GS_MOBILITY_MANAGEMENT_MESSAGE;
	secMC_m.mmHeader.secuHeader = SECURITY_HEADER_TYPE_NOT_PROTECTED;
	secMC_m.mmHeader.msgType = SECURITY_MODE_COMMAND;
	
	secContext_t secCtxt = {};

	secMC_m.nasSecurityAlgorithm.encryptionAlgo = secCtxt.secAlgo.nasEncAlgo;
	secMC_m.nasSecurityAlgorithm.integrityAlgo = secCtxt.secAlgo.nasIntAlgo;
	secMC_m.ueSecuCapability.len = UE_SECURITY_CAPABILITY_NAS_AS_LEN;

	pthread_mutex_lock(&UeContextMapLock);
	UeSecurityCapability_t ueSecurityCapability = UeContextMap[amfUeNgapId].ueSecurityCapability;
	pthread_mutex_unlock(&UeContextMapLock);
	
	secMC_m.ueSecuCapability._5gNASIntAlgo = ueSecurityCapability._5gNASIntAlgo;
	secMC_m.ueSecuCapability._5gNASEncAlgo = ueSecurityCapability._5gNASEncAlgo;

	pthread_mutex_lock(&UeContextMapLock);
	NaskeysetId_t ngKSI = UeContextMap[amfUeNgapId].ngKsi;
	pthread_mutex_unlock(&UeContextMapLock);secMC_m.ngKsi = ngKSI;

	nas_m.plain._5gmmMsg.secModeCmdMsg = secMC_m;
	
	NGAP_PDU_t ngapPdu_m = {};
	
	InitiatingMessage_t iniMsg_m = {};
	
	DownlinkNASTransport_t dln_m = {};

	ngapPdu_m.present = NGAP_PDU_PR_initiatingMessage;
	ngapPdu_m.choice.initiatingMessage= &iniMsg_m;

	iniMsg_m.procedureCode = ProcedureCode_id_DownlinkNASTransport;
	iniMsg_m.criticality = Criticality_ignore;
	iniMsg_m.value.present = InitiatingMessage__value_PR_DownlinkNASTransport;
	
	DownlinkNASTransport_IEs_t amfid = {};

	amfid.id = ProtocolIE_ID_id_AMF_UE_NGAP_ID;
	amfid.criticality = Criticality_reject;
	amfid.value.present = DownlinkNASTransport_IEs__value_PR_AMF_UE_NGAP_ID;
	
	int status3 = asn_ulong2INTEGER(&amfid.value.choice.AMF_UE_NGAP_ID,amfUeNgapId);

	ASN_SEQUENCE_ADD(&dln_m.protocolIEs.list, &amfid);
	
	DownlinkNASTransport_IEs_t ranid = {};

	ranid.id = ProtocolIE_ID_id_RAN_UE_NGAP_ID;
	ranid.criticality = Criticality_reject;
	ranid.value.present = DownlinkNASTransport_IEs__value_PR_RAN_UE_NGAP_ID;

	pthread_mutex_lock(&UeContextMapLock);
	RAN_UE_NGAP_ID_t ranUeId = UeContextMap[amfUeNgapId].ranUeNgapId;
	pthread_mutex_unlock(&UeContextMapLock);ranid.value.choice.RAN_UE_NGAP_ID = ranUeId;

	ASN_SEQUENCE_ADD(&dln_m.protocolIEs.list, &ranid);
	
	DownlinkNASTransport_IEs_t amfName = {};

	amfName.id = ProtocolIE_ID_id_OldAMF;
	amfName.criticality = Criticality_reject;
	amfName.value.present = DownlinkNASTransport_IEs__value_PR_AMFName;
	
	ifstream ifs("amfconfig.json");
	Json::Reader reader;
	Json::Value amfConfig= {};
	reader.parse(ifs,amfConfig);

	OCTET_STRING_t amf_config_amfname = toOctetString(amfConfig["AMFName"].asString().c_str());
	
	amfName.value.choice.AMFName = amf_config_amfname;

	ASN_SEQUENCE_ADD(&dln_m.protocolIEs.list, &amfName);
	
	DownlinkNASTransport_IEs_t naspdu = {};
	naspdu.id = ProtocolIE_ID_id_NAS_PDU;
	naspdu.criticality = Criticality_reject;
	naspdu.value.present = DownlinkNASTransport_IEs__value_PR_NAS_PDU;

	OCTET_STRING_t nas_octet_string = nasMessagetoOctetString(&nas_m, &secCtxt);
	
	naspdu.value.choice.NAS_PDU = nas_octet_string;
	ASN_SEQUENCE_ADD(&dln_m.protocolIEs.list, &naspdu);
	iniMsg_m.value.choice.DownlinkNASTransport = dln_m;

	size_t ngapPdu_m_enc_sz = BUF_SIZE;
	char ngapPdu_m_enc[ngapPdu_m_enc_sz] = {}; // on stack, only reqd till msg sent.
	encodeNgap(ngapPdu_m_enc, &ngapPdu_m, ngapPdu_m_enc_sz); // buff size

	pthread_mutex_lock (&keyToFdMapLock);
	int fd1 = keyToFdMap[amfUeNgapId];
	pair<struct sockaddr_in, int> ipFdPair = keyToIpFdMap[amfUeNgapId];
	pthread_mutex_unlock (&keyToFdMapLock);

	// send to ran. 
	// response from RAN will be handled by NGAPIncoming
	sendData("127.0.0.1", 38413, ngapPdu_m_enc, false, SCTP_PROTOCOL, RAN, ngapPdu_m_enc_sz, fd1, NULL, &ipFdPair.first, nfvInst);

LOG_EXIT;
}

void NasSecurityInitiationResponse(NGAP_PDU_t* messageBody,nasMessage_t nasMsg, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst){
LOG_ENTRY;
	
	AMF_UE_NGAP_ID_t _amfUeNgapId;
	int status = ngapGetAmfUeNgapId(_amfUeNgapId,messageBody);

	
	AmfUeNgapId_t amfUeNgapId;
	int status1 = asn_INTEGER2ulong(&amfUeNgapId,&_amfUeNgapId);

	initialContextSetup (amfUeNgapId, fd, client_ip, nfvInst);
LOG_EXIT;
}

void initialContextSetup(AmfUeNgapId_t amfUeNgapId, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst){
LOG_ENTRY;
	
	nasMessage_t nas_m = {};
	
	RegistrationAcceptMsg_t regAcpt_m = {};

	regAcpt_m.mmHeader.epd = _5GS_MOBILITY_MANAGEMENT_MESSAGE;
	regAcpt_m.mmHeader.secuHeader = SECURITY_HEADER_TYPE_NOT_PROTECTED;
	regAcpt_m.mmHeader.msgType = REGISTRATION_ACCEPT;
	regAcpt_m._5gregResult.len = REG_RESULT_SIZE;
	regAcpt_m._5gregResult.smsAllowed = SMS_NOT_SUPPORTED;
	
	secContext_t _secCtxt = {};

	regAcpt_m._5gregResult.value = E_3GPP_ACCESS;
	
	regAcpt_m._5gmobileId.len = GUTI_LENGTH;
	regAcpt_m._5gmobileId.guti5gMobileId = generateGuti();

	regAcpt_m.presenceMask = 0;

	nas_m.plain._5gmmMsg.regAcceptMsg = regAcpt_m;
	
	NGAP_PDU_t ngapPdu_m = {};
	
	InitiatingMessage_t iniMsg_m = {};
	
	InitialContextSetupRequest_t icr_m = {};

	ngapPdu_m.present = NGAP_PDU_PR_initiatingMessage;
	ngapPdu_m.choice.initiatingMessage= &iniMsg_m;

	iniMsg_m.procedureCode = ProcedureCode_id_InitialContextSetup;
	iniMsg_m.criticality = Criticality_reject;
	iniMsg_m.value.present = InitiatingMessage__value_PR_InitialContextSetupRequest;
	
	InitialContextSetupRequestIEs_t amfid = {};

	amfid.id = ProtocolIE_ID_id_AMF_UE_NGAP_ID;
	amfid.criticality = Criticality_reject;
	amfid.value.present = InitialContextSetupRequestIEs__value_PR_AMF_UE_NGAP_ID;
	
	int status3 = asn_ulong2INTEGER(&amfid.value.choice.AMF_UE_NGAP_ID,amfUeNgapId);

	ASN_SEQUENCE_ADD(&icr_m.protocolIEs.list, &amfid);
	
	InitialContextSetupRequestIEs_t ranid = {};

	ranid.id = ProtocolIE_ID_id_RAN_UE_NGAP_ID;
	ranid.criticality = Criticality_reject;
	ranid.value.present = InitialContextSetupRequestIEs__value_PR_RAN_UE_NGAP_ID;

	pthread_mutex_lock(&UeContextMapLock);
	RAN_UE_NGAP_ID_t ranUeId = UeContextMap[amfUeNgapId].ranUeNgapId;
	pthread_mutex_unlock(&UeContextMapLock);
	ranid.value.choice.RAN_UE_NGAP_ID = ranUeId;

	ASN_SEQUENCE_ADD(&icr_m.protocolIEs.list, &ranid);
	
	InitialContextSetupRequestIEs_t amfName = {};

	amfName.id = ProtocolIE_ID_id_OldAMF;
	amfName.criticality = Criticality_reject;
	amfName.value.present = InitialContextSetupRequestIEs__value_PR_AMFName;
	
	ifstream ifs("amfconfig.json");
	Json::Reader reader;
	Json::Value amfConfig= {};
	reader.parse(ifs,amfConfig);

	OCTET_STRING_t amf_config_amfname = toOctetString(amfConfig["AMFName"].asString().c_str());
	
	amfName.value.choice.AMFName = amf_config_amfname;
	
	ASN_SEQUENCE_ADD(&icr_m.protocolIEs.list, &amfName);
	
	InitialContextSetupRequestIEs_t guami = {};

	guami.id = ProtocolIE_ID_id_GUAMI;
	guami.criticality = Criticality_reject;
	guami.value.present = InitialContextSetupRequestIEs__value_PR_GUAMI;
	guami.value.choice.GUAMI = generateGuami();

	ASN_SEQUENCE_ADD(&icr_m.protocolIEs.list, &guami);
	
	InitialContextSetupRequestIEs_t alnssai = {};

	alnssai.id = ProtocolIE_ID_id_AllowedNSSAI;
	alnssai.criticality = Criticality_reject;
	alnssai.value.present = InitialContextSetupRequestIEs__value_PR_AllowedNSSAI;
	
	AllowedNSSAI_t alnssai_IEs = {};
	
	AllowedNSSAI_Item_t alnssai_item[2] = {};

	for (int itr=0;itr<2;itr++) {
		S_NSSAI_t snssai = {};
	
		char sst[1] = {};

		sst[0] = amfConfig["amf-s-nssai-list"]["amf-nssai"][itr]["snssai"]["sst"].asInt();
	
		int stat1 = OCTET_STRING_fromBuf(&snssai.sST,sst,1);

		alnssai_item[itr].s_NSSAI = snssai;

		ASN_SEQUENCE_ADD(&alnssai_IEs.list, &alnssai_item[itr]);
	}
	
	alnssai.value.choice.AllowedNSSAI = alnssai_IEs;

	ASN_SEQUENCE_ADD(&icr_m.protocolIEs.list, &alnssai);
	
	InitialContextSetupRequestIEs_t ueSecCap = {};

	ueSecCap.id = ProtocolIE_ID_id_UESecurityCapabilities;
	ueSecCap.criticality = Criticality_reject;
	ueSecCap.value.present = InitialContextSetupRequestIEs__value_PR_UESecurityCapabilities;
	
	UESecurityCapabilities_t ueSec = {};
	
	int rc1 = BIT_STRING_fromNum(&ueSec.nRencryptionAlgorithms,0,16);

	int rc2 = BIT_STRING_fromNum(&ueSec.nRintegrityProtectionAlgorithms,0,16);

	int rc3 = BIT_STRING_fromNum(&ueSec.eUTRAencryptionAlgorithms,0,16);

	int rc4 = BIT_STRING_fromNum(&ueSec.eUTRAintegrityProtectionAlgorithms,0,16);

	ueSecCap.value.choice.UESecurityCapabilities = ueSec;

	ASN_SEQUENCE_ADD(&icr_m.protocolIEs.list, &ueSecCap);
	
	InitialContextSetupRequestIEs_t secKey = {};

	secKey.id = ProtocolIE_ID_id_SecurityKey;
	secKey.criticality = Criticality_reject;
	secKey.value.present = InitialContextSetupRequestIEs__value_PR_SecurityKey;
	
	char secKeyBuf[256] = {};
	
	int rc = BIT_STRING_fromBuf(&secKey.value.choice.SecurityKey,secKeyBuf,256);

	ASN_SEQUENCE_ADD(&icr_m.protocolIEs.list, &secKey);
	
	InitialContextSetupRequestIEs_t naspdu = {};

	naspdu.id = ProtocolIE_ID_id_NAS_PDU;
	naspdu.criticality = Criticality_reject;
	naspdu.value.present = InitialContextSetupRequestIEs__value_PR_NAS_PDU;

	OCTET_STRING_t nas_octet_string = nasMessagetoOctetString(&nas_m, &_secCtxt);
	lowLog("sz_oct: %ld\n", nas_octet_string.size);
	
	naspdu.value.choice.NAS_PDU = nas_octet_string;

	ASN_SEQUENCE_ADD(&icr_m.protocolIEs.list, &naspdu);

	iniMsg_m.value.choice.InitialContextSetupRequest = icr_m;

	pthread_mutex_lock (&keyToFdMapLock);
	int fd1 = keyToFdMap[amfUeNgapId];
	pair<struct sockaddr_in, int> ipFdPair = keyToIpFdMap[amfUeNgapId];
	pthread_mutex_unlock (&keyToFdMapLock);

	size_t ngapPdu_m_enc_sz = BUF_SIZE;
	char ngapPdu_m_enc[ngapPdu_m_enc_sz] = {}; // on stack, only reqd till msg sent.
	encodeNgap(ngapPdu_m_enc, &ngapPdu_m, ngapPdu_m_enc_sz); // buff size

	sendData("127.0.0.1", 38413, ngapPdu_m_enc, false, SCTP_PROTOCOL, RAN, ngapPdu_m_enc_sz, fd1, NULL, &ipFdPair.first, nfvInst);

LOG_EXIT;
}

void initialContextSetupResponse(NGAP_PDU_t* messageBody, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst){
LOG_ENTRY;
	
	AMF_UE_NGAP_ID_t _amfUeNgapId;
	int status = ngapGetAmfUeNgapId(_amfUeNgapId,messageBody);

	
	AmfUeNgapId_t amfUeNgapId;
	int status1 = asn_INTEGER2ulong(&amfUeNgapId,&_amfUeNgapId);

	udmSelection (amfUeNgapId, fd, client_ip, nfvInst);

LOG_EXIT;
}

void udmSelection(AmfUeNgapId_t amfUeNgapId, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst){
LOG_ENTRY;
	pthread_mutex_lock(&globalContextMapLock);
	string udm_ip = globalContextMap["structEntry"].udm_ip;
	pthread_mutex_unlock(&globalContextMapLock);
	
	if (udm_ip=="") 
	{
		HttpRequest nnrf_disc = {};
		nnrf_disc.options.insert({"Host", "127.0.0.1"});
		nnrf_disc.options.insert({"User-Agent","cpprestsdk/2.10.15"});
		nnrf_disc.options.insert({"Connection","Keep-Alive"});

		nnrf_disc.method = GET;
		nnrf_disc.version = HTTP_2_0;
		nnrf_disc.uri = "/nnrf-disc/v1/nf-instances";
		nnrf_disc.queryParams["target-nf-type"] = "UDM";
		nnrf_disc.queryParams["requester-nf-type"] = "AMF";
		nnrf_disc.queryParams["service-names"] = "nudm-uecm";

		pthread_mutex_lock(&UeContextMapLock);
		UeContextMap[amfUeNgapId].state= "nrfDiscovery";
		pthread_mutex_unlock(&UeContextMapLock);

		size_t nnrf_disc_enc_sz = BUF_SIZE;
		string nnrf_disc_enc;
		encodeHTTP(nnrf_disc_enc, nnrf_disc, nnrf_disc_enc_sz);

		sendData("127.0.0.1", 6666, (char *)nnrf_disc_enc.c_str(), true, TCP_PROTOCOL, NRF, nnrf_disc_enc_sz, amfUeNgapId, sbiIncoming, NULL, nfvInst);
	}
	else 
	{
		uecmRegistration (amfUeNgapId, fd, client_ip, nfvInst);
	}
LOG_EXIT;
}

void uecmRegistration(AmfUeNgapId_t amfUeNgapId, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst){
LOG_ENTRY;
	
	HttpRequest nudm_uecm_reg = {};
	nudm_uecm_reg.options.insert({"Host", "127.0.0.1"});
	nudm_uecm_reg.options.insert({"User-Agent","cpprestsdk/2.10.15"});
	nudm_uecm_reg.options.insert({"Connection","Keep-Alive"});

	nudm_uecm_reg.method = PUT;
	nudm_uecm_reg.version = HTTP_2_0;

	pthread_mutex_lock(&UeContextMapLock);
	string suci = UeContextMap[amfUeNgapId].suci;
	pthread_mutex_unlock(&UeContextMapLock);

	nudm_uecm_reg.uri = "/nudm-uecm/v1/"+suci+"/registrations/amf-3gpp-access";
	
	ifstream ifs("amfconfig.json");
	Json::Reader reader;
	Json::Value amfConfig= {};
	reader.parse(ifs,amfConfig);

	nudm_uecm_reg.body["amfInstanceId"] = amfConfig["amf-id"].asString().c_str();
	nudm_uecm_reg.body["deregCallbackUri"] = "http://127.0.0.1:80/";
	nudm_uecm_reg.body["guami"]["amfId"] = "amf1";
	nudm_uecm_reg.body["guami"]["plmnId"]["mcc"] = amfConfig["guamiAndGutiInfo"]["plmn-mcc"].asString().c_str();
	nudm_uecm_reg.body["guami"]["plmnId"]["mnc"] = amfConfig["guamiAndGutiInfo"]["plmn-mnc"].asString().c_str();
	nudm_uecm_reg.body["ratType"] = "NR";

	pthread_mutex_lock(&UeContextMapLock);
	UeContextMap[amfUeNgapId].state= "uecmRegistration";
	pthread_mutex_unlock(&UeContextMapLock);
	
	pthread_mutex_lock(&globalContextMapLock);
	string udm_ip = globalContextMap["structEntry"].udm_ip;
	pthread_mutex_unlock(&globalContextMapLock);

	size_t  nudm_uecm_reg_enc_sz = BUF_SIZE;
	string nudm_uecm_reg_enc;
	encodeHTTP(nudm_uecm_reg_enc, nudm_uecm_reg, nudm_uecm_reg_enc_sz);

	sendData(udm_ip, 3333, (char *)nudm_uecm_reg_enc.c_str(), true, TCP_PROTOCOL, UDM, nudm_uecm_reg_enc_sz, amfUeNgapId, sbiIncoming, NULL, nfvInst);

LOG_EXIT;
}

void uecmRegistrationResponse(json messageBody, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst){
LOG_ENTRY;

	pthread_mutex_lock(&fdToKeyMapLock);
	int amfUeNgapId = fdToKeyMap[fd];
	pthread_mutex_unlock(&fdToKeyMapLock);

	udmSDMGet (amfUeNgapId, fd, client_ip, nfvInst);

LOG_EXIT;
}
void udmSDMGet(int amfUeNgapId, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst){
LOG_ENTRY;
	
	HttpRequest nudm_sdm_get = {};
	nudm_sdm_get.options.insert({"Host", "127.0.0.1"});
	nudm_sdm_get.options.insert({"User-Agent","cpprestsdk/2.10.15"});
	nudm_sdm_get.options.insert({"Connection","Keep-Alive"});

	nudm_sdm_get.method = GET;
	nudm_sdm_get.version = HTTP_2_0;

	pthread_mutex_lock(&UeContextMapLock);
	string suci = UeContextMap[amfUeNgapId].suci;
	pthread_mutex_unlock(&UeContextMapLock);

	nudm_sdm_get.uri = "/nudm-sdm/v1/"+suci+"/nssai";
	nudm_sdm_get.queryParams["plmn-id"] = "40400";

	pthread_mutex_lock(&UeContextMapLock);
	UeContextMap[amfUeNgapId].state= "udmSDMGet";
	pthread_mutex_unlock(&UeContextMapLock);
	
	pthread_mutex_lock(&globalContextMapLock);
	string udm_ip = globalContextMap["structEntry"].udm_ip;
	pthread_mutex_unlock(&globalContextMapLock);

	size_t nudm_sdm_get_enc_sz = BUF_SIZE;
	string nudm_sdm_get_enc;
	encodeHTTP(nudm_sdm_get_enc, nudm_sdm_get, nudm_sdm_get_enc_sz);

	sendData(udm_ip, 3333, (char *)nudm_sdm_get_enc.c_str(), true, TCP_PROTOCOL, UDM, nudm_sdm_get_enc_sz, amfUeNgapId, sbiIncoming, NULL, nfvInst);

LOG_EXIT;
}

void udmSDMGetResponse(json messageBody, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst){
LOG_ENTRY;

	pthread_mutex_lock(&fdToKeyMapLock);
	int amfUeNgapId = fdToKeyMap[fd];
	pthread_mutex_unlock(&fdToKeyMapLock);

	pthread_mutex_lock(&UeContextMapLock);
	nssai_t reqNssai = UeContextMap[amfUeNgapId].requestedNssai;
	pthread_mutex_unlock(&UeContextMapLock);

	nssai_t allowNSSAI = {};
	
	rejectedNssai_t rejNssai = {};

	if (reqNssai.no_of_slices>0) 
	{
		nssai_t extractedNssais = {};
		
		for (int itr=0;itr<messageBody["singleNssais"].size();itr++) 
		{
			s_nssai_t subSlice = {};

			subSlice.sST = messageBody["singleNssais"][itr]["sst"];
			subSlice.sD= stoi((string)messageBody["singleNssais"][itr]["sd"]);
			
			//uint8_t num1;
			uint8_t num1 = extractedNssais.no_of_slices;
	
			int stat52 = increment(num1,1);

			extractedNssais.Nssai[num1] = subSlice;
		}

		//bool subscribedSlice;
		bool subscribedSlice = false;
		for (int slice=0;slice<reqNssai.no_of_slices;slice++) 
		{
			for (int i=0;i<extractedNssais.no_of_slices;i++) 
			{
				if (reqNssai.Nssai[slice].len_s_nssai==extractedNssais.Nssai[i].len_s_nssai && reqNssai.Nssai[slice].sST==extractedNssais.Nssai[i].sST && reqNssai.Nssai[slice].sD==extractedNssais.Nssai[i].sD) 
				{
					subscribedSlice = true;
					break;
				}
				if (subscribedSlice==false) 
				{
					//uint8_t num;
					uint8_t num = rejNssai.no_of_slices;
					rejNssai.Nssai[num].len_s_nssai = reqNssai.Nssai[slice].len_s_nssai;
					rejNssai.Nssai[num].reject_cause = CAUSE_S_NSSAI_NA_FOR_PLMN;
					rejNssai.Nssai[num].sST = reqNssai.Nssai[slice].sST;
					rejNssai.Nssai[num].sD = reqNssai.Nssai[slice].sD;
	
					int stat12 = increment(num,1);

					continue;
				}
			}

			//bool amfSupport;
			bool amfSupport = false;
	
			ifstream ifs("amfconfig.json");
			Json::Reader reader;
			Json::Value amfConfig= {};
			reader.parse(ifs,amfConfig);

			for (int i=0;i<2;i++) 
			{
				if (reqNssai.Nssai[slice].sST==amfConfig["amf-s-nssai-list"]["amf-nssai"][i]["sst"].asInt() && reqNssai.Nssai[slice].sD==amfConfig["amf-s-nssai-list"]["amf-nssai"][i]["SD"].asInt()) 
				{
					amfSupport = true;
					break;
				}
			}
			if (amfSupport==true) 
			{
				//uint8_t num;
				uint8_t num = allowNSSAI.no_of_slices;
				allowNSSAI.Nssai[num].len_s_nssai = reqNssai.Nssai[slice].len_s_nssai;
				allowNSSAI.Nssai[num].sST = reqNssai.Nssai[slice].sST;
				allowNSSAI.Nssai[num].sD = reqNssai.Nssai[slice].sD;
				
				int stat11 = increment(num,1);

				continue;

			}
		}
	}
	if (allowNSSAI.no_of_slices>0) 
	{
		pthread_mutex_lock(&UeContextMapLock);
		UeContextMap[amfUeNgapId].allowedNssai= allowNSSAI;
		pthread_mutex_unlock(&UeContextMapLock);
	}
	if (rejNssai.no_of_slices>0) 
	{
	pthread_mutex_lock(&UeContextMapLock);
	UeContextMap[amfUeNgapId].rejectedNssai= rejNssai;
	pthread_mutex_unlock(&UeContextMapLock);
	}
	
	registrationAccept (amfUeNgapId, fd, client_ip, nfvInst);
LOG_EXIT;
}

void registrationAccept(int amfUeNgapId, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst){
LOG_ENTRY;
	
	nasMessage_t nas_m = {};
	
	RegistrationAcceptMsg_t regAcpt_m = {};

	regAcpt_m.mmHeader.epd = _5GS_MOBILITY_MANAGEMENT_MESSAGE;
	regAcpt_m.mmHeader.secuHeader = SECURITY_HEADER_TYPE_NOT_PROTECTED;
	regAcpt_m.mmHeader.msgType = REGISTRATION_ACCEPT;
	regAcpt_m._5gregResult.len = REG_RESULT_SIZE;
	regAcpt_m.presenceMask = 0;
	regAcpt_m._5gregResult.smsAllowed = SMS_NOT_SUPPORTED;

	regAcpt_m._5gmobileId.len = GUTI_LENGTH;
	regAcpt_m._5gmobileId.guti5gMobileId = generateGuti();
	
	secContext_t secCtxt = {};
	
	regAcpt_m.presenceMask = regAcpt_m.presenceMask|REGISTRATION_ACCEPT_REJ_NSSAI_PRESENT;
	
	regAcpt_m.allowedNssai.no_of_slices = 1;
	regAcpt_m.rejectedNssai.no_of_slices = 1;
	regAcpt_m.rejectedNssai.Nssai[0].len_s_nssai = LEN_SST_AND_SD;
	
	nas_m.plain._5gmmMsg.regAcceptMsg = regAcpt_m;
	
	NGAP_PDU_t ngapPdu_m = {};
	
	InitiatingMessage_t iniMsg_m = {};
	
	DownlinkNASTransport_t dln_m = {};
	
	ngapPdu_m.present = NGAP_PDU_PR_initiatingMessage;
	ngapPdu_m.choice.initiatingMessage= &iniMsg_m;

	iniMsg_m.procedureCode = ProcedureCode_id_DownlinkNASTransport;
	iniMsg_m.criticality = Criticality_ignore;
	iniMsg_m.value.present = InitiatingMessage__value_PR_DownlinkNASTransport;
	
	DownlinkNASTransport_IEs_t amfid = {};

	amfid.id = ProtocolIE_ID_id_AMF_UE_NGAP_ID;
	amfid.criticality = Criticality_reject;
	amfid.value.present = DownlinkNASTransport_IEs__value_PR_AMF_UE_NGAP_ID;
	
	int status3 = asn_ulong2INTEGER(&amfid.value.choice.AMF_UE_NGAP_ID,amfUeNgapId);

	ASN_SEQUENCE_ADD(&dln_m.protocolIEs.list, &amfid);
	
	DownlinkNASTransport_IEs_t ranid = {};
	
	ranid.id = ProtocolIE_ID_id_RAN_UE_NGAP_ID;
	ranid.criticality = Criticality_reject;
	ranid.value.present = DownlinkNASTransport_IEs__value_PR_RAN_UE_NGAP_ID;

	pthread_mutex_lock(&UeContextMapLock);
	RAN_UE_NGAP_ID_t t1 = UeContextMap[amfUeNgapId].ranUeNgapId;
	pthread_mutex_unlock(&UeContextMapLock);
	
	ranid.value.choice.RAN_UE_NGAP_ID = t1;

	ASN_SEQUENCE_ADD(&dln_m.protocolIEs.list, &ranid);
	
	DownlinkNASTransport_IEs_t amfName = {};

	amfName.id = ProtocolIE_ID_id_OldAMF;
	amfName.criticality = Criticality_reject;
	amfName.value.present = DownlinkNASTransport_IEs__value_PR_AMFName;
	
	ifstream ifs("amfconfig.json");
	Json::Reader reader;
	Json::Value amfConfig= {};
	reader.parse(ifs,amfConfig);

	OCTET_STRING_t amf_config_amfname = toOctetString(amfConfig["AMFName"].asString().c_str());
	
	amfName.value.choice.AMFName = amf_config_amfname;

	ASN_SEQUENCE_ADD(&dln_m.protocolIEs.list, &amfName);
	
	DownlinkNASTransport_IEs_t naspdu = {};

	naspdu.id = ProtocolIE_ID_id_NAS_PDU;
	naspdu.criticality = Criticality_reject;
	naspdu.value.present = DownlinkNASTransport_IEs__value_PR_NAS_PDU;

	OCTET_STRING_t nas_octet_string = nasMessagetoOctetString(&nas_m, &secCtxt);
	
	naspdu.value.choice.NAS_PDU = nas_octet_string;
	
	ASN_SEQUENCE_ADD(&dln_m.protocolIEs.list, &naspdu);

	iniMsg_m.value.choice.DownlinkNASTransport = dln_m;
	
	size_t ngapPdu_m_enc_sz = BUF_SIZE;
	char ngapPdu_m_enc[ngapPdu_m_enc_sz] = {}; // on stack, only reqd till msg sent.
	encodeNgap(ngapPdu_m_enc, &ngapPdu_m, ngapPdu_m_enc_sz); // buff size

	pthread_mutex_lock (&keyToFdMapLock);
	int fd1 = keyToFdMap[amfUeNgapId];
	pair<struct sockaddr_in, int> ipFdPair = keyToIpFdMap[amfUeNgapId];
	pthread_mutex_unlock (&keyToFdMapLock);
	sendData("127.0.0.1", 38413, ngapPdu_m_enc, false, SCTP_PROTOCOL, RAN, ngapPdu_m_enc_sz, fd1, NULL, &ipFdPair.first, nfvInst);

LOG_EXIT;
}

void registrationAcceptResponse(NGAP_PDU_t* messageBody,nasMessage_t nasMsg, int fd, struct sockaddr_in *client_ip, struct nfvInstanceData *nfvInst){
LOG_ENTRY;
	
	AMF_UE_NGAP_ID_t _amfUeNgapId;
	int status = ngapGetAmfUeNgapId(_amfUeNgapId,messageBody);

	
	AmfUeNgapId_t amfUeNgapId;
	int status1 = asn_INTEGER2ulong(&amfUeNgapId,&_amfUeNgapId);

	pthread_mutex_lock(&UeContextMapLock);
	UeContextMap[amfUeNgapId].isSuccess= true;
	pthread_mutex_unlock(&UeContextMapLock);

LOG_EXIT;
}