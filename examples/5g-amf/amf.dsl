EVENT sbiIncoming(message) # node->AMF first function.
    DECODE(decode_sbi_message, messageBody, message)
    DECODE(decode_sbi_json_header, header, message)
    GET_KEY (amfUeNgapId)
    LOOKUP (state, UeContextMap, amfUeNgapId, state)

    IF (state ==  "nrfDiscovery")
        CALL (nrfDiscoveryResponse, messageBody)
    
    IF (state ==  "ueAuthentication")
        CALL (ueAuthenticationResponse, messageBody)
    
    IF (state ==  "ueAuthenticationUpdate")
        CALL (ueAuthenticationUpdateResponse, messageBody)
    
    IF (state ==  "uecmRegistration")
        CALL (uecmRegistrationResponse, messageBody)
    
    IF (state ==  "udmSDMGet")
        CALL (udmSDMGetResponse, messageBody)

EVENT sbiIncomingRequestJSON(header, messageBody)
    PASS

EVENT ngapIncoming(message)
    DECODE(decodeNgapPdu, messageBody, message) # decode knows len from message itself
    IF (messageBody)
        CALL(failure, message)
    UDF (status, ngapGetProcedureCode, procedureCode, messageBody)
    IF (procedureCode == MACRO(ProcedureCode_id_UplinkNASTransport))
        CALL (handleUPLN, messageBody)
    
    IF (procedureCode == MACRO(ProcedureCode_id_DownlinkNASTransport))
        CALL (handleDNLN, messageBody)
    
    IF (procedureCode == MACRO(ProcedureCode_id_InitialUEMessage))
        CALL (handleINITUE, messageBody)

    IF (procedureCode == MACRO(ProcedureCode_id_NGSetup))
        CALL (NGSetupRequest, messageBody)
    
    IF (procedureCode == MACRO(ProcedureCode_id_InitialContextSetup))
        CALL (initialContextSetupResponse, messageBody)

EVENT failure(message)
    PASS

EVENT handleUPLN(messageBody)
    
    UDF (status1, ngapGetNasPdu, nasPDU, messageBody)
    UDF (status2, nasMessagePlainDecode, nasMsg, nasPDU.buf, nasPDU.size)

    IF (nasMsg.plain._5gmmMsg.mmheader.msgType == MACRO(AUTHENTICATION_RESPONSE))
        CALL (NasAuthenticationResponse, messageBody, nasMsg)

    IF (nasMsg.plain._5gmmMsg.mmheader.msgType == MACRO(IDENTITY_RESPONSE))
        CALL (identityResponse, messageBody, nasMsg)

    IF (nasMsg.plain._5gmmMsg.mmheader.msgType == MACRO(SECURITY_MODE_COMPLETE))
        CALL (NasSecurityInitiationResponse, messageBody, nasMsg)

    IF (nasMsg.plain._5gmmMsg.mmheader.msgType == MACRO(REGISTRATION_ACCEPT))
        CALL (registrationAcceptResponse, messageBody, nasMsg)

EVENT handleDNLN(messageBody)
    PASS

EVENT handleINITUE(messageBody)
       
    UDF (status1, ngapGetNasPdu, nasPDU, messageBody)
    UDF (status2, nasMessagePlainDecode, nasMsg, nasPDU.buf, nasPDU.size)

    IF (nasMsg.plain._5gmmMsg.mmheader.msgType == MACRO(REGISTRATION_REQUEST))
        CALL (initialRegistrationRequest, messageBody, nasMsg)

##########################################################################################################################
#                                       NgSetup Response
##########################################################################################################################

EVENT NGSetupRequest (messageBody)
    UDF (status, getGlobalRANId, gNId, messageBody)
    UDF (status1, BitStringToNum, gNId_num, gNId.choice.globalGNB_ID.gNB_ID.choice.gNB_ID)
    SET_KEY (gNId_num)
    CALL (NGSetupResponse, messageBody)

EVENT NGSetupResponse (messageBody)
    CREATE_MESSAGE (ngapPdu_m, NGAP_PDU_t)
    CREATE_MESSAGE (succ_m, SuccessfulOutcome_t)
    CREATE_MESSAGE (ngsr_m, NGSetupResponse_t)

    SET (ngapPdu_m.present, MACRO(NGAP_PDU_PR_successfulOutcome))
    SET (ngapPdu_m.choice.successfulOutcome, succ_m)

    SET (succ_m.procedureCode, MACRO(ProcedureCode_id_NGSetup))
    SET (succ_m.criticality, MACRO(Criticality_reject))
    SET (succ_m.value.present, MACRO(SuccessfulOutcome__value_PR_NGSetupResponse))


    CREATE_MESSAGE (amfName, NGSetupResponseIEs_t)

    SET (amfName.id, MACRO(ProtocolIE_ID_id_AMFName))
    SET (amfName.criticality, MACRO(Criticality_reject))
    SET (amfName.value.present, MACRO(NGSetupResponseIEs__value_PR_AMFName))
    READ_CONFIG(amfConfig,"amfconfig.json")

    # lhs: reduces to octet string, rhs: char buf, i.e. string from amfconfig
    UDF(amf_config_amfname, toOctetString, amfConfig.AMFName) # call to OCTET_STRING_fromBuf
    
    SET (amfName.value.choice.AMFName, amf_config_amfname) # in k_set: if lhstype red to octet

    APPEND (ngsr_m, amfName) # append to the container type of a message.

    CREATE_MESSAGE (sGuami_m, NGSetupResponseIEs_t)
    CREATE_MESSAGE(sGuamiIE, ServedGUAMIList_t) 

    SET (sGuami_m.id, MACRO(ProtocolIE_ID_id_ServedGUAMIList))
    SET (sGuami_m.criticality, MACRO(Criticality_reject))
    SET (sGuami_m.value.present, MACRO(NGSetupResponseIEs__value_PR_ServedGUAMIList))

    CREATE_MESSAGE(sGuamiItem, ServedGUAMIItem_t) 
    SET (sGuamiItem.gUAMI, UDF(generateGuami))

    APPEND ( sGuamiIE,sGuamiItem)
    SET (sGuami_m.value.choice.ServedGUAMIList, sGuamiIE)

    APPEND (ngsr_m, sGuami_m)


    CREATE_MESSAGE (relAmfCap, NGSetupResponseIEs_t)

    SET (relAmfCap.id, MACRO(ProtocolIE_ID_id_RelativeAMFCapacity))
    SET (relAmfCap.criticality, MACRO(Criticality_ignore))
    SET (relAmfCap.value.present, MACRO(NGSetupResponseIEs__value_PR_RelativeAMFCapacity))
    SET (relAmfCap.value.choice.RelativeAMFCapacity, amfConfig.relativeAMFcapacity) 

    APPEND (ngsr_m, relAmfCap)

    CREATE_MESSAGE (pLMNSList, NGSetupResponseIEs_t)

    SET (pLMNSList.id, MACRO(ProtocolIE_ID_id_PLMNSupportList))
    SET (pLMNSList.criticality, MACRO(Criticality_reject))
    SET (pLMNSList.value.present, MACRO(NGSetupResponseIEs__value_PR_PLMNSupportList))

    CREATE_MESSAGE (pLMNIEs,PLMNSupportList_t)
    CREATE_MESSAGE (pLMNSItem, PLMNSupportItem_t)
    CREATE_MESSAGE (plmnBUF, char, 3)

    UDF(oct_str_plmnBuf, toOctetString, plmnBUF)
    
    SET(pLMNSItem.pLMNIdentity, octet_string_plmnBuf)

    #UDF (rc, OCTET_STRING_fromBuf ,pLMNSItem.pLMNIdentity,plmnBUF,3)

    CREATE_MESSAGE (sSuppList, SliceSupportList_t)
    CREATE_MESSAGE (sSuppItem, SliceSupportItem_t, 2)

    LOOP (itr,0,2) 
        CREATE_MESSAGE (snssai, S_NSSAI_t)
        CREATE_MESSAGE (sst, char, 1)
        #CREATE_MESSAGE (sd, char, 3)
        
        SET(sst[0], amfConfig.amf-s-nssai-list.amf-nssai[itr].snssai.sst)
        #SET(sd[0], amfConfig.amf-s-nssai-list.amf-nssai[itr].snssai.sst)
        #SET(sd[1], amfConfig.amf-s-nssai-list.amf-nssai[itr].snssai.sst)
        #SET(sd[2], amfConfig.amf-s-nssai-list.amf-nssai[itr].snssai.sst)

        UDF(oct_str_sst, toOctetString, sst)
    
        SET(snssai.sST, oct_str_sst)

        #UDF (stat1,OCTET_STRING_fromBuf,snssai.sST, sst, 1)
        #SET(snssai.sD,sd)

        SET(sSuppItem[itr].s_NSSAI, snssai)
        APPEND(sSuppList, sSuppItem[itr])


    SET (pLMNSItem.sliceSupportList,sSuppList)
    APPEND (pLMNIEs, pLMNSItem)

    SET (pLMNSList.value.choice.PLMNSupportList, pLMNIEs)
    APPEND (ngsr_m, pLMNSList)

    #criticalityDiagnostics

    CREATE_MESSAGE (critDiag_m, NGSetupResponseIEs_t)

    SET (critDiag_m.id, MACRO(ProtocolIE_ID_id_CriticalityDiagnostics))
    SET (critDiag_m.criticality, MACRO(Criticality_ignore))
    SET (critDiag_m.value.present, MACRO(NGSetupResponseIEs__value_PR_CriticalityDiagnostics))

    APPEND (ngsr_m, critDiag_m)

    SET (succ_m.value.choice.NGSetupResponse, ngsr_m)

    UDF (status, getGlobalRANId, gNId, messageBody)
    UDF (status1, BitStringToNum, gNId_num, gNId.choice.globalGNB_ID.gNB_ID.choice.gNB_ID)

    ENCODE(encodeNgap, ngapPdu_m_enc, ngapPdu_m, ngapPdu_m_enc_sz)
    #SEND(ngapPdu_m_enc, ngapPdu_m_enc_sz, "127.0.0.1", AMF, RAN, N2, gNId_num, NULL)
        
##########################################################################################################################
#                                       Initial Registration Procedure
##########################################################################################################################

EVENT initialRegistrationRequest(messageBody, nasMsg)

    UDF (status1, ngapGetRanUeNgapId, ranUeNgapId, messageBody)

    STORE (UeContextMapTemp, ranUeNgapId, _5gregType, nasMsg.plain._5gmmMsg.regReqMsg._5gregType)
    STORE (UeContextMapTemp, ranUeNgapId, ngKsi, nasMsg.plain._5gmmMsg.regReqMsg.ngKsi)
    
    CREATE_MESSAGE (requestedNSSAI, nssai_t)
    SET (requestedNSSAI.no_of_slices, nasMsg.plain._5gmmMsg.regReqMsg.requestedNssai.no_of_slices)

    LOOP (itr, 0, nasMsg.plain._5gmmMsg.regReqMsg.requestedNssai.no_of_slices)
        IF (nasMsg.plain._5gmmMsg.regReqMsg.requestedNssai.Nssai[itr].len_s_nssai == MACRO(LEN_ONLY_SST))
            SET (requestedNSSAI.Nssai[itr].len_s_nssai, nasMsg.plain._5gmmMsg.regReqMsg.requestedNssai.Nssai[itr].len_s_nssai)
            SET (requestedNSSAI.Nssai[itr].sST, nasMsg.plain._5gmmMsg.regReqMsg.requestedNssai.Nssai[itr].sST)
        
        IF (nasMsg.plain._5gmmMsg.regReqMsg.requestedNssai.Nssai[itr].len_s_nssai == MACRO(LEN_SST_AND_SD))
            SET (requestedNSSAI.Nssai[itr].len_s_nssai, nasMsg.plain._5gmmMsg.regReqMsg.requestedNssai.Nssai[itr].len_s_nssai)
            SET (requestedNSSAI.Nssai[itr].sST, nasMsg.plain._5gmmMsg.regReqMsg.requestedNssai.Nssai[itr].sST)
            SET (requestedNSSAI.Nssai[itr].sD, nasMsg.plain._5gmmMsg.regReqMsg.requestedNssai.Nssai[itr].sD)
    
    STORE (UeContextMapTemp, ranUeNgapId, requestedNssai, requestedNSSAI)

    UDF (status2, retrieveMobileIdentity, suci_, nasMsg.plain._5gmmMsg.regReqMsg)

    # Set fields of the context

    IF (status2 == MACRO(FAILURE))
        CALL (identityRequest, messageBody, nasMsg)
    ELSE
        # IF_PRESENT (SuciToAmfUeNgapIDMap, SUCI)
        #    EXCEPTION (FOUND)

        UDF (status3, suciSchemeToImsi, SUCI, suci_)

        UDF (status4, generateAmfUeNgapId, amfUeNgapId)

        STORE (UeContextMap, amfUeNgapId, ranUeNgapId, ranUeNgapId)
        STORE (UeContextMap, amfUeNgapId, suci, SUCI)
        STORE (SuciAmfUeNgapIdMap, SUCI, amfUeNgapId, amfUeNgapId)

        STORE (UeContextMap, amfUeNgapId, _5gregType, nasMsg.plain._5gmmMsg.regReqMsg._5gregType)
        STORE (UeContextMap, amfUeNgapId, ngKsi, nasMsg.plain._5gmmMsg.regReqMsg.ngKsi)
                
        STORE (UeContextMap, amfUeNgapId, requestedNssai, requestedNSSAI)
        STORE (UeContextMap, amfUeNgapId, ueSecurityCapability, nasMsg.plain._5gmmMsg.regReqMsg.ueSecuCapability)
        SET_KEY (amfUeNgapId)
        CALL (AUSFSelection, amfUeNgapId)
        
EVENT identityRequest (messageBody, nasMsg)
    PASS

    #CREATE_MESSAGE (M1, nasMessage_t)

    #CREATE_STRUCTURE (H1, nasSecurityMessageHeader_t, M1, nasSecurityMessageHeader)
    #SET (H1.epd, globalContext.epd)
    #SET (H1.secuHeader, globalContext.secuHeader)
    #SET (H1.macCode, glovbalContext.macCode)
    #SET (H1.sqnNum, globalContext.sqnNum)
    #CREATE_STRUCTURE (M6, _5gmmMsg_t, M1, plain)
    #CREATE_STRUCTURE (M2, IdentityRequest_t, M6, identityReq)
    #CREATE_STRUCTURE (H2, _5gmmMsgHeader_t, M2, mmHeader)
    #SET (H2.epd, globalContext.epd)
    #SET (H2.secuHeader, globalContext.secuHeader)
    #SET (H2.msgType, IDENTITY_REQUEST)
    #SET (M2.identityType, 3)
    #
    ## NGAP Message
    #CREATE_MESSAGE (N1, NGAP_PDU_t)
    #CREATE_MESSAGE (N2, choice_t)    # Disputed matter
    #CREATE_MESSAGE (N3, Initiating_Msg_t)
    #CREATE_MESSAGE (N4, DownLinkNasTransport_t)
    ## Protocol list pending
    #CREATE_MESSAGE (N7, AMF-UE-NGAP-ID)
    #SET (N7.id, 46)
    #SET (N7.criticality, REJECT)
    #CREATE_MESSAGE (N8, value_t)
    #SET (N8.present, 1)
    #CREATE_MESSAGE (N9, choice_t)
    #SET (N9.AMF-UE-NGAP-ID, XYZ) # Value obtained from somewhere
    #SET (N7.value, N8)
    #CREATE_MESSAGE (N10, RAN-UE-NGAP-ID)
    #SET (N10.id, 46)
    #SET (N10.criticality, REJECT)
    #CREATE_MESSAGE (N11, value_t)
    #SET (N11.present, 1)
    #CREATE_MESSAGE (N12, choice_t)
    #SET (N12.RAN-UE-NGAP-ID, XYZ) # Value obtained from somewhere
    #SET (N10.value, N11)
    #SET (N4.AMF-UE-NGAP_ID, N7)
    #SET (N4.RAN-UE-NGAP_ID, N10)
    #SET (N4.NAS_PDU, M1)
    #SET (N3.procedureCode, 25)
    #SET (N3.criticality, IGNORE)
    #CREATE_MESSAGE (N5, value_t)
    #CREATE_MESSAGE (N6, choice_t)
    #SET (N6.DownLinkNasTransport, N4)
    #SET (N5.choice, N6)
    #SET (N3.value, N5)
    #SET (N2.initiatingMsg, N3)
    #SET (N1.choice, N2)
    ##SEND (N1)


EVENT identityResponse(messageBody, nasMsg)
    
    UDF (status1, ngapGetRanUeNgapId, ranUeNgapId, messageBody)

    UDF (status2, retrieveMobileIdentity, suci_, nasMsg.plain._5gmmMsg.regReqMsg)
    UDF (status3, suciToString, SUCI, suci_)

    # IF_PRESENT (SuciToAmfUeNgapIDMap, SUCI)
    #    EXCEPTION (FOUND)

    UDF (status4, generateAmfUeNgapId, amfUeNgapId)

    STORE (UeContextMapTemp, ranUeNgapId, suci, SUCI)
    STORE (SuciAmfUeNgapIdMap, SUCI, amfUeNgapId, amfUeNgapId)

    LOOKUP (regType, UeContextMapTemp, ranUeNgapId, _5gregType)
    STORE (UeContextMap, amfUeNgapId, _5gregType, regType)
    LOOKUP (ngKsi_, UeContextMapTemp, ranUeNgapId, ngKsi)
    STORE (UeContextMap, amfUeNgapId, ngKsi, ngKsi_)
    LOOKUP (_requestedNssai, UeContextMapTemp, ranUeNgapId, requestedNssai)
    STORE (UeContextMap, amfUeNgapId, requestedNssai, _requestedNssai)
    CALL (AUSFSelection, amfUeNgapId)

#############################################################################################################
#                                       Discovery Function
#############################################################################################################

EVENT nrfDiscoveryResponse(messageBody)
    GET_KEY(amfUeNgapId)
    IF (messageBody.nfInstances[0].nfType == "AUSF")
        
        STORE (globalContextMap, NULL, ausf_ip, messageBody.nfInstances[0].ipv4addresses[0])
        CALL (ueAuthentication, amfUeNgapId)

    IF (messageBody.nfInstances[0].nfType == "UDM")

        STORE (globalContextMap, NULL, udm_ip, messageBody.nfInstances[0].ipv4addresses[0])
        CALL (uecmRegistration, amfUeNgapId)


#############################################################################################################
#                                       AUSF SELECTION
#############################################################################################################


EVENT AUSFSelection(amfUeNgapId)

    LOOKUP (ausf_ip, globalContextMap, NULL, ausf_ip)

    IF (ausf_ip == "")
        CREATE_MESSAGE (nnrf_disc, HttpRequest)
        SET (nnrf_disc.method, MACRO(GET))
        SET (nnrf_disc.version, MACRO(HTTP_2_0))
        SET (nnrf_disc.uri, "/nnrf-disc/v1/nf-instances")
        SET (nnrf_disc.queryParams.target-nf-type, "AUSF")
        SET (nnrf_disc.queryParams.requester-nf-type, "AMF")
        SET (nnrf_disc.queryParams.service-names, "nausf-auth")
        STORE (UeContextMap, amfUeNgapId, state, "nrfDiscovery")
        ENCODE (encodeHTTP, nnrf_disc_enc, nnrf_disc, nnrf_disc_enc_sz)
        #SEND (request, "127.0.0.1", AMF, NRF, nnrf_disc_enc_sz, Nnrf, amfUeNgapId, sbiIncoming)
    ELSE
        CALL (ueAuthentication, amfUeNgapId)


##############################################################################################################
#                                        Authentication Starts
##############################################################################################################

        
EVENT ueAuthentication (amfUeNgapId)

    CREATE_MESSAGE (nausf_auth_ueAuth, HttpRequest)
    SET (nausf_auth_ueAuth.method, MACRO(POST))
    SET (nausf_auth_ueAuth.version, MACRO(HTTP_2_0))
    SET (nausf_auth_ueAuth.uri, "/nausf-auth/v1/ue-authentications")

    #SET (nausf_auth_ueAuth.body.amfInstanceId, "f38441e6_7f5f_4de0_8d3c_02eb6aa2617e")
    READ_CONFIG(amfConfig,"amfconfig.json")
    SET (nausf_auth_ueAuth.body.amfInstanceId, amfConfig.amf-id)

    #SET (nausf_auth_ueAuth.body.servingNetworkName, "5G:mnc000.mcc404.3gppnetwork.org")
    SET (nausf_auth_ueAuth.body.servingNetworkName, UDF(getSnName))

    #SET (nausf_auth_ueAuth.body.supiOrSuci, "404000000000000")
    LOOKUP (suciTemp, UeContextMap, amfUeNgapId, suci)
    SET (nausf_auth_ueAuth.body.supiOrSuci,suciTemp)
    STORE (UeContextMap, amfUeNgapId, state, "ueAuthentication")
    LOOKUP (ausf_ip, globalContextMap, NULL, ausf_ip)
    ENCODE(encodeHTTP, nausf_auth_ueAuth_enc, nausf_auth_ueAuth, nausf_auth_ueAuth_enc_sz)
    #SEND (nausf_auth_ueAuth_enc, ausf_ip, AMF, AUSF, nausf_auth_ueAuth_enc_sz, Nausf, amfUeNgapId, sbiIncoming)


EVENT ueAuthenticationResponse(messageBody)

    GET_KEY(amfUeNgapId) 

    IF (messageBody.authType == "5G_AKA")
        # Some validation steps can be written header or UDF can be called for validation

        STORE (UeContextMap, amfUeNgapId, RAND, messageBody.5gAuthData.rand)
        STORE (UeContextMap, amfUeNgapId, hxresStar, messageBody.5gAuthData.hxresStar)
        STORE (UeContextMap, amfUeNgapId, kSeaf, messageBody.5gAuthData.kSeaf)
        STORE (UeContextMap, amfUeNgapId, autn, messageBody.5gAuthData.autn)

    ELSE
        EXCEPTION (FAILURE)

    
    STORE (UeContextMap, amfUeNgapId, authCtxId, messageBody._links[0])
    
    CALL (NasAuthentication, amfUeNgapId)
    
EVENT NasAuthentication (amfUeNgapId)

    CREATE_MESSAGE (nas_m, nasMessage_t)
    CREATE_MESSAGE (authReq_m, AuthenticationRequestMsg_t)

    SET (authReq_m.mmHeader.epd, MACRO(_5GS_MOBILITY_MANAGEMENT_MESSAGE))
    SET (authReq_m.mmHeader.secuHeader, MACRO(SECURITY_HEADER_TYPE_NOT_PROTECTED))
    SET (authReq_m.mmHeader.msgType, MACRO(AUTHENTICATION_REQUEST))

    CREATE_MESSAGE (secCtxt, secContext_t)

    LOOKUP (ngKSI, UeContextMap, amfUeNgapId, ngKsi)
    SET (authReq_m.ngKsi, ngKSI)
    SET (authReq_m.abba.len, MACRO(ABBA_LEN_MIN))
    CREATE_MESSAGE (contents, uint8_t(ABBA_CONTENTS_MAX_SIZE))
    SET (authReq_m.abba.contents, contents)
    SET (authReq_m.presenceMask, 0)

    SET (authReq_m.presenceMask, authReq_m.presenceMask | MACRO(NAS_AUTH_REQUEST_OPT_RAND_PRESENT))
    
    LOOKUP (rand, UeContextMap, amfUeNgapId, RAND)
    UDF (status1, hexCopyFromStrings, authReq_m.rand.RAND, RAND_SIZE, rand)


    SET (authReq_m.presenceMask, authReq_m.presenceMask | MACRO(NAS_AUTH_REQUEST_OPT_AUTN_PRESENT))
    SET (authReq_m.autn.len, 16)
    #SET (authReq_m.autn.AUTN, secCtxt._5gAv.AUTN)
     
    LOOKUP (autn, UeContextMap, amfUeNgapId, autn)
    UDF (status2, hexCopyFromStrings, authReq_m.autn.AUTN, AUTN_SIZE, autn)



    SET (nas_m.plain._5gmmMsg.authReqMsg, authReq_m)


    # NGAP Message

    CREATE_MESSAGE (ngapPdu_m, NGAP_PDU_t)
    CREATE_MESSAGE (iniMsg_m, InitiatingMessage_t)
    CREATE_MESSAGE (dln_m, DownlinkNASTransport_t)

    SET (ngapPdu_m.present, MACRO(NGAP_PDU_PR_initiatingMessage))
    SET (ngapPdu_m.choice.initiatingMessage, iniMsg_m)

    SET (iniMsg_m.procedureCode, MACRO(ProcedureCode_id_DownlinkNASTransport))
    SET (iniMsg_m.criticality, MACRO(Criticality_ignore))
    SET (iniMsg_m.value.present, MACRO(InitiatingMessage__value_PR_DownlinkNASTransport))

    CREATE_MESSAGE (amfid, DownlinkNASTransport_IEs_t)

    SET (amfid.id, MACRO(ProtocolIE_ID_id_AMF_UE_NGAP_ID))
    SET (amfid.criticality, MACRO(Criticality_reject))
    SET (amfid.value.present, MACRO(DownlinkNASTransport_IEs__value_PR_AMF_UE_NGAP_ID))
    UDF (status3, asn_ulong2INTEGER, amfid.value.choice.AMF_UE_NGAP_ID, amfUeNgapId) 

    APPEND (dln_m, amfid)

    CREATE_MESSAGE (ranid, DownlinkNASTransport_IEs_t)

    SET (ranid.id, MACRO(ProtocolIE_ID_id_RAN_UE_NGAP_ID))
    SET (ranid.criticality, MACRO(Criticality_reject))
    SET (ranid.value.present, MACRO(DownlinkNASTransport_IEs__value_PR_RAN_UE_NGAP_ID))

    LOOKUP (ranUeId, UeContextMap, amfUeNgapId, ranUeNgapId)
    SET (ranid.value.choice.RAN_UE_NGAP_ID, ranUeId) 

    APPEND (dln_m, ranid)

    CREATE_MESSAGE (amfName, DownlinkNASTransport_IEs_t)

    SET (amfName.id, MACRO(ProtocolIE_ID_id_OldAMF))
    SET (amfName.criticality, MACRO(Criticality_reject))
    SET (amfName.value.present, MACRO(DownlinkNASTransport_IEs__value_PR_AMFName))
    READ_CONFIG(amfConfig,"amfconfig.json")

    # lhs: reduces to octet string, rhs: char buf, i.e. string from amfconfig
    UDF(amf_config_amfname, toOctetString, amfConfig.AMFName) # call to OCTET_STRING_fromBuf
    
    SET (amfName.value.choice.AMFName, amf_config_amfname) # in k_set: if lhstype red to octet


    APPEND (dln_m, amfName)

    CREATE_MESSAGE (naspdu, DownlinkNASTransport_IEs_t)

    SET (naspdu.id, MACRO(ProtocolIE_ID_id_NAS_PDU))
    SET (naspdu.criticality, MACRO(Criticality_reject))
    SET (naspdu.value.present, MACRO(DownlinkNASTransport_IEs__value_PR_NAS_PDU))
    
    UDF(nas_octet_string, nasMessagetoOctetString, nas_m, secCtxt) 
    SET (naspdu.value.choice.NAS_PDU, nas_octet_string) # lhs must reduce to rhs type else error.

    APPEND (dln_m, naspdu)

    SET (iniMsg_m.value.choice.DownlinkNASTransport, dln_m)

    ENCODE(encodeNgap, ngapPdu_m_enc, ngapPdu_m, ngapPdu_m_enc_sz)

    #SEND(ngapPdu_m_enc, "127.0.0.1", AMF, RAN, ngapPdu_m_enc_sz, N2, amfUeNgapId, NULL)

EVENT NasAuthenticationResponse(messageBody, nasMsg)

    UDF (status, ngapGetAmfUeNgapId, _amfUeNgapId, messageBody)
    UDF (status1, asn_INTEGER2ulong, amfUeNgapId, _amfUeNgapId)

    STORE (UeContextMap, amfUeNgapId, resStar, nasMsg.plain._5gmmMsg.authRespMsg.authRespParam.RESstar)

    # there are some checks which can be safely skipped for now

    CALL (ueAuthenticationUpdate, amfUeNgapId)

EVENT ueAuthenticationUpdate (amfUeNgapId)
    CREATE_MESSAGE (nausf_auth_ueAuth, HttpRequest)
    SET (nausf_auth_ueAuth.method, MACRO(PUT))
    SET (nausf_auth_ueAuth.version, MACRO(HTTP_2_0))
    LOOKUP (cntxId, UeContextMap, amfUeNgapId, authCtxId)
    SET (nausf_auth_ueAuth.uri, "/nausf-auth/v1/ue-authentications/" + cntxId + "/5g-aka-confirmation")

    #SET (nausf_auth_ueAuth.body.supiOrSuci, "404000000000000")
    LOOKUP (suciTemp, UeContextMap, amfUeNgapId, suci)
    SET (nausf_auth_ueAuth.body.supiOrSuci,suciTemp)
    LOOKUP (resStar, UeContextMap, amfUeNgapId, resStar)

    UDF (status1, hexCopyToStrings, hexS, resStar, 16)

    SET (nausf_auth_ueAuth.body.resStar, hexS)
    STORE (UeContextMap, amfUeNgapId, state, "ueAuthenticationUpdate")
    LOOKUP (ausf_ip, globalContextMap, NULL, ausf_ip)
    ENCODE(encodeHTTP, nausf_auth_ueAuth_enc, nausf_auth_ueAuth, nausf_auth_ueAuth_enc_sz)
    #SEND (nausf_auth_ueAuth, ausf_ip, AMF, AUSF, nausf_auth_ueAuth_sz, Nausf, amfUeNgapId, sbiIncoming)

EVENT ueAuthenticationUpdateResponse (messageBody)
    GET_KEY(amfUeNgapId)
    STORE (UeContextMap, amfUeNgapId, supi, messageBody.supi)
    STORE (SupiAmfUeNgapIdMap, messageBody.supi, amfUeNgapId, amfUeNgapId)
    CALL (NasSecurityModeCommand, amfUeNgapId)

EVENT NasSecurityModeCommand (amfUeNgapId)

    CREATE_MESSAGE (nas_m, nasMessage_t)
    CREATE_MESSAGE (secMC_m, SecurityModeCommand_t)

    SET (secMC_m.mmHeader.epd, MACRO(_5GS_MOBILITY_MANAGEMENT_MESSAGE))
    SET (secMC_m.mmHeader.secuHeader, MACRO(SECURITY_HEADER_TYPE_NOT_PROTECTED))
    SET (secMC_m.mmHeader.msgType, MACRO(SECURITY_MODE_COMMAND))

    CREATE_MESSAGE (secCtxt, secContext_t)

    SET (secMC_m.nasSecurityAlgorithm.encryptionAlgo, secCtxt.secAlgo.nasEncAlgo)
    SET (secMC_m.nasSecurityAlgorithm.integrityAlgo, secCtxt.secAlgo.nasIntAlgo)
    SET (secMC_m.ueSecuCapability.len, MACRO(UE_SECURITY_CAPABILITY_NAS_AS_LEN))
    LOOKUP (ueSecurityCapability, UeContextMap, amfUeNgapId, ueSecurityCapability)
    SET (secMC_m.ueSecuCapability._5gNASIntAlgo, ueSecurityCapability._5gNASIntAlgo)
    SET (secMC_m.ueSecuCapability._5gNASEncAlgo, ueSecurityCapability._5gNASEncAlgo)
    LOOKUP (ngKSI, UeContextMap, amfUeNgapId, ngKsi)
    SET (secMC_m.ngKsi, ngKSI)

    SET (nas_m.plain._5gmmMsg.secModeCmdMsg, secMC_m)


    # NGAP Message

    CREATE_MESSAGE (ngapPdu_m, NGAP_PDU_t)
    CREATE_MESSAGE (iniMsg_m, InitiatingMessage_t)
    CREATE_MESSAGE (dln_m, DownlinkNASTransport_t)

    SET (ngapPdu_m.present, MACRO(NGAP_PDU_PR_initiatingMessage))
    SET (ngapPdu_m.choice.initiatingMessage, iniMsg_m)

    SET (iniMsg_m.procedureCode, MACRO(ProcedureCode_id_DownlinkNASTransport))
    SET (iniMsg_m.criticality, MACRO(Criticality_ignore))
    SET (iniMsg_m.value.present, MACRO(InitiatingMessage__value_PR_DownlinkNASTransport))

    CREATE_MESSAGE (amfid, DownlinkNASTransport_IEs_t)

    SET (amfid.id, MACRO(ProtocolIE_ID_id_AMF_UE_NGAP_ID))
    SET (amfid.criticality, MACRO(Criticality_reject))
    SET (amfid.value.present, MACRO(DownlinkNASTransport_IEs__value_PR_AMF_UE_NGAP_ID))
    UDF (status3, asn_ulong2INTEGER, amfid.value.choice.AMF_UE_NGAP_ID, amfUeNgapId) 

    APPEND (dln_m, amfid)

    CREATE_MESSAGE (ranid, DownlinkNASTransport_IEs_t)

    SET (ranid.id, MACRO(ProtocolIE_ID_id_RAN_UE_NGAP_ID))
    SET (ranid.criticality, MACRO(Criticality_reject))
    SET (ranid.value.present, MACRO(DownlinkNASTransport_IEs__value_PR_RAN_UE_NGAP_ID))
    LOOKUP (ranUeId, UeContextMap, amfUeNgapId, ranUeNgapId)
    SET (ranid.value.choice.RAN_UE_NGAP_ID, ranUeId) 

    APPEND (dln_m, ranid)

    CREATE_MESSAGE (amfName, DownlinkNASTransport_IEs_t)

    SET (amfName.id, MACRO(ProtocolIE_ID_id_OldAMF))
    SET (amfName.criticality, MACRO(Criticality_reject))
    SET (amfName.value.present, MACRO(DownlinkNASTransport_IEs__value_PR_AMFName))
    READ_CONFIG(amfConfig,"amfconfig.json")

    # lhs: reduces to octet string, rhs: char buf, i.e. string from amfconfig
    UDF(amf_config_amfname, toOctetString, amfConfig.AMFName) # call to OCTET_STRING_fromBuf
    
    SET (amfName.value.choice.AMFName, amf_config_amfname) # in k_set: if lhstype red to octet


    APPEND (dln_m, amfName)

    CREATE_MESSAGE (naspdu, DownlinkNASTransport_IEs_t)

    SET (naspdu.id, MACRO(ProtocolIE_ID_id_NAS_PDU))
    SET (naspdu.criticality, MACRO(Criticality_reject))
    SET (naspdu.value.present, MACRO(DownlinkNASTransport_IEs__value_PR_NAS_PDU))
    #SET (naspdu.value.choice.NAS_PDU, nas_m)

    UDF(nas_octet_string, nasMessagetoOctetString, nas_m, secCtxt) 
    SET (naspdu.value.choice.NAS_PDU, nas_octet_string) # lhs must reduce to rhs type else error.
    

    APPEND (dln_m, naspdu)

    SET (iniMsg_m.value.choice.DownlinkNASTransport, dln_m)

    ENCODE(encodeNgap, ngapPdu_m_enc, ngapPdu_m, ngapPdu_m_enc_sz)
    #SEND(response, "127.0.0.1", AMF, RAN, N2, ngapPdu_m_enc_sz, amfUeNgapId, NULL)


EVENT NasSecurityInitiationResponse(messageBody, nasMsg)
    UDF (status, ngapGetAmfUeNgapId, _amfUeNgapId, messageBody)
    UDF (status1, asn_INTEGER2ulong, amfUeNgapId, _amfUeNgapId)
    CALL (initialContextSetup, amfUeNgapId)

EVENT initialContextSetup (amfUeNgapId)

    #what to put in NAS message (regAccept?)
    CREATE_MESSAGE (nas_m, nasMessage_t)
    CREATE_MESSAGE (regAcpt_m, RegistrationAcceptMsg_t)

    SET (regAcpt_m.mmHeader.epd, MACRO(_5GS_MOBILITY_MANAGEMENT_MESSAGE))
    SET (regAcpt_m.mmHeader.secuHeader, MACRO(SECURITY_HEADER_TYPE_NOT_PROTECTED))
    SET (regAcpt_m.mmHeader.msgType, MACRO(REGISTRATION_ACCEPT))
    SET (regAcpt_m._5gregResult.len, MACRO(REG_RESULT_SIZE))
    SET (regAcpt_m._5gregResult.smsAllowed, MACRO(SMS_NOT_SUPPORTED))
    CREATE_MESSAGE(_secCtxt, secContext_t)

    #accesstype??
    SET (regAcpt_m._5gregResult.value, MACRO(E_3GPP_ACCESS))

    SET (regAcpt_m._5gmobileId.len, MACRO(GUTI_LENGTH))
    SET (regAcpt_m._5gmobileId.guti5gMobileId, UDF(generateGuti))

    SET (regAcpt_m.presenceMask, 0)

    SET (nas_m.plain._5gmmMsg.regAcceptMsg,regAcpt_m)

    # NGAP Message

    CREATE_MESSAGE (ngapPdu_m, NGAP_PDU_t)
    CREATE_MESSAGE (iniMsg_m, InitiatingMessage_t)
    CREATE_MESSAGE (icr_m, InitialContextSetupRequest_t)

    SET (ngapPdu_m.present, MACRO(NGAP_PDU_PR_initiatingMessage))
    SET (ngapPdu_m.choice.initiatingMessage, iniMsg_m)

    SET (iniMsg_m.procedureCode, MACRO(ProcedureCode_id_InitialContextSetup))
    SET (iniMsg_m.criticality, MACRO(Criticality_reject))
    SET (iniMsg_m.value.present, MACRO(InitiatingMessage__value_PR_InitialContextSetupRequest))

    CREATE_MESSAGE (amfid, InitialContextSetupRequestIEs_t)

    SET (amfid.id, MACRO(ProtocolIE_ID_id_AMF_UE_NGAP_ID))
    SET (amfid.criticality, MACRO(Criticality_reject))
    SET (amfid.value.present, MACRO(InitialContextSetupRequestIEs__value_PR_AMF_UE_NGAP_ID))
    UDF (status3, asn_ulong2INTEGER, amfid.value.choice.AMF_UE_NGAP_ID, amfUeNgapId) 

    APPEND (icr_m, amfid)

    CREATE_MESSAGE (ranid, InitialContextSetupRequestIEs_t)

    SET (ranid.id, MACRO(ProtocolIE_ID_id_RAN_UE_NGAP_ID))
    SET (ranid.criticality, MACRO(Criticality_reject))
    SET (ranid.value.present, MACRO(InitialContextSetupRequestIEs__value_PR_RAN_UE_NGAP_ID))
    LOOKUP (ranUeId, UeContextMap, amfUeNgapId, ranUeNgapId)
    SET (ranid.value.choice.RAN_UE_NGAP_ID, ranUeId) 

    APPEND (icr_m, ranid)

    CREATE_MESSAGE (amfName, InitialContextSetupRequestIEs_t)

    SET (amfName.id, MACRO(ProtocolIE_ID_id_OldAMF))
    SET (amfName.criticality, MACRO(Criticality_reject))
    SET (amfName.value.present, MACRO(InitialContextSetupRequestIEs__value_PR_AMFName))
    READ_CONFIG(amfConfig,"amfconfig.json")

    # lhs: reduces to octet string, rhs: char buf, i.e. string from amfconfig
    UDF(amf_config_amfname, toOctetString, amfConfig.AMFName) # call to OCTET_STRING_fromBuf
    
    SET (amfName.value.choice.AMFName, amf_config_amfname) # in k_set: if lhstype red to octet

    APPEND (icr_m, amfName)

    CREATE_MESSAGE (guami, InitialContextSetupRequestIEs_t)

    SET (guami.id, MACRO(ProtocolIE_ID_id_GUAMI))
    SET (guami.criticality, MACRO(Criticality_reject))
    SET (guami.value.present, MACRO(InitialContextSetupRequestIEs__value_PR_GUAMI))
    SET (guami.value.choice.GUAMI, UDF (generateGuami))

    APPEND (icr_m, guami)

    CREATE_MESSAGE (alnssai, InitialContextSetupRequestIEs_t)

    SET (alnssai.id, MACRO(ProtocolIE_ID_id_AllowedNSSAI))
    SET (alnssai.criticality, MACRO(Criticality_reject))
    SET (alnssai.value.present, MACRO(InitialContextSetupRequestIEs__value_PR_AllowedNSSAI))

    CREATE_MESSAGE(alnssai_IEs, AllowedNSSAI_t) 
    CREATE_MESSAGE (alnssai_item, AllowedNSSAI_Item_t(2))

    LOOP (itr,0,2) 
        CREATE_MESSAGE (snssai, S_NSSAI_t)
        CREATE_MESSAGE (sst,char, 1)
        #CREATE_MESSAGE (sd,char, 3)
        
        SET(sst[0], amfConfig.amf-s-nssai-list.amf-nssai[itr].snssai.sst)
        #SET(sd[0], amfConfig.amf-s-nssai-list.amf-nssai[itr].snssai.sst)
        #SET(sd[1], amfConfig.amf-s-nssai-list.amf-nssai[itr].snssai.sst)
        #SET(sd[2], amfConfig.amf-s-nssai-list.amf-nssai[itr].snssai.sst)

        UDF (stat1,OCTET_STRING_fromBuf,snssai.sST, sst, 1)
        #SET(snssai.sD,sd)

        SET(alnssai_item[itr].s_NSSAI, snssai)
        APPEND(alnssai_IEs, alnssai_item[itr])

    SET (alnssai.value.choice.AllowedNSSAI, alnssai_IEs)

    APPEND (icr_m, alnssai)

    #uESecurityCapabilities

    CREATE_MESSAGE(ueSecCap, InitialContextSetupRequestIEs_t) 

    SET (ueSecCap.id, MACRO(ProtocolIE_ID_id_UESecurityCapabilities))
    SET (ueSecCap.criticality, MACRO(Criticality_reject))
    SET (ueSecCap.value.present, MACRO(InitialContextSetupRequestIEs__value_PR_UESecurityCapabilities))

    CREATE_MESSAGE (ueSec, UESecurityCapabilities_t)

    UDF (rc1, BIT_STRING_fromNum,ueSec.nRencryptionAlgorithms, 0, 16)
    UDF (rc2, BIT_STRING_fromNum,ueSec.nRintegrityProtectionAlgorithms, 0, 16)
    UDF (rc3, BIT_STRING_fromNum,ueSec.eUTRAencryptionAlgorithms, 0, 16)
    UDF (rc4, BIT_STRING_fromNum,ueSec.eUTRAintegrityProtectionAlgorithms, 0, 16)

    SET (ueSecCap.value.choice.UESecurityCapabilities, ueSec)

    APPEND (icr_m, ueSecCap)

    #securityKey

    CREATE_MESSAGE(secKey, InitialContextSetupRequestIEs_t) 

    SET (secKey.id, MACRO(ProtocolIE_ID_id_SecurityKey))
    SET (secKey.criticality, MACRO(Criticality_reject))
    SET (secKey.value.present, MACRO(InitialContextSetupRequestIEs__value_PR_SecurityKey))

    CREATE_MESSAGE (secKeyBuf,char, 256)

    UDF (rc, BIT_STRING_fromBuf, secKey.value.choice.SecurityKey,secKeyBuf, 256)

    APPEND (icr_m, secKey)

    CREATE_MESSAGE (naspdu, InitialContextSetupRequestIEs_t)

    SET (naspdu.id, MACRO(ProtocolIE_ID_id_NAS_PDU))
    SET (naspdu.criticality, MACRO(Criticality_reject))
    SET (naspdu.value.present, MACRO(InitialContextSetupRequestIEs__value_PR_NAS_PDU))
    # SET (naspdu.value.choice.NAS_PDU, nas_m)
    UDF(nas_octet_string, nasMessagetoOctetString, nas_m, _secCtxt) 
    SET (naspdu.value.choice.NAS_PDU, nas_octet_string) # lhs must reduce to rhs type else error.

    APPEND (icr_m, naspdu)

    SET (iniMsg_m.value.choice.InitialContextSetupRequest, icr_m)

    ENCODE(encodeNgap, ngapPdu_m_enc, ngapPdu_m, ngapPdu_m_enc_sz)
    #SEND(response, "127.0.0.1", AMF, RAN, N2, amfUeNgapId, NULL)
    
EVENT initialContextSetupResponse(messageBody)
    
    UDF (status, ngapGetAmfUeNgapId, _amfUeNgapId, messageBody)
    UDF (status1, asn_INTEGER2ulong, amfUeNgapId, _amfUeNgapId)

    CALL (udmSelection, amfUeNgapId)


##############################################################################################################
#                                        Authentication Complete
##############################################################################################################


EVENT udmSelection (amfUeNgapId)
    LOOKUP (udm_ip, globalContextMap, NULL, udm_ip)

    IF (udm_ip == "")
        CREATE_MESSAGE (nnrf_disc, HttpRequest)
        SET (nnrf_disc.method, MACRO(GET))
        SET (nnrf_disc.version, MACRO(HTTP_2_0))
        SET (nnrf_disc.uri, "/nnrf-disc/v1/nf-instances")
        SET (nnrf_disc.queryParams.target-nf-type, "UDM")
        SET (nnrf_disc.queryParams.requester-nf-type, "AMF")
        SET (nnrf_disc.queryParams.service-names, "nudm-uecm")
        STORE (UeContextMap, amfUeNgapId, state, "nrfDiscovery")
        ENCODE (encodeHTTP, nnrf_disc_enc, nnrf_disc, nnrf_disc_enc_sz)
        SEND (request, "127.0.0.1", AMF, NRF, Nnrf, nnrf_disc_enc_sz, amfUeNgapId, sbiIncoming)
    ELSE
        CALL (uecmRegistration, amfUeNgapId)

EVENT uecmRegistration (amfUeNgapId)
    CREATE_MESSAGE (nudm_uecm_reg, HttpRequest)
    SET (nudm_uecm_reg.method, MACRO(PUT))
    SET (nudm_uecm_reg.version, MACRO(HTTP_2_0))
    LOOKUP (suci, UeContextMap, amfUeNgapId, suci)
    SET (nudm_uecm_reg.uri, "/nudm-uecm/v1/" + suci + "/registrations/amf-3gpp-access")

    READ_CONFIG(amfConfig,"amfconfig.json")

    SET (nudm_uecm_reg.body.amfInstanceId, amfConfig.amf-id)
    SET (nudm_uecm_reg.body.deregCallbackUri, "http://127.0.0.1:80/")
    SET (nudm_uecm_reg.body.guami.amfId, "amf1")
    SET (nudm_uecm_reg.body.guami.plmnId.mcc, amfConfig.guamiAndGutiInfo.plmn-mcc)
    SET (nudm_uecm_reg.body.guami.plmnId.mnc, amfConfig.guamiAndGutiInfo.plmn-mnc)
    SET (nudm_uecm_reg.body.ratType, "NR")
    
    STORE (UeContextMap, amfUeNgapId, state, "uecmRegistration")
    LOOKUP (udm_ip, globalContextMap, NULL, udm_ip)
    ENCODE(encodeHTTP, nudm_uecm_reg_enc, nudm_uecm_reg, nudm_uecm_reg_enc_sz)
    #SEND (request, udm_ip, AMF, UDM, nudm_uecm_reg_enc_sz, Nudm, amfUeNgapId, sbiIncoming)   


EVENT uecmRegistrationResponse(messageBody)
    # Nothing is done using this message

    GET_KEY (amfUeNgapId)

    CALL (udmSDMGet, amfUeNgapId)


EVENT udmSDMGet (amfUeNgapId)
    CREATE_MESSAGE (nudm_sdm_get, HttpRequest)
    SET (nudm_sdm_get.method, MACRO(GET))
    SET (nudm_sdm_get.version, MACRO(HTTP_2_0))
    LOOKUP (suci, UeContextMap, amfUeNgapId, suci)
    SET (nudm_sdm_get.uri, "/nudm-sdm/v1/" + suci + "/nssai")

    SET (nudm_sdm_get.queryParams.plmn-id, "40400")

    STORE (UeContextMap, amfUeNgapId, state, "udmSDMGet")
    LOOKUP (udm_ip, globalContextMap, NULL, udm_ip)
    ENCODE(encodeHTTP, nudm_sdm_get_enc,nudm_sdm_get,nudm_sdm_get_enc_sz)
    #SEND (request, udm_ip, AMF, UDM, nudm_sdm_get_enc_sz, Nudm, amfUeNgapId, sbiIncoming)

EVENT udmSDMGetResponse(messageBody)
    
    GET_KEY (amfUeNgapId)
    LOOKUP (reqNssai, UeContextMap, amfUeNgapId, requestedNssai)

    CREATE_MESSAGE (allowNSSAI, nssai_t)
    CREATE_MESSAGE (rejNssai, rejectedNssai_t)

    IF (reqNssai.no_of_slices > 0)
        CREATE_MESSAGE (extractedNssais, nssai_t)

        LOOP (itr, 0, messageBody.singleNssais.size())
            CREATE_MESSAGE (subSlice, s_nssai_t)
            SET (subSlice.sST,  messageBody.singleNssais[itr].sst)
            SET (subSlice.sD,  messageBody.singleNssais[itr].sd)
            #CREATE_MESSAGE (num1, uint8_t)
            SET (num1, extractedNssais.no_of_slices)
            UDF (stat52, increment, num1, 1)
            SET (extractedNssais.Nssai[num1], subSlice)

        #CREATE_MESSAGE (subscribedSlice, bool)
        SET (subscribedSlice, false)

        LOOP (slice, 0, reqNssai.no_of_slices)
            LOOP (i, 0, extractedNssais.no_of_slices)
                IF (reqNssai.Nssai[slice].len_s_nssai == extractedNssais.Nssai[i].len_s_nssai && reqNssai.Nssai[slice].sST == extractedNssais.Nssai[i].sST && reqNssai.Nssai[slice].sD == extractedNssais.Nssai[i].sD)
                    SET (subscribedSlice, true)
                    BREAK()
                
                IF (subscribedSlice == false)
                    #CREATE_MESSAGE (num, uint8_t)
                    SET (num, rejNssai.no_of_slices)
                    SET (rejNssai.Nssai[num].len_s_nssai, reqNssai.Nssai[slice].len_s_nssai)
                    SET (rejNssai.Nssai[num].reject_cause, MACRO(CAUSE_S_NSSAI_NA_FOR_PLMN))
                    SET (rejNssai.Nssai[num].sST, reqNssai.Nssai[slice].sST)
                    SET (rejNssai.Nssai[num].sD, reqNssai.Nssai[slice].sD)
                    UDF (stat12, increment, num, 1)
                    CONTINUE()

            #CREATE_MESSAGE (amfSupport, bool)
            SET (amfSupport, false)

            READ_CONFIG(amfConfig, "amfconfig.json")

            LOOP (i, 0, 2)
                IF (reqNssai.Nssai[slice].sST == amfConfig.amf-s-nssai-list.amf-nssai[i].sst && reqNssai.Nssai[slice].sD == amfConfig.amf-s-nssai-list.amf-nssai[i].SD)
                    SET (amfSupport, true)
                    BREAK()
            
            IF (amfSupport == true)
                #CREATE_MESSAGE (num, uint8_t)
                SET (num, allowNSSAI.no_of_slices)
                SET (allowNSSAI.Nssai[num].len_s_nssai, reqNssai.Nssai[slice].len_s_nssai)
                SET (allowNSSAI.Nssai[num].sST, reqNssai.Nssai[slice].sST)
                SET (allowNSSAI.Nssai[num].sD, reqNssai.Nssai[slice].sD)
                UDF (stat11, increment, num, 1)
                CONTINUE()

    IF (allowNSSAI.no_of_slices > 0)
        STORE (UeContextMap, amfUeNgapId, allowedNssai, allowNSSAI)

    IF (rejNssai.no_of_slices > 0)
        STORE (UeContextMap, amfUeNgapId, rejectedNssai, rejNssai)

    CALL (registrationAccept, amfUeNgapId)


EVENT registrationAccept (amfUeNgapId)

    CREATE_MESSAGE (nas_m, nasMessage_t)
    CREATE_MESSAGE (regAcpt_m, RegistrationAcceptMsg_t)

    SET (regAcpt_m.mmHeader.epd, MACRO(_5GS_MOBILITY_MANAGEMENT_MESSAGE))
    SET (regAcpt_m.mmHeader.secuHeader, MACRO(SECURITY_HEADER_TYPE_NOT_PROTECTED))
    SET (regAcpt_m.mmHeader.msgType, MACRO(REGISTRATION_ACCEPT))
    SET (regAcpt_m._5gregResult.len, MACRO(REG_RESULT_SIZE))
    SET (regAcpt_m.presenceMask, 0)
    SET (regAcpt_m._5gregResult.smsAllowed, MACRO(SMS_NOT_SUPPORTED))

    #get guti from context
    SET (regAcpt_m._5gmobileId.len, MACRO(GUTI_LENGTH))
    SET (regAcpt_m._5gmobileId.guti5gMobileId, UDF (generateGuti))

    CREATE_MESSAGE (secCtxt, secContext_t)

    SET (regAcpt_m.presenceMask, regAcpt_m.presenceMask | MACRO(REGISTRATION_ACCEPT_REJ_NSSAI_PRESENT))
    
    #set no_of_slices from context

    SET (regAcpt_m.allowedNssai.no_of_slices, 1)
    SET (regAcpt_m.rejectedNssai.no_of_slices, 1)
    SET (regAcpt_m.rejectedNssai.Nssai[0].len_s_nssai, MACRO(LEN_SST_AND_SD))

    #CREATE_MESSAGE (_rejectedNssai, rejectedNssai_t)
    #SET (regAcpt_m.rejectedNssai.Nssai[0].reject_cause, _rejectedNssai.Nssai[0].reject_cause)
    #SET (regAcpt_m.rejectedNssai.Nssai[0].sST, _rejectedNssai.Nssai[0].sST)
    #SET (regAcpt_m.rejectedNssai.Nssai[0].sD, _rejectedNssai.Nssai[0].sD)

    SET (nas_m.plain._5gmmMsg.regAcceptMsg, regAcpt_m)


    # NGAP Message #Downlink Nas Transport

    CREATE_MESSAGE (ngapPdu_m, NGAP_PDU_t)
    CREATE_MESSAGE (iniMsg_m, InitiatingMessage_t)
    CREATE_MESSAGE (dln_m, DownlinkNASTransport_t)

    SET (ngapPdu_m.present, MACRO(NGAP_PDU_PR_initiatingMessage))
    SET (ngapPdu_m.choice.initiatingMessage, iniMsg_m)

    SET (iniMsg_m.procedureCode, MACRO(ProcedureCode_id_DownlinkNASTransport))
    SET (iniMsg_m.criticality, MACRO(Criticality_ignore))
    SET (iniMsg_m.value.present, MACRO(InitiatingMessage__value_PR_DownlinkNASTransport))

    CREATE_MESSAGE (amfid, DownlinkNASTransport_IEs_t)

    SET (amfid.id, MACRO(ProtocolIE_ID_id_AMF_UE_NGAP_ID))
    SET (amfid.criticality, MACRO(Criticality_reject))
    SET (amfid.value.present, MACRO(DownlinkNASTransport_IEs__value_PR_AMF_UE_NGAP_ID))
    UDF (status3, asn_ulong2INTEGER, amfid.value.choice.AMF_UE_NGAP_ID, amfUeNgapId) 

    APPEND (dln_m, amfid)

    CREATE_MESSAGE (ranid, DownlinkNASTransport_IEs_t)

    SET (ranid.id, MACRO(ProtocolIE_ID_id_RAN_UE_NGAP_ID))
    SET (ranid.criticality, MACRO(Criticality_reject))
    SET (ranid.value.present, MACRO(DownlinkNASTransport_IEs__value_PR_RAN_UE_NGAP_ID))
    LOOKUP (t1, UeContextMap, amfUeNgapId, ranUeNgapId)
    SET (ranid.value.choice.RAN_UE_NGAP_ID, t1) 

    APPEND (dln_m, ranid)

    CREATE_MESSAGE (amfName, DownlinkNASTransport_IEs_t)

    SET (amfName.id, MACRO(ProtocolIE_ID_id_OldAMF))
    SET (amfName.criticality, MACRO(Criticality_reject))
    SET (amfName.value.present, MACRO(DownlinkNASTransport_IEs__value_PR_AMFName))
    READ_CONFIG(amfConfig,"amfconfig.json")
    # lhs: reduces to octet string, rhs: char buf, i.e. string from amfconfig
    UDF(amf_config_amfname, toOctetString, amfConfig.AMFName) # call to OCTET_STRING_fromBuf
    
    SET (amfName.value.choice.AMFName, amf_config_amfname) # in k_set: if lhstype red to octet


    APPEND (dln_m, amfName)

    CREATE_MESSAGE (naspdu, DownlinkNASTransport_IEs_t)

    SET (naspdu.id, MACRO(ProtocolIE_ID_id_NAS_PDU))
    SET (naspdu.criticality, MACRO(Criticality_reject))
    SET (naspdu.value.present, MACRO(DownlinkNASTransport_IEs__value_PR_NAS_PDU))
    # SET (naspdu.value.choice.NAS_PDU, nas_m)
    UDF(nas_octet_string, nasMessagetoOctetString, nas_m, secCtxt) 
    SET (naspdu.value.choice.NAS_PDU, nas_octet_string) # lhs must reduce to rhs type else error.

    APPEND (dln_m, naspdu)

    SET (iniMsg_m.value.choice.DownlinkNASTransport, dln_m)

    ENCODE(encodeNgap, ngapPdu_m_enc, ngapPdu_m, ngapPdu_m_enc_sz)
    #SEND(ngapPdu_m, "127.0.0.1", AMF, RAN, ngapPdu_m_enc_sz, N2, amfUeNgapId, NULL)


EVENT registrationAcceptResponse(messageBody, nasMsg)
    
    UDF (status, ngapGetAmfUeNgapId, _amfUeNgapId, messageBody)
    UDF (status1, asn_INTEGER2ulong, amfUeNgapId, _amfUeNgapId)
    # This should be state change
    STORE (UeContextMap, amfUeNgapId, isSuccess, true)


