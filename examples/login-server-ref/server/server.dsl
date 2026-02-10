EVENT server_entry(message): # called from platform file.
    DECODE(SynerPMessageDecode, m, message, m_enc_sz)
    SET(userCMD, m.header.cmd) 
    SET(userID, m.uname.contents) # contents is an array -> 

    IF (userCMD == MACRO(ECHO)):
        CALL(do_echo, m)
    ELIF (userCMD == MACRO(LOGIN_REQUEST)):
        UDF(generate_procedure_key, procedure_key)
        CALL(do_login, userID, procedure_key)

EVENT do_echo(message_body):
    ENCODE(SynerPMessageEncoder, message_body_enc, message_body, message_body_enc_sz)
    SEND(message_body, Server, Client, _)
        
EVENT do_login(userID, procedure_key):    
    LOOKUP(login_status, client_login_map, userID, status) # search for key userID in vector. optional 4th argument if the value at key is a struct.
    IF (login_status):
        TIMER_STOP(T_FORGET, userID)
        GET_KEY(procedure_key) # procedure_key = fdtokeymap[sockfd]
        
        CREATE_MESSAGE(SynerPMessage_t, simple)
        SET(simple.header.cmd, MACRO(LOGIN_RESPONSE))
        
        UDF(login_response, procedure_key, generate_login_response, userID, EXIST);
        SET(simple.data.contents, login_response)

        TIMER_START(T_LOGIN_FORGET, 5, forget_user)

        ENCODE(SynerPMessageEncoder, simple_enc, simple, simple_enc_sz)
        SEND(simple, Server, Client, _)
    ELSE:
        # new procedure instance
        UDF(procedure_key, generate_procedure_instance_key)
        
        SET_KEY(procedure_key) # keytofdmap[proc_inst] = sockfd
        
        STORE(user_login_map, userID, login_status, false)
        
        TIMER_START(procedure_key, T_LOGIN_FORGET, 5, forget_user) # start the T_FORGET timer for user userID for 5 seconds.
        
        CREATE_MESSAGE(SynerPMessage_t, simple)
        SET(simple.cmd, MACRO(LOGIN_RESPONSE))
        
        UDF(login_response, generate_login_response, userID, NOEXIST);
        
        ENCODE(SynerPMessageEncoder, simple_enc, simple, simple_enc_sz)
        SEND(simple, <sendingInterface>, <peerNFname>, <callbackname>)

//@@timer
EVENT forget_user(user_id, timer_id): -> void forget_user(timer_expiry_struct_t timer_ctx, struct nfvInstanceData *nfvInst)
    STORE(user_login_map, user_id, login_status, false) // get userID type
    
    # Send notification back to client.
    CREATE_MESSAGE(SynerPMessage_t, simple)

    SET(simple.cmd, MACRO(TIMER_NOTIFICATION))

    UDF(timer_expiry_response, generate_timer_response, user_id, timer_id, USER_TIMER_EXPIRY) // get timer_id type
    SET(simple.data.contents, timer_response)

    // args used to identify a timer
    // -> generic_timer_stop(_e_TimerType timer_id, std::string user_id)
    TIMER_STOP(T_LOGIN_FORGET, user_id) 

    GET_KEY(procedure_key) # procedure_inst = fdtokeymap[sockfd]
    ENCODE(SynerPMessageEncoder, simple_enc, simple, simple_enc_sz)
    SEND(simple, <sendingInterface>, <peerNFname>, <callbackname>)

//@@timer
EVENT misc_timer2(timer_ctx):

