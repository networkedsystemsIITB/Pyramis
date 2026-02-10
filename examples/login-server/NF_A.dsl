EVENT do_echo(message_body):
    ENCODE(SynerPMessageEncode, message_body_enc, message_body, message_body_enc_sz)
    SEND(message_body_enc, ia0, NF_B, ib0) # sendingNFInterface to generate protocol

EVENT ia0_server_entry(message): 
    DECODE(SynerPMessageDecode, m, message)
    SET(userCMD, m.header.cmd) 
    SET(userID, m.uname.contents)

    UDF(procedure_key, generate_procedure_key)

    IF (userCMD == MACRO(ECHO)):
        CALL(do_echo, m)
    ELSE:
        IF(userCMD == MACRO(LOGIN_REQUEST)):
            CALL(do_login, userID, procedure_key)

EVENT do_login(userID, procedure_key):    
    LOOKUP(login_status, user_login_map, userID, login_status) 
    
    IF(login_status): 
        TIMER_STOP(MACRO(T_LOGIN_FORGET)) 
        
        CREATE_MESSAGE(simple, SynerPMessage_t)
        SET (simple.header.cmd, MACRO(LOGIN_RESPONSE))
        
        UDF(login_response, generate_login_response, MACRO(USER_EXIST))

        SET(simple.uname.contents, userID)
        SET(simple.uname.sz, userID.size())

        SET(simple.data.contents, login_response)
        SET(simple.data.sz, login_response.size())

        ENCODE(SynerPMessageEncode, simple_enc, simple, simple_enc_sz)
        SEND(simple_enc, ia0, NF_B, ib0) 

        CREATE_TIMER_CONTEXT(t1, MACRO(T_LOGIN_FORGET))

        SET(t1.user_id, userID)

        TIMER_START(MACRO(T_LOGIN_FORGET), 5, t1, forget_user)

        SET_KEY(procedure_key)
    ELSE:
        SET_KEY(procedure_key)
        STORE(user_login_map, userID, login_status, true)
        
        CREATE_TIMER_CONTEXT(t2, MACRO(T_LOGIN_FORGET))
        SET(t2.my_var, true)

        TIMER_START(MACRO(T_LOGIN_FORGET), 5, t2, forget_user) 
        
        CREATE_MESSAGE(simple, SynerPMessage_t)
        SET(simple.header.cmd, MACRO(LOGIN_RESPONSE))
        
        UDF(login_response, generate_login_response, MACRO(USER_NEW))
        
        ENCODE(SynerPMessageEncode, simple_enc, simple, simple_enc_sz)

        SEND(simple_enc, ia0, NF_B, ib0)

EVENT forget_user(timer_ctx):
    SET(user_id, timer_ctx.user_id) 
    STORE(user_login_map, user_id, login_status, false) 
    
    # Send notification back to client.
    CREATE_MESSAGE(simple, SynerPMessage_t)

    SET (simple.header.cmd, MACRO(TIMER_NOTIFICATION))

    # get timer_id type
    SET(timer_id, MACRO(T_LOGIN_FORGET))
    UDF(timer_expiry_response, generate_timer_response, user_id, timer_id, MACRO(USER_TIMER_EXPIRY))

    SET(simple.data.contents, timer_expiry_response)
    SET(simple.data.sz, timer_expiry_response.size())

    ENCODE(SynerPMessageEncode, simple_enc, simple, simple_enc_sz)
    SEND(simple_enc, ia0, NF_B, ib0)
    
    TIMER_STOP(MACRO(T_LOGIN_FORGET))
