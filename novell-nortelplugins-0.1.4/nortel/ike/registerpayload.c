/*
 * Copyright (C) 2005-2009 Novell, Inc.
 * 
 * All rights reserved.
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, contact Novell, Inc.
 * 
 * To contact Novell about this file by physical or electronic mail,
 * you may find current contact information at www.novell.com.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdint.h>

/* My headers */
#include "utility.h"
#include "nortel_vmbuf.h"
#include "nortel_inf.h"
#include "callbacks.h"
#include "registerpayload.h"

/* Racoon Headers */
#include "racoon/vmbuf.h"
#include "racoon/isakmp_var.h"
#include "racoon/isakmp.h"
#include "racoon/ipsec_doi.h"

#include <linux/pfkeyv2.h>

#if 0
int constructHookPoint(struct hookpoint *hook, u_int8_t type, u_int8_t AttrOrPayloadType, u_int8_t AttrOrPayloadSubType, u_int32_t position, u_int8_t mandatoryOrOptional, u_int32_t keylen, void *key)
{
    hook->Type = type;
    hook->AttrOrPayloadType = AttrOrPayloadType  ;
    hook->AttrOrPayloadSubType = AttrOrPayloadSubType;
    hook->position = position;
    hook->mandatoryOrOptional = mandatoryOrOptional; //Mandatory.    
    hook->keylen = keylen;
    hook->key = key;
    return 0;
    
}

int constructHandlerInfo( struct handlerinfo *hi, u_int32_t DataTypeToBeSent, u_int32_t DataTypeToBeRecvd, CALLBACK callback)
{
    hi->hprivdata = NULL;
    hi->DataTypeToBeSent = DataTypeToBeSent;
    hi->DataTypeToBeRecvd = DataTypeToBeRecvd;
    hi->callback = callback; 
    return 0;
    
}
#endif

int registerThis(struct hookpoint *hp, struct handlerinfo *hi)
{
    hi->plugin_name = (char *) malloc(strlen(PLUGINNAME) + 1);
    
    if(!(hi->plugin_name))
        return -1;

    memcpy(hi->plugin_name, PLUGINNAME, strlen(PLUGINNAME) + 1 );
    
    if(tpike_register_handler(hp, hi)<0){
        return -1;    
    } 
    return 0;
}

int registerQMStartCallback(){
    //QM Start reqd
    struct hookpoint hook = {'\0'};
    struct handlerinfo hi = {'\0'};
//    struct hookpoint hookptr =&hook;

    u_int32_t position = 0;
    
    
    position = constructPosition( 
                                  ISAKMP_ETYPE_QUICK, /* Mode */
                                  TPIKE_MIDX_RESPONDER, /* Side */
                                  TPIKE_MIDX_RECEIVE, /* Direction */
                                  1, /* msg index */ 
                                  0xff, /* k1 - any */
                                  0xff  /* k2 */
                                  );
    constructHookPoint(
                       &hook, /* Hook */
                       IKE_NEGO_STATE_TYPE, /* Type */
                       ISAKMP_NPTYPE_NONE, /* PayloadOrAttrType */
                       ISAKMP_NPTYPE_NONE, /* PayloadOrAttrSubType */
                       position, /*Position */
                       1, /*Mandatory/Optional */
                       0, /*keylen*/
                       NULL /*KEY*/
                       );
                       
    constructHandlerInfo( 
                          &hi,                  /* handlerinfo */
                          0, /*DataTypeToBeSent */
                          0, /*DataTypeToBeRecvd */
                         QMStartNotifyCallback/*Callback function */
                        ); 
    
    return registerThis( &hook, &hi);
    
}
int registerNotifyPayloadCallback()
{
  // VID 
    struct hookpoint hook = {'\0'};
    struct handlerinfo hi = {'\0'};
//    struct hookpoint hookptr =&hook;

    u_int32_t position = 0;
    
    
    position = constructPosition( 
                                  ISAKMP_ETYPE_INFO, /* Mode */
                                  TPIKE_MIDX_ANY, /* Side */
                                  TPIKE_MIDX_ANY, /* Direction */
                                  0, /* msg index */ 
                                  0, /* after SA */
                                  0  /* k2 */
                                  );
    constructHookPoint(
                       &hook, /* Hook */
                       PAYLOAD_TYPE, /* Type */
                       ISAKMP_NPTYPE_NONE, /* PayloadOrAttrType */
                       ISAKMP_NPTYPE_NONE, /* PayloadOrAttrSubType */
                       position, /*Position */
                       1, /*Mandatory/Optional */
                       0, /*keylen*/
                       NULL /*KEY*/
                       );
                       
    constructHandlerInfo( 
                          &hi,                  /* handlerinfo */
                          TPIKE_DTYPE_STRUCTIPH1 | TPIKE_DTYPE_INT32PT, /*DataTypeToBeSent */
                          TPIKE_DTYPE_STRUCTVCHAR , /*DataTypeToBeRecvd */
                          notifyPayloadCallback/*Callback function */
                        ); 
    
    return registerThis( &hook, &hi);

}


int registerIsPayloadExistencyCheckCallback(){
    //ispayload existency reqd
    struct hookpoint hook = {'\0'};
    struct handlerinfo hi = {'\0'};
//    struct hookpoint hookptr =&hook;

    u_int32_t position = 0;
    
    
    position = constructPosition( 
                                  ISAKMP_ETYPE_QUICK, /* Mode */
                                  TPIKE_MIDX_RESPONDER, /* Side */
                                  TPIKE_MIDX_RECEIVE, /* Direction */
                                  0, /* msg index */ 
                                  0xff, /* k1 - any */
                                  0xff  /* k2 */
                                  );
    constructHookPoint(
                       &hook, /* Hook */
                       IS_PLECHECK_TYPE, /* Type */
                       ISAKMP_NPTYPE_NONE, /* PayloadOrAttrType */
                       ISAKMP_NPTYPE_NONE, /* PayloadOrAttrSubType */
                       position, /*Position */
                       1, /*Mandatory/Optional */
                       0, /*keylen*/
                       NULL /*KEY*/
                       );
                       
    constructHandlerInfo( 
                          &hi,                  /* handlerinfo */
                          0, /*DataTypeToBeSent */
                          TPIKE_DTYPE_INT32PT , /*DataTypeToBeRecvd */
                          isPayloadExistencyCheckCallback/*Callback function */
                        ); 
    
    return registerThis( &hook, &hi);
    
}


int registerIsPhase2CompleteCallback()
{
  // isphase2complete
    struct hookpoint hook = {'\0'};
    struct handlerinfo hi = {'\0'};
//    struct hookpoint hookptr =&hook;

    u_int32_t position = 0;
    
    
    position = constructPosition( 
                                  ISAKMP_ETYPE_ALL, /* Mode */
                                  TPIKE_MIDX_ANY, /* Side */
                                  TPIKE_MIDX_ANY, /* Direction */
                                  0, /* msg index */ 
                                  0xff, /* k1 - any */
                                  0xff  /* k2 */
                                  );
    constructHookPoint(
                       &hook, /* Hook */
                       PFKEY_MSG_TYPE, /* Type */
                       SADB_UPDATE , /* PayloadOrAttrType */
                       ISAKMP_NPTYPE_NONE, /* PayloadOrAttrSubType */
                       position, /*Position */
                       1, /*Mandatory/Optional */
                       0, /*keylen*/
                       NULL /*KEY*/
                       );
                       
    constructHandlerInfo( 
                          &hi,                  /* handlerinfo */
                          0, /*DataTypeToBeSent */
                          0, /*DataTypeToBeRecvd */
                          isPhase2CompleteCallback/*Callback function */
                        ); 
    
    return registerThis( &hook, &hi);

}

int registerIsRekeyReqCallback()
{
  // isRekeyReq 
    struct hookpoint hook = {'\0'};
    struct handlerinfo hi = {'\0'};
//    struct hookpoint hookptr =&hook;

    u_int32_t position = 0;
    
    
    position = constructPosition( 
                                  ISAKMP_ETYPE_ALLPHASE1, /* Mode */
                                  TPIKE_MIDX_ANY, /* Side */
                                  TPIKE_MIDX_ANY, /* Direction */
                                  0, /* msg index */ 
                                  0xff, /* k1 - any */
                                  0xff  /* k2 */
                                  );
    constructHookPoint(
                       &hook, /* Hook */
                       IS_REKEYREQ_TYPE, /* Type */
                       ISAKMP_NPTYPE_NONE, /* PayloadOrAttrType */
                       ISAKMP_NPTYPE_NONE, /* PayloadOrAttrSubType */
                       position, /*Position */
                       1, /*Mandatory/Optional */
                       0, /*keylen*/
                       NULL /*KEY*/
                       );
                       
    constructHandlerInfo( 
                          &hi,                  /* handlerinfo */
                          0, /*DataTypeToBeSent */
                          TPIKE_DTYPE_INT32PT , /*DataTypeToBeRecvd */
                          isRekeyReqCallback  /*Callback function */
                        ); 
    
    return registerThis( &hook, &hi);

}

int registerVIDPayloadCallback()
{    
    
  // VID 
    struct hookpoint hook = {'\0'};
    struct handlerinfo hi = {'\0'};
//    struct hookpoint hookptr =&hook;

    u_int32_t position = 0;
    
    
    
    position = constructPosition( 
                                  ISAKMP_ETYPE_ALLPHASE1, /* Mode */
                                  TPIKE_MIDX_INITIATOR, /* Side */
                                  TPIKE_MIDX_SEND, /* Direction */
                                  1, /* msg index */ 
                                  ISAKMP_NPTYPE_SA, /* after SA */
                                  0  /* k2 */
                                  );
    constructHookPoint(
                       &hook, /* Hook */
                       PAYLOAD_TYPE, /* Type */
                       ISAKMP_NPTYPE_VID, /* PayloadOrAttrType */
                       ISAKMP_NPTYPE_NONE, /* PayloadOrAttrSubType */
                       position, /*Position */
                       1, /*Mandatory/Optional */
                       0, /*keylen*/
                       NULL /*KEY*/
                       );
                       
    constructHandlerInfo( 
                          &hi,                  /* handlerinfo */
                          TPIKE_DTYPE_STRUCTIPH1, /*DataTypeToBeSent */
                          TPIKE_DTYPE_STRUCTPAYLOADLIST , /*DataTypeToBeRecvd */
                         VIDPayloadCallback  /*Callback function */
                        ); 
    
    return registerThis( &hook, &hi);

}

int registerCheckVIDPayloadCallback()
{    
    
    // Check VID 
    struct hookpoint hook = {'\0'};
    struct handlerinfo hi = {'\0'};
    u_int32_t position = 0;
    
    position = constructPosition( 
                                  ISAKMP_ETYPE_ALLPHASE1, /* Mode */
                                  TPIKE_MIDX_INITIATOR, /* Side */
                                  TPIKE_MIDX_RECEIVE, /* Direction */
                                  1, /* msg index */ 
                                  0xff, /* k1 - any */
                                  0xff  /* k2 */
                                  );
    constructHookPoint(
                       &hook, /* Hook */
                       PAYLOAD_TYPE, /* Type */
                       ISAKMP_NPTYPE_VID, /* PayloadOrAttrType */
                       ISAKMP_NPTYPE_NONE, /* PayloadOrAttrSubType */
                       position, /*Position */
                       1, /*Mandatory/Optional */
                       0, /*keylen*/
                       NULL /*KEY*/
                       );
                       
    
   
    
    constructHandlerInfo( 
                          &hi,                  /* handlerinfo */
                          TPIKE_DTYPE_STRUCTISAKMPGEN,   /*DataTypeToBeSent */
                          TPIKE_DTYPE_STRUCTISAKMPDATA,  /*DataTypeToBeRecvd */
                          checkVIDPayloadCallback  /*Callback function */
                        ); 
    
    return registerThis( &hook, &hi);

}

int registerOpaqueIDCallback()
{
    // OpaqueID 
    struct hookpoint hook = {'\0'};
    struct handlerinfo hi = {'\0'};
    u_int32_t position = 0;
    
    position = constructPosition( 
                                  ISAKMP_ETYPE_ALLPHASE1, /* Mode */
                                  TPIKE_MIDX_INITIATOR, /* Side */
                                  TPIKE_MIDX_SEND, /* Direction */
                                  1, /* msg index */ 
                                  ISAKMP_NPTYPE_NONCE, /* after NONCE */
                                  0  /* k2 */
                                  );
    constructHookPoint(
                       &hook, /* Hook */
                       PAYLOAD_TYPE, /* Type */
                       ISAKMP_NPTYPE_ID, /* PayloadOrAttrType */
                       IPSECDOI_ID_KEY_ID, /* PayloadOrAttrSubType */
                       position, /*Position */
                       1, /*Mandatory/Optional */
                       0, /*keylen*/
                       NULL /*KEY*/
                       );
    
    constructHandlerInfo( 
                          &hi,                  /* handlerinfo */
                          0,                    /*DataTypeToBeSent */
                          TPIKE_DTYPE_STRUCTVCHAR,     /*DataTypeToBeRecvd */
                          opaqueIDCallback    /*Callback list index */
                        ); 
    
    return registerThis( &hook, &hi);
}

int registerGeneratePSKCallback()
{
    // PSK 
    struct hookpoint hook = {'\0'};
    struct handlerinfo hi = {'\0'};
    u_int32_t position = 0;
    
    position = constructPosition( 
                                  ISAKMP_ETYPE_AGG, /* Mode */
                                  TPIKE_MIDX_INITIATOR, /* Side */
                                  TPIKE_MIDX_RECEIVE, /* Direction */
                                  1, /* msg index */ 
                                  0xff, /* k1 - any */
                                  0xff  /* k2 - any*/
                                  );
    constructHookPoint(
                       &hook, /* Hook */
                       PAYLOAD_TYPE, /* Type */
                       ISAKMP_NPTYPE_NONE, /* PayloadOrAttrType */
                       ISAKMP_NPTYPE_NONE, /* PayloadOrAttrSubType */
                       position, /*Position */
                       1, /*Mandatory/Optional */
                       0, /*keylen*/
                       NULL /*KEY*/
                       );
    
    constructHandlerInfo( 
                          &hi,                  /* handlerinfo */
                          0,                    /*DataTypeToBeSent */
                          TPIKE_DTYPE_STRUCTVCHAR,     /*DataTypeToBeRecvd */
                          presharedKeyCallback  /*Callback list index */
                        ); 
    
    return registerThis( &hook, &hi);
}

int registerCfgSetAckCallback (){

    struct hookpoint hook = {'\0'};
    struct handlerinfo hi = {'\0'};

    u_int32_t position = 0;
    
    
    position = constructPosition( 
            ISAKMP_ETYPE_CFG, /* Mode */
            TPIKE_MIDX_INITIATOR, /* Side */
            TPIKE_MIDX_RECEIVE, /* Direction */
            0, /* msg index */ 
            0xff, /* k1 - any */
            0xff  /* k2 */
            );
    constructHookPoint(
            &hook, /* Hook */
            ATTRIBUTE_TYPE, /* Type */
            CONFIG_ATTRIB_ACK_TYPE, /* PayloadOrAttrType */
            ISAKMP_CFG_SET, /* PayloadOrAttrSubType */
            position, /*Position */
            0, /*Mandatory/Optional */
            0, /*keylen*/
            NULL /*KEY*/
            );
    
    constructHandlerInfo( 
            &hi,                  /* handlerinfo */
            0, /*DataTypeToBeSent */
            0, /*DataTypeToBeRecvd */
            cfgSetAckCallback /*Callback function */
            ); 
    
    return registerThis( &hook, &hi);
    
}
