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
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>

/* My headers */
#include "utility.h"
#include "nortel_vmbuf.h"
#include "nortel_inf.h"
#include "callbacks.h"
#include "registerattr.h"
#include "registerpayload.h"
    
/* Racoon Headers */
#include "racoon/vmbuf.h"
#include "racoon/isakmp_var.h"
#include "racoon/isakmp.h"

// IKE Attribute CES Client Version

int registerCESClientVerCallback()
{    
    
    struct hookpoint hook = {'\0'};
    struct handlerinfo hi = {'\0'};
    u_int32_t position = 0;
    u_int32_t key = CONTIVITY_CLIENT_VERSION;  
    
    position = constructPosition( 
                                  ISAKMP_ETYPE_ALLPHASE1, /* Mode */
                                  TPIKE_MIDX_INITIATOR, /* Side */
                                  TPIKE_MIDX_SEND, /* Direction */
                                  0, /* msg index */ 
                                  0xff, /* k1 */
                                  0xff  /* k2 */
                                  );
    constructHookPoint(
                       &hook, /* Hook */
                       ATTRIBUTE_TYPE, /* Type */
                       IKE_ATTRIB_TYPE, /* PayloadOrAttrType - IKE attr */
                       0,               /* PayloadOrAttrSubType  */
                       position, /*Position */
                       1, /*Mandatory/Optional */
                       sizeof(key), /*keylen*/
                       &key /*KEY - IKE Attr Type */
                       );
                       
    constructHandlerInfo( 
                          &hi,                  /* handlerinfo */
                          0,                    /*DataTypeToBeSent */
                          TPIKE_DTYPE_STRUCTISAKMPDATA | TPIKE_DTYPE_INT32PT, /*DataTypeToBeRecvd */
                          CESClientVerCallback  /*Callback function */
                        ); 
    
    return registerThis( &hook, &hi);

}

/* Cfg Attribute */
/* REQUEST */
int registerCfgAttrReqCallback(u_int16_t key, CALLBACK callback)
{    
    
    struct hookpoint hook = {'\0'};
    struct handlerinfo hi = {'\0'};
    u_int32_t position = 0;
    key = ntohs(key);
    
    position = constructPosition( 
                                  ISAKMP_ETYPE_CFG, /* Mode */
                                  TPIKE_MIDX_INITIATOR, /* Side */
                                  TPIKE_MIDX_RECEIVE, /* Direction */
                                  0, /* msg index */ 
                                  0xff, /* k1 */
                                  0xff  /* k2 */
                                  );
    constructHookPoint(
                       &hook, /* Hook */
                       ATTRIBUTE_TYPE,     /* Type */
                       CONFIG_ATTRIB_TYPE,    /* PayloadOrAttrType - IKE attr */
                       ISAKMP_CFG_REQUEST, /* PayloadOrAttrSubType  */
                       position,           /*Position */
                       1,                  /*Mandatory/Optional */
                       sizeof(key), /*keylen*/
                       &key               /*KEY - CFG Attr Type */
                       );
                       
    constructHandlerInfo( 
                          &hi,                  /* handlerinfo */
                          0,                    /*DataTypeToBeSent */
                          TPIKE_DTYPE_STRUCTISAKMPDATA, /*DataTypeToBeRecvd */
                          callback /*Callback function */
                        ); 
    
    return registerThis( &hook, &hi);
}

int registerCfgAttrSetCallback(u_int16_t key, CALLBACK callback)
{    
    
    struct hookpoint hook = {'\0'};
    struct handlerinfo hi = {'\0'};
    u_int32_t position = 0;
    key = ntohs(key);
    
    position = constructPosition( 
                                  ISAKMP_ETYPE_CFG, /* Mode */
                                  TPIKE_MIDX_INITIATOR, /* Side */
                                  TPIKE_MIDX_RECEIVE, /* Direction */
                                  0, /* msg index */ 
                                  0xff, /* k1 */
                                  0xff  /* k2 */
                                  );
    constructHookPoint(
                       &hook, /* Hook */
                       ATTRIBUTE_TYPE,     /* Type */
                       CONFIG_ATTRIB_TYPE,    /* PayloadOrAttrType - IKE attr */
                       ISAKMP_CFG_SET, /* PayloadOrAttrSubType  */
                       position,           /*Position */
                       1,                  /*Mandatory/Optional */
                       sizeof(key), /*keylen*/
                       &key               /*KEY - CFG Attr Type */
                       );
                       
    constructHandlerInfo( 
                          &hi,                  /* handlerinfo */
                          TPIKE_DTYPE_STRUCTISAKMPDATA, /*DataTypeToBeSent */
                          TPIKE_DTYPE_STRUCTISAKMPDATA, /*DataTypeToBeRecvd */
                          callback /*Callback function */
                        ); 
    
    return registerThis( &hook, &hi);
}

static int registerCfgXauthStatusCallback(u_int8_t cfgPrivType, CALLBACK callback)
{    
    
    struct hookpoint hook = {'\0'};
    struct handlerinfo hi = {'\0'};
    u_int32_t position = 0;
    
    position = constructPosition( 
                                  ISAKMP_ETYPE_CFG, /* Mode */
                                  TPIKE_MIDX_INITIATOR, /* Side */
                                  TPIKE_MIDX_RECEIVE, /* Direction */
                                  0, /* msg index */ 
                                  0xff, /* k1 */
                                  0xff  /* k2 */
                                  );
    constructHookPoint(
                       &hook, /* Hook */
                       ATTRIBUTE_TYPE,     /* Type */
                       CONFIG_ATTRIB_TYPE,    /* PayloadOrAttrType - IKE attr */
                       cfgPrivType, /* PayloadOrAttrSubType  */
                       position,           /*Position */
                       1,                  /*Mandatory/Optional */
                       0, /*keylen*/
                       NULL               /*KEY - CFG Attr Type */
                       );
                       
    constructHandlerInfo( 
                          &hi,                 /* handlerinfo */
                          TPIKE_DTYPE_STRUCTISAKMPDATA, /*DataTypeToBeSent */
                          0,                   /*DataTypeToBeRecvd */
                          callback             /*Callback function */
                        ); 
    
    return registerThis( &hook, &hi);
}

int registerCfgXauthOKCallback(CALLBACK callback)
{
   return registerCfgXauthStatusCallback(ISAKMP_CFG_AUTH_OK, callback);
}

int registerCfgXauthFAILCallback(CALLBACK callback)
{
   return registerCfgXauthStatusCallback(ISAKMP_CFG_AUTH_FAILED, callback);
}

//ISAKMP Attribute - Extended Contivity Client Version
int registerXtndedContivityVersionCallback()
{    
    
    struct hookpoint hook = {'\0'};
    struct handlerinfo hi = {'\0'};
    u_int32_t position = 0;
    u_int32_t key = XTNDD_CONTIVITY_CLIENT_VERSION;  
    
    position = constructPosition( 
                                  0, /* Mode */
                                  0, /* Side */
                                  TPIKE_MIDX_RECEIVE, /* Direction */
                                  0, /* msg index */ 
                                  0xff, /* k1 */
                                  0xff  /* k2 */
                                  );
    constructHookPoint(
                       &hook, /* Hook */
                       ATTRIBUTE_TYPE, /* Type */
                       ISAKMP_ATTRIB_TYPE, /* PayloadOrAttrType - IPsec attr */
                       0,               /* PayloadOrAttrSubType  */
                       position, /*Position */
                       0, /*Mandatory/Optional */
                       sizeof(key), /*keylen*/
                       &key /*KEY - IPsec Attr Type */
                       );
                       
    constructHandlerInfo( 
                          &hi,                  /* handlerinfo */
                          TPIKE_DTYPE_STRUCTISAKMPDATA,          /*DataTypeToBeSent */
                          0, /*DataTypeToBeRecvd */
                          checkXtenddClientVersionCallback  /*Callback function */
                        ); 
    
    return registerThis( &hook, &hi);
}

// IPsec Attribute UDP Encapsulation Flag

int registerUDPEncapCallback()
{    
    
    struct hookpoint hook = {'\0'};
    struct handlerinfo hi = {'\0'};
    u_int32_t position = 0;
    u_int32_t key = UDP_ENCAP_FLAG;  
    
    position = constructPosition( 
                                  ISAKMP_ETYPE_QUICK, /* Mode */
                                  TPIKE_MIDX_RESPONDER, /* Side */
                                  TPIKE_MIDX_RECEIVE, /* Direction */
                                  0, /* msg index */ 
                                  0xff, /* k1 */
                                  0xff  /* k2 */
                                  );
    constructHookPoint(
                       &hook, /* Hook */
                       ATTRIBUTE_TYPE, /* Type */
                       IPSEC_ATTRIB_TYPE, /* PayloadOrAttrType - IPsec attr */
                       0,               /* PayloadOrAttrSubType  */
                       position, /*Position */
                       1, /*Mandatory/Optional */
                       sizeof(key), /*keylen*/
                       &key /*KEY - IPsec Attr Type */
                       );
                       
    constructHandlerInfo( 
                          &hi,                  /* handlerinfo */
                          TPIKE_DTYPE_STRUCTISAKMPDATA,          /*DataTypeToBeSent */
                          0, /*DataTypeToBeRecvd */
                          setNATFloatingPortCallback  /*Callback function */
                        ); 
    
    return registerThis( &hook, &hi);
}

int registerSetNattOptionsCallback()
{    
    
    struct hookpoint hook = {'\0'};
    struct handlerinfo hi = {'\0'};
    u_int32_t position = 0;
    
    position = constructPosition( 
                                  ISAKMP_ETYPE_QUICK, /* Mode */
                                  TPIKE_MIDX_RESPONDER, /* Side */
                                  TPIKE_MIDX_ANY, /* Direction */
                                  0, /* msg index */ 
                                  0xff, /* k1 */
                                  0xff  /* k2 */
                                  );
    constructHookPoint(
                       &hook, /* Hook */
                       NATT_OPTIONS_TYPE,     /* Type */
                       0,    /* PayloadOrAttrType - IKE attr */
                       0, /* PayloadOrAttrSubType  */
                       position,           /*Position */
                       0,                  /*Mandatory/Optional */
                       0, /*keylen*/
                       NULL               /*KEY - CFG Attr Type */
                       );
                       
    constructHandlerInfo( 
                          &hi,                  /* handlerinfo */
                          0, /*DataTypeToBeSent */
                          TPIKE_DTYPE_STRUCTNATTOPTIONS, /*DataTypeToBeRecvd */
                          fillNATOptionsCallback /*Callback function */
                        ); 
    
    return registerThis( &hook, &hi);
}
