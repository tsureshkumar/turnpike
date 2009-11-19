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
#ifndef __CALLBACKS_H__
#define __CALLBACKS_H__

#define PLUGINNAME "nortel"

/* Callbacks that are not supposed to be here */

int QMStartNotifyCallback(void *gprivdata, void *hprivdata, void *INARRAY, void **OUTARRAY);; 
int isPayloadExistencyCheckCallback (void *gprivdata, void *hprivdata, void *INARRAY, void **OUTARRAY);; 
int isPhase2CompleteCallback(void *gprivdata, void *hprivdata, void *INARRAY, void **OUTARRAY);;
int isRekeyReqCallback (void *gprivdata, void *hprivdata, void *INARRAY, void **OUTARRAY);;

/* Payloads */
int notifyPayloadCallback(void *gprivdata, void *hprivdata, void *INARRAY, void **OUTARRAY);;  
int VIDPayloadCallback(void *gprivdata, void *hprivdata, void *INARRAY, void **OUTARRAY);
int checkVIDPayloadCallback(void *gprivdata, void *hprivdata, void *INARRAY, void **OUTARRAY);
int opaqueIDCallback(void *gprivdata, void *hprivdata, void *INARRAY, void **OUTARRAY);
int presharedKeyCallback(void *gprivdata, void *hprivdata, void *INARRAY, void **OUTARRAY);

/* IKE ATTR */
int CESClientVerCallback (void *gprivdata, void *hprivdata, void *INARRAY, void **OUTARRAY); 
int checkXtenddClientVersionCallback(void *gprivdata, void *hprivdata, void *INARRAY, void **OUTARRAY); 
  
/* IPsec attr */
int setNATFloatingPortCallback(void *gprivdata, void *hprivdata, void *inArray, void **outArray); 
/* CFG ATTR */ 

//REQUESTS
int cfgXauthTypeCallback (void *gprivdata, void *hprivdata, void *INARRAY, void **OUTARRAY); 
int cfgXauthUserNameCallback (void *gprivdata, void *hprivdata, void *INARRAY, void **OUTARRAY); 
int cfgXauthPasswdCallback (void *gprivdata, void *hprivdata, void *INARRAY, void **OUTARRAY); 
int cfg3PartyLicenseCallback (void *gprivdata, void *hprivdata, void *INARRAY, void **OUTARRAY); 
int cfg3PartyVersionCallback (void *gprivdata, void *hprivdata, void *INARRAY, void **OUTARRAY);

//SETS
int cfgAckKACallback(void *gprivdata, void *hprivdata, void *inArray, void **outArray); 
int cfgAckIPv4Callback(void *gprivdata, void *hprivdata, void *INARRAY, void **OUTARRAY); 
int cfgAckIPv4MaskCallback(void *gprivdata, void *hprivdata, void *INARRAY, void **OUTARRAY); 
int cfgAckIPv4DnsCallback(void *gprivdata, void *hprivdata, void *INARRAY, void **OUTARRAY); 
int cfgAckBifurcationCallback(void *gprivdata, void *hprivdata, void *INARRAY, void **OUTARRAY);
int cfgSetAckCallback (void *gprivdata, void *hprivdata, void *inArray, void **outArray);
int cfgAckIPv4DomainNameCallback(void *gprivdata, void *hprivdata, void *inArray, void **outArray) ;



//Priv Types

int cfgXauthOKCallback(void *gprivdata, void *hprivdata, void *INARRAY, void **OUTARRAY);  
int cfgXauthFAILCallback(void *gprivdata, void *hprivdata, void *INARRAY, void **OUTARRAY);  
/* NATT options */
int fillNATOptionsCallback(void *gprivdata, void *hprivdata, void *inArray, void **outArray);

int cfgAckNatKeepAliveIntervalCallback (void *gprivdata,
                                        void *hprivdata,
                                        void *inArray,
                                        void **outArray);

#endif
