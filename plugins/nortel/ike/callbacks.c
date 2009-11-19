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
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>

/* My headers */
#include "nortel_vmbuf.h"
#include "nortel_inf.h"
#include "callbacks.h"
#include "utility.h"
#include "nortel_cfg.h"

/* Racoon Headers */
#include "racoon/vmbuf.h"
#include "racoon/isakmp_var.h"
#include "racoon/isakmp.h"
#include "racoon/nattraversal.h"
#include "racoon/schedule.h"
#include "racoon/admin.h"

/* Framework headers */
#include "plugin_frame/common.h"

#include "callbacks.h"
#include "packets.h"
#include "payloadgen.h"
#include "attrgen.h"

#include "common/plog.h"

//int (*callback)(void *, void *, void *, void **);
extern int check_NortelVID(struct isakmp_gen *gen, struct isakmp_data **resp);
extern int setNATFloatingPort(struct isakmp_data *data);
extern int generatePresharedKey(vchar_t *grpname, vchar_t *encpass,  vchar_t **preshared_key);
extern int check_NortelVID(struct isakmp_gen *gen, struct isakmp_data **resp);
extern int checkXtenddClientVer(struct isakmp_data *data);

int checkXtenddClientVersionCallback(void *gprivdata, void *hprivdata, void *inArray, void **outArray);

extern int nortel_keepalive_interval;

int QMStartNotifyCallback(void *gprivdata, void *hprivdata, void *inArray, void **outArray)  {
	extern kaInf_t ka;
    
	plog(LLV_DEBUG, LOCATION, NULL,"==> Enter QMStartNotifyCallback...\n");
	//Pack to outArray
	if(((struct nortelHandle *)gprivdata)->isPhase2Complete == 1 && ka.s != NULL)
	{
		sched_kill(ka.s);
		ka.s=NULL;
	}
    
	return 0;

}
int isPayloadExistencyCheckCallback(void *gprivdata, void *hprivdata, void *inArray, void **outArray)   
{
	int *isPlECheckRqd = NULL;
    
	plog(LLV_DEBUG, LOCATION, NULL,"==> Enter isPayloadExistencyCheckCallback...\n");
	isPlECheckRqd = (int *) malloc(sizeof(int));
	memset(isPlECheckRqd, 0, sizeof(int));    

	if(!isPlECheckRqd)
		return -1;

	*isPlECheckRqd = 1;
    
	//Pack to outArray
	if(((struct nortelHandle *)gprivdata)->isPhase2Complete == 1){
		*isPlECheckRqd = 0;
	}

	if( PACK ( outArray, 1, TPIKE_DTYPE_INT32PT,isPlECheckRqd ) < 0)
		return -1;

	return 0;
    
}

int isPhase2CompleteCallback(void *gprivdata, void *hprivdata, void *inArray, void **outArray)  
{
	plog(LLV_DEBUG,LOCATION,NULL,"Phase 2 Completed... \n");
    
	if(((struct nortelHandle *)gprivdata)->isPhase2Complete == 1)
		/* Rekey */
		; 
	else
		/* First time */
		((struct nortelHandle *)gprivdata)->isPhase2Complete = 1;
    
	return 0;

}

int isRekeyReqCallback(void *gprivdata, void *hprivdata, void *inArray, void **outArray)  
{
	int *isRekeyReq = NULL;
    
	plog(LLV_DEBUG, LOCATION, NULL,"==> Enter isRekeyReqCallback...\n");
	isRekeyReq = (int *) malloc(sizeof(int));
	memset(isRekeyReq, 0, sizeof(int));    

	if(!isRekeyReq)
		return -1;

	*isRekeyReq = 0;
    
	//Pack to outArray
	if( PACK ( outArray, 1, TPIKE_DTYPE_INT32PT,isRekeyReq ) < 0)
		return -1;

	return 0;
}

//  Prototype will be
int notifyPayloadCallback(void *gprivdata, void *hprivdata, void *inArray, void **outArray)   
{
	vchar_t *payload = NULL; 
	struct ph1handle *iph1 = NULL;
	int *type = NULL;
    
	plog(LLV_DEBUG,LOCATION,NULL,"In notify payload callback\n");
    
	if(((struct nortelHandle *)gprivdata)->isPhase2Complete == 0){
       
		plog(LLV_DEBUG,LOCATION,NULL,"Notify Payload doesnot interest me\n");
		goto end;
        
	}
    
	// Obtain gen from inArray
	if( UNPACK ( inArray, 2, TPIKE_DTYPE_STRUCTIPH1, &iph1, TPIKE_DTYPE_INT32PT, &type ) < 0)
		return -1;    

	payload = (vchar_t *)malloc(sizeof(vchar_t)); //to be freed by racoon 

	if (!payload)
		return -1;
    
	memset(payload, 0, sizeof(vchar_t)); //to be freed by racoon 
    
	plog(LLV_DEBUG,LOCATION,NULL,"Unpacked and am gonna generate notify with type %d\n",*type);

	if(generateNotifyPayload(payload, iph1, *type, ((struct nortelHandle *)gprivdata)->keepAliveInSec)<0){
		return -1;   
	};

	//PAck it to outArray
 end:
	if( PACK ( outArray, 1, TPIKE_DTYPE_STRUCTVCHAR, payload ) < 0)
		return -1;    
	return 0;
    
}

int VIDPayloadCallback(void *gprivdata, void *hprivdata, void *inArray, void **outArray)
{
	struct payload_list *pl = NULL; 
	struct ph1handle *iph1 = NULL;
    
	plog(LLV_DEBUG, LOCATION, NULL,"==> Enter VIDPayloadCallback...\n");
	// Obtain gen from inArray
	if( UNPACK ( inArray, 1, TPIKE_DTYPE_STRUCTIPH1, &iph1 ) < 0)
		return -1;    

	pl = (struct payload_list *)malloc(sizeof(struct payload_list)); //to be freed by racoon 
	memset(pl,0, sizeof(struct payload_list)); //to be freed by racoon 

	if (!pl)
		return -1;

	if(generateNortelVID(pl,iph1)<0){
		return -1;   
	};

	//PAck it to outArray
	if( PACK ( outArray, 1, TPIKE_DTYPE_STRUCTPAYLOADLIST, pl ) < 0)
		return -1;    
	return 0;
}

int checkVIDPayloadCallback(void *gprivdata, void *hprivdata, void *inArray, void **outArray)
{
	struct isakmp_gen *gen = NULL;
	struct isakmp_data *resp = NULL;
	int ret;

	plog(LLV_DEBUG, LOCATION, NULL,"==> Enter checkVIDPayloadCallback...\n");

	// Obtain gen from inArray
	if( UNPACK ( inArray, 1, TPIKE_DTYPE_STRUCTISAKMPGEN, &gen ) < 0)
		return -1;    

	if((ret = check_NortelVID(gen, &resp)) <0)
		return ret;
    
	if(PACK(outArray, 1, TPIKE_DTYPE_STRUCTISAKMPDATA, resp) < 0)
		return -1;

	return 0;
}

/*
  IN: Nothing
  OUT: vchar_t * of id 
*/

int opaqueIDCallback(void *gprivdata, void *hprivdata, void *inArray, void **outArray)
{
	vchar_t *opaqueID = NULL;

	plog(LLV_DEBUG, LOCATION, NULL,"==> Enter opaqueIDCallback...\n");
	if(generateOpaqueID( &(((struct nortelHandle *)gprivdata)->cfg->grpname), &opaqueID)<0){
		return -1;
	}
	//PAck it to outArray
	if( PACK ( outArray, 1, TPIKE_DTYPE_STRUCTVCHAR, opaqueID ) < 0)
		return -1;

	return 0; 
}

/*
  IN: Nothing
  OUT: vchar_t * of psk 
*/

int presharedKeyCallback(void *gprivdata, void *hprivdata, void *inArray, void **outArray)
{
	vchar_t *preshared_key = NULL;
	plog(LLV_DEBUG,LOCATION,NULL,"groupname:");
	plogdump(LLV_DEBUG, ((struct nortelHandle *)gprivdata)->cfg->grpname.v,
		((struct nortelHandle *)gprivdata)->cfg->grpname.l);
	plog(LLV_DEBUG,LOCATION,NULL,"grp passwd len:%zd\n", ((struct nortelHandle *)gprivdata)->cfg->grppasswd.l);
	
	if(generatePresharedKey(
		   &(((struct nortelHandle *)gprivdata)->cfg->grpname), 
		   &(((struct nortelHandle *)gprivdata)->cfg->grppasswd), 
		   &preshared_key
		   )<0){
		return -1;
	}

	//PAck it to outArray
	if( PACK ( outArray, 1, TPIKE_DTYPE_STRUCTVCHAR, preshared_key  ) < 0)
		return -1;

	return 0; 
}

/****************IKE ATTR *****************/

int CESClientVerCallback (void *gprivdata, void *hprivdata, void *inArray, void **outArray) 
{
	struct isakmp_data *data = NULL;
	int *len = NULL;
    
	plog(LLV_DEBUG, LOCATION, NULL,"==> Enter CESClientVerCallback...\n");
	data = (struct isakmp_data *)malloc(sizeof(struct isakmp_data));
	memset(data,0, sizeof(struct isakmp_data)); //to be freed by racoon 
    
	len = (int *) malloc(sizeof(int));
	memset(len, 0, sizeof(int));    

	if(!data || !len)
		return -1;

	if((*len = setCESClientVer(data))<0) 
		return -1; 

	//Pack to outArray
	if( PACK ( outArray, 2, TPIKE_DTYPE_STRUCTISAKMPDATA, data, TPIKE_DTYPE_INT32PT, len ) < 0)
		return -1;

	return 0;
}

int checkXtenddClientVersionCallback(void *gprivdata, void *hprivdata, void *inArray, void **outArray) 
{
	struct isakmp_data *data = NULL;
    
	plog(LLV_DEBUG, LOCATION, NULL,"==> Enter checkXtenddClientVersionCallback...\n");
	if( UNPACK ( inArray, 1, TPIKE_DTYPE_STRUCTISAKMPDATA, &data ) < 0)
		return -1;    
    
	if(checkXtenddClientVer(data) < 0) 
		return -1; 

	return 0;
}
   
int setNATFloatingPortCallback(void *gprivdata, void *hprivdata, void *inArray, void **outArray) 
{
	struct isakmp_data *data = NULL;
    
	plog(LLV_DEBUG, LOCATION, NULL,"==> Enter setNATFloatingPortCallback...\n");

	if( UNPACK ( inArray, 1, TPIKE_DTYPE_STRUCTISAKMPDATA, &data ) < 0)
		return -1;    

	if(setNATFloatingPort(data) < 0) 
		return -1; 

	return 0;
}

/****************CFG ATTR *****************/

int cfgXauthTypeCallback (void *gprivdata, void *hprivdata, void *inArray, void **outArray) 
{ 
	struct isakmp_data *data = NULL;
    
	plog(LLV_DEBUG, LOCATION, NULL,"==> Enter cfgXauthTypeCallback...\n");
	data = (struct isakmp_data *)malloc(sizeof(struct isakmp_data));
	memset(data,0, sizeof(struct isakmp_data)); //to be freed by racoon 

	if(replyXauthType(data)<0) 
		return -1; 

	//Pack to outArray
	if( PACK ( outArray, 1, TPIKE_DTYPE_STRUCTISAKMPDATA, data ) < 0)
		return -1;

	return 0;

}

int cfgXauthUserNameCallback (void *gprivdata, void *hprivdata, void *inArray, void **outArray) 
{ 
	struct isakmp_data *data = NULL;
    
	plog(LLV_DEBUG, LOCATION, NULL,"==> Enter cfgXauthUserNameCallback...\n");
	plog(LLV_DEBUG, LOCATION, NULL,"uname len= %zd\n",
			((struct nortelHandle *)gprivdata)->cfg->uname.l);
	data = (struct isakmp_data *)malloc(sizeof(struct isakmp_data) + ((struct nortelHandle *)gprivdata)->cfg->uname.l );
	memset(data,0, sizeof(struct isakmp_data) + ((struct nortelHandle *)gprivdata)->cfg->uname.l ); //to be freed by racoon 

	if(replyXauthUserName(
		   data,
		   ((struct nortelHandle *)gprivdata)->cfg->uname.l, 
		   ((struct nortelHandle *)gprivdata)->cfg->uname.v 
		   )<0) 
		return -1; 

	//Pack to outArray
	if( PACK ( outArray, 1, TPIKE_DTYPE_STRUCTISAKMPDATA, data ) < 0)
		return -1;

	return 0;
}

int cfgXauthPasswdCallback (void *gprivdata, void *hprivdata, void *inArray, void **outArray) 
{ 
	struct isakmp_data *data = NULL;
    
	plog(LLV_DEBUG, LOCATION, NULL,"==> Enter cfgXauthPasswdCallback...\n");
	data = (struct isakmp_data *)malloc(sizeof(struct isakmp_data) + ((struct nortelHandle *)gprivdata)->cfg->upass.l );
	memset(data,0, sizeof(struct isakmp_data) + ((struct nortelHandle *)gprivdata)->cfg->upass.l ); //to be freed by racoon 

	if(replyXauthPasswd(
		   data,
		   ((struct nortelHandle *)gprivdata)->cfg->upass.l, 
		   ((struct nortelHandle *)gprivdata)->cfg->upass.v 
		   )<0) 
		return -1; 

	//Pack to outArray
	if( PACK ( outArray, 1, TPIKE_DTYPE_STRUCTISAKMPDATA, data ) < 0)
		return -1;

	return 0;
}

int cfg3PartyLicenseCallback (void *gprivdata, void *hprivdata, void *inArray, void **outArray) 
{ 
	struct isakmp_data *data = NULL;
    
	plog(LLV_DEBUG, LOCATION, NULL,"==> Enter cfg3PartyLicenseCallback...\n");
	data = (struct isakmp_data *)malloc(sizeof(struct isakmp_data));
	memset(data,0, sizeof(struct isakmp_data)); //to be freed by racoon 

	if(replyCfg3PartyLicense(
		   data
		   )<0) 
		return -1; 

	//Pack to outArray
	if( PACK ( outArray, 1, TPIKE_DTYPE_STRUCTISAKMPDATA, data ) < 0)
		return -1;

	return 0;
}

int cfg3PartyVersionCallback (void *gprivdata, void *hprivdata, void *inArray, void **outArray) 
{ 
	struct isakmp_data *data = NULL;
    
	plog(LLV_DEBUG, LOCATION, NULL,"==> Enter cfg3PartyVersionCallback...\n");
	data = (struct isakmp_data *)malloc(sizeof(struct isakmp_data) + 50 /* sizeof version. TODO: MACRO IT */);
	memset(data,0, sizeof(struct isakmp_data) + 50 ); //to be freed by racoon 

	if(replyCfg3PartyVersion(
		   data
		   )<0) 
		return -1; 

	//Pack to outArray
	if( PACK ( outArray, 1, TPIKE_DTYPE_STRUCTISAKMPDATA, data ) < 0)
		return -1;

	return 0;
}

int cfgAckKACallback(void *gprivdata, void *hprivdata, void *inArray, void **outArray) 
{
	u_int32_t ka = 0;
	//struct isakmp_data indata = {'\0'};

	//struct isakmp_data *indataptr = &indata;
	struct isakmp_data *indataptr = NULL;
    
	struct isakmp_data *outdata = NULL;
    
	plog(LLV_DEBUG, LOCATION, NULL,"==> Enter cfgAckKACallback...\n");
	outdata = (struct isakmp_data *)malloc(sizeof(struct isakmp_data));
	memset(outdata,0, sizeof(struct isakmp_data)); //to be freed by racoon 

	//UNPACK inArray and obtain internal_ip 
	if( UNPACK ( inArray, 1, TPIKE_DTYPE_STRUCTISAKMPDATA, &indataptr ) < 0)
		return -1;

	ka = *(unsigned int *)((char*)(indataptr+1));

	//Update the global struct with internal ip
	plog(LLV_DEBUG,LOCATION,NULL,"KA IN SECS IS %x \n", ka); 

	((struct nortelHandle *)gprivdata)->keepAliveInSec = ka;
        nortel_keepalive_interval = ka;

	if(ackKATimer(outdata ,ka ) < 0){
		return -1;
	}

	//PACK into outArray
	if( PACK ( outArray, 1, TPIKE_DTYPE_STRUCTISAKMPDATA, outdata ) < 0)
		return -1;
	return 0;
}


int cfgAckIPv4Callback(void *gprivdata, void *hprivdata, void *inArray, void **outArray) 
{
	u_int32_t internel_ip = 0;
	//struct isakmp_data indata = {'\0'};

	//struct isakmp_data *indataptr = &indata;
	struct isakmp_data *indataptr = NULL;
    
	struct isakmp_data *outdata = NULL;
    
	plog(LLV_DEBUG, LOCATION, NULL,"==> Enter cfgAckIPv4Callback...\n");
	outdata = (struct isakmp_data *)malloc(sizeof(struct isakmp_data));
	memset(outdata,0, sizeof(struct isakmp_data)); //to be freed by racoon 

	//UNPACK inArray and obtain internal_ip 
	if( UNPACK ( inArray, 1, TPIKE_DTYPE_STRUCTISAKMPDATA, &indataptr ) < 0)
		return -1;

	internel_ip = *(unsigned int *)((char*)(indataptr+1));

	//Update the global struct with internal ip
	plog(LLV_DEBUG,LOCATION,NULL,"ASSIGNED IP ADDRESS IS %x \n", internel_ip); 

	//printf("ASSIGNED IP ADDRESS IS %x \n", internel_ip);
	((struct nortelHandle *)gprivdata)->assignedIPAddr = internel_ip;
	if(add_default_policy_to_SPD(((struct nortelHandle *)gprivdata)->assignedIPAddr)<0){
            return -1;
	}

	/* Add Server Policies */
	if (((struct nortelHandle *)gprivdata)->assignedNetMask) {
	    if(addRoutesForServerPolicies(((struct nortelHandle *)gprivdata)->rt_list,
					  ((struct nortelHandle *)gprivdata)->cfg->gatewayIP,
					  ((struct nortelHandle *)gprivdata)->assignedIPAddr,
					  ((struct nortelHandle *)gprivdata)->assignedNetMask,
					  ((struct nortelHandle *)gprivdata)->noSplitTunnel) < 0) {
			plog(LLV_DEBUG, LOCATION, NULL,
					"add Routes failed in cfgAckIPv4Callback.\n");
			return -1;
		}
	}

	if(ackIPv4Addr(outdata ,internel_ip ) < 0){
		return -1;
	}

	//PACK into outArray
	if( PACK ( outArray, 1, TPIKE_DTYPE_STRUCTISAKMPDATA, outdata ) < 0)
		return -1;
	return 0;
}

int cfgAckIPv4MaskCallback(void *gprivdata, void *hprivdata, void *inArray, void **outArray) 
{
	u_int32_t internel_mask = 0;
	//struct isakmp_data indata = {'\0'};

	//struct isakmp_data *indataptr = &indata;
	struct isakmp_data *indataptr = NULL;
	struct isakmp_data *outdata = NULL;
    
	plog(LLV_DEBUG, LOCATION, NULL,"==> Enter cfgAckIPv4MaskCallback...\n");
	outdata = (struct isakmp_data *)malloc(sizeof(struct isakmp_data));
	memset(outdata,0, sizeof(struct isakmp_data)); //to be freed by racoon 

	//UNPACK inArray and obtain internal_mask 
	if( UNPACK ( inArray, 1, TPIKE_DTYPE_STRUCTISAKMPDATA, &indataptr ) < 0)
		return -1;

	internel_mask = *(unsigned int *)((char*)(indataptr+1));

	//Update the global struct with internal ip mask
	((struct nortelHandle *)gprivdata)->assignedNetMask = internel_mask;

	/* Add Server Policies */
	if (((struct nortelHandle *)gprivdata)->assignedIPAddr) {
		if(addRoutesForServerPolicies(((struct nortelHandle *)gprivdata)->rt_list,
					((struct nortelHandle *)gprivdata)->cfg->gatewayIP,
					((struct nortelHandle *)gprivdata)->assignedIPAddr,
					((struct nortelHandle *)gprivdata)->assignedNetMask,
					((struct nortelHandle *)gprivdata)->noSplitTunnel) < 0) {
			plog(LLV_DEBUG, LOCATION, NULL,
					"add Routes failed in cfgAckIPv4MaskCallback.\n");
			return -1;
		}
	}

	if(ackIPv4Mask(outdata ,internel_mask ) < 0){
		return -1;
	}

	/* TODO: Add default policy with new spd (Should ike plugin do it. Or send the internal address to gui plugin and leave it to the gui plugin to add this via admin port */

	//PACK into outArray
	if( PACK ( outArray, 1, TPIKE_DTYPE_STRUCTISAKMPDATA, outdata ) < 0)
		return -1;
	return 0;
}

int cfgAckIPv4DnsCallback(void *gprivdata, void *hprivdata, void *inArray, void **outArray) 
{
	u_int32_t internel_dns = 0;
	int ret = 0;

	struct isakmp_data *indataptr = NULL;
	struct isakmp_data *outdata = NULL;

	plog(LLV_DEBUG, LOCATION, NULL,"==> Enter cfgAckIPv4DnsCallback...\n");
	outdata = (struct isakmp_data *)malloc(sizeof(struct isakmp_data));
	memset(outdata,0, sizeof(struct isakmp_data)); //to be freed by racoon

	//UNPACK inArray and obtain dns
	if( UNPACK ( inArray, 1, TPIKE_DTYPE_STRUCTISAKMPDATA, &indataptr ) < 0)
		return -1;

	internel_dns = *(unsigned int *)((char*)(indataptr+1));

	//Update the global struct with internal
	if (((struct nortelHandle *)gprivdata)->assignedDNSAddrPrimary == 0) {
		((struct nortelHandle *)gprivdata)->assignedDNSAddrPrimary = internel_dns;
	} else if (((struct nortelHandle *)gprivdata)->assignedDNSAddrSecondary == 0) {
		((struct nortelHandle *)gprivdata)->assignedDNSAddrSecondary = internel_dns;
	} else {
		plog(LLV_DEBUG, LOCATION, NULL,
				"The primary(0x%08x) and secondary(0x%08x) DNS already set?\n",
				((struct nortelHandle *)gprivdata)->assignedDNSAddrPrimary,
				((struct nortelHandle *)gprivdata)->assignedDNSAddrSecondary);
	}

	ret = updateDNSForServerPolicies (
			((struct nortelHandle *)gprivdata)->noDNS,
			((struct nortelHandle *)gprivdata)->assignedDNSAddrPrimary,
			((struct nortelHandle *)gprivdata)->assignedDNSAddrSecondary,
			((struct nortelHandle *)gprivdata)->assignedDomainName);
	if (ret < 0) {
		plog(LLV_DEBUG, LOCATION, NULL,
				"update DNS failed in cfgAckIPv4DnsCallback.\n");
	}

	if (ackIPv4Dns (outdata, internel_dns ) < 0) {
		return -1;
	}

	//PACK into outArray
	if (PACK ( outArray, 1, TPIKE_DTYPE_STRUCTISAKMPDATA, outdata ) < 0)
		return -1;
	return 0;
}

int cfgAckIPv4DomainNameCallback(void *gprivdata, void *hprivdata, void *inArray, void **outArray) 
{
	char* internal_domain_name;

	struct isakmp_data *indataptr = NULL;
	struct isakmp_data *outdata = NULL;
	u_int32_t len = 0;
	int i = 0;
	int ret = 0;

	plog(LLV_DEBUG, LOCATION, NULL,"==> Enter cfgAckIPv4DomainNameCallback...\n");
	outdata = (struct isakmp_data *)malloc(sizeof(struct isakmp_data));
	memset(outdata,0, sizeof(struct isakmp_data)); //to be freed by racoon

	//UNPACK inArray and obtain internal_mask
	if (UNPACK ( inArray, 1, TPIKE_DTYPE_STRUCTISAKMPDATA, &indataptr ) < 0)
		return -1;

	len = ntohs (indataptr->lorv);
	internal_domain_name = (char*)((char*)(indataptr+1));

	i = 0;
	while (i < len && internal_domain_name[i] != '@')
		i++;

	//Update the global struct with internal
	strncpy(((struct nortelHandle *)gprivdata)->assignedDomainName, internal_domain_name, i);
	((struct nortelHandle *)gprivdata)->assignedDomainName [i] = 0;

	ret = updateDNSForServerPolicies (
			((struct nortelHandle *)gprivdata)->noDNS,
			((struct nortelHandle *)gprivdata)->assignedDNSAddrPrimary,
			((struct nortelHandle *)gprivdata)->assignedDNSAddrSecondary,
			((struct nortelHandle *)gprivdata)->assignedDomainName);
	if (ret < 0) {
		plog(LLV_DEBUG, LOCATION, NULL,
				"update Domain name failed in cfgAckIPv4DomainNameCallback.\n");
	}

	if (ackIPv4DomainName (outdata, internal_domain_name ) < 0) {
		return -1;
	}

	//PACK into outArray
	if (PACK ( outArray, 1, TPIKE_DTYPE_STRUCTISAKMPDATA, outdata ) < 0)
		return -1;
	return 0;
}

int cfgAckBifurcationCallback(void *gprivdata, void *hprivdata, void *inArray, void **outArray) 
{
	vchar_t *rt_list  = NULL;
	//struct isakmp_data indata = {'\0'};

	//struct isakmp_data *indataptr = &indata;
	struct isakmp_data *indataptr = NULL;
	struct isakmp_data *outdata = NULL;
	u_int32_t len = 0;   

	plog(LLV_DEBUG, LOCATION, NULL,"==> Enter cfgAckBifurcationCallback...\n");
	outdata = (struct isakmp_data *)malloc(sizeof(struct isakmp_data));
	if (NULL == outdata) {
		plog(LLV_ERROR, LOCATION, NULL, "Not enough memory in cfgAckBifurcationCallback.\n");
		return -1;
	}
	memset(outdata, 0, sizeof(struct isakmp_data)); //to be freed by racoon 

	//UNPACK inArray and obtain rt_list 
	if (UNPACK(inArray, 1, TPIKE_DTYPE_STRUCTISAKMPDATA, &indataptr) < 0) {
		plog(LLV_ERROR, LOCATION, NULL, "Unpack array failed in cfgAckBifurcationCallback.\n");
		return -1;
	}

	if (NULL == indataptr) {
		plog(LLV_ERROR, LOCATION, NULL, "Indataptr is NULL.\n");
		return -1;
	}

	len = htons(indataptr->lorv);
	if( (rt_list = nortel_vmalloc(len)) == NULL ){ 
		plog(LLV_ERROR, LOCATION, NULL,
			   	"Vmalloc memory failed in cfgAckBifurcationCallback.\n");
		return -1;
	}

	//rt_list->l = indataptr->lorv;
	rt_list->l = len;

	memcpy(rt_list->v, (char *)(indataptr+1), rt_list->l);

	//Update the global struct with rt_list 
	((struct nortelHandle *)gprivdata)->rt_list = rt_list;

	/* Add Server Policies */
	if (((struct nortelHandle *)gprivdata)->assignedIPAddr &&
			((struct nortelHandle *)gprivdata)->assignedNetMask &&
			((struct nortelHandle *)gprivdata)->cfg) {
		if (addRoutesForServerPolicies(rt_list,
					((struct nortelHandle *)gprivdata)->cfg->gatewayIP,
					((struct nortelHandle *)gprivdata)->assignedIPAddr,
					((struct nortelHandle *)gprivdata)->assignedNetMask,
					((struct nortelHandle *)gprivdata)->noSplitTunnel) < 0) {
			plog(LLV_ERROR, LOCATION, NULL,
					"Add routes failed in cfgAckBifurcationCallback.\n");
			return -1; 
		}
		plog(LLV_DEBUG, LOCATION, NULL,
				"Add routes policies success in cfgAckBifurcationCallback!\n");
	} else {
		plog(LLV_ERROR, LOCATION, NULL,
				"Assigned IPAddr, Netmask or cfg is null in cfgAckBifurcationCallback.\n");
	}

	if (ackCfgBifurcation(outdata , rt_list) < 0) {
		plog(LLV_ERROR, LOCATION, NULL,
				"Ack Bifurcation failed in cfgAckBifurcationCallback.\n");
		return -1;
	}

	//PACK into outArray
	if (PACK(outArray, 1, TPIKE_DTYPE_STRUCTISAKMPDATA, outdata) < 0) {
		plog(LLV_ERROR, LOCATION, NULL,
				"Pack out array failed in cfgAckBifurcationCallback.\n");
		return -1;
	}

	return 0;
}

int cfgXauthOKCallback(void *gprivdata, void *hprivdata, void *inArray, void **outArray)  
{
	struct isakmp_data *indata = NULL;
    
	plog(LLV_DEBUG, LOCATION, NULL,"==> Enter cfgXauthOKCallback...\n");
	//UNPACK inArray and obtain data 
	if( UNPACK ( inArray, 1, TPIKE_DTYPE_STRUCTISAKMPDATA, &indata ) < 0)
		return -1;

	//Update the global struct with rt_list 
	((struct nortelHandle *)gprivdata)->isAuthSuccess = 1;


	if(handleCfgAuthOK(indata) < 0){
		return -1;
	}

	return 0;

}

int cfgXauthFAILCallback(void *gprivdata, void *hprivdata, void *inArray, void **outArray)  
{
	struct isakmp_data *indata = NULL;
	plog(LLV_DEBUG, LOCATION, NULL,"==> Enter cfgXauthFAILCallback...\n");
	//UNPACK inArray and obtain data 
	if( UNPACK ( inArray, 1, TPIKE_DTYPE_STRUCTISAKMPDATA, &indata ) < 0)
		return -1;

	//Update the global struct with rt_list 
	((struct nortelHandle *)gprivdata)->isAuthSuccess = 1;

	if(handleCfgAuthFailed(indata) < 0){
		return -1;
	}

	return 0;
}


int fillNATOptionsCallback(void *gprivdata, void *hprivdata, void *inArray, void **outArray)
{
	struct ph2natt *natt = NULL; 

	plog(LLV_DEBUG, LOCATION, NULL,"==> Enter fillNATOptionsCallback...\n");
	if((natt = (struct ph2natt *)malloc(sizeof(struct ph2natt))) == NULL) //to be freed by racoon 
		return -1;
	memset(natt,0, sizeof(struct ph2natt)); //to be freed by racoon 

	if(fill_natt_options(natt) < 0)
		return -1;   
    
	//Pack it to outArray
	if( PACK ( outArray, 1, TPIKE_DTYPE_STRUCTNATTOPTIONS, natt ) < 0)
		return -1;    
	return 0;
}


int cfgSetAckCallback (void *gprivdata, void *hprivdata, void *inArray, void **outArray)
{
   plog (LLV_DEBUG, LOCATION, NULL, "Acking final cfg set reply");
   nortel_cfg_split_tunnel (GETPLUGINHANDLE(gprivdata));
   return 0;
}


int 
cfgAckNatKeepAliveIntervalCallback (void *gprivdata,
                                        void *hprivdata,
                                        void *inArray,
                                        void **outArray)
{
   struct isakmp_data *reply_attr = NULL, *in_attr = NULL;

	plog(LLV_DEBUG, LOCATION, NULL,"==> Enter cfgAckNatKeepAliveIntervalCallback...\n");
   //UNPACK inArray and obtain data 
   if( UNPACK ( inArray, 1, TPIKE_DTYPE_STRUCTISAKMPDATA, &in_attr ) < 0)
      return -1;

   reply_attr = nortel_cfg_set (GETPLUGINHANDLE(gprivdata), in_attr);

   if( PACK ( outArray, 1, TPIKE_DTYPE_STRUCTISAKMPDATA, reply_attr ) < 0)
      return -1;

   return 0;
}
