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

/* My headers */
#include "nortel_vmbuf.h"
#include "nortel_inf.h"
#include "callbacks.h"
#include "utility.h"

/* Racoon Headers */
#include "racoon/vmbuf.h"
#include "racoon/isakmp_var.h"
#include "racoon/isakmp.h"

#include "plugin_frame/error.h"

#include "registerpayload.h"
#include "registerattr.h"

//static int cp2gp(struct configInf **ci, void *cp)
static int cp2gp(struct nortelHandle *nh, void *cp)
{
    /* I declare this cos I dont want to typecast void at every place */
    struct configInf *cfginf =NULL ;
    
   // struct configInf *ci = (struct configInf *) cp;
   
#if 0
    cfginf = malloc (sizeof(struct configInf)); //Should be freed during de-init 
    if(!cfginf)
        return -1;
    
    memset(cfginf, 0, sizeof(struct configInf));

    cfginf->uname.l = strlen("JUNK");
    cfginf->uname.v = (caddr_t) malloc(cfginf->uname.l * sizeof(char));//Should be freed during de-init  
    memset(cfginf->uname.v, 0, cfginf->uname.l);
    memcpy (cfginf->uname.v,"JUNK" , cfginf->uname.l);

    cfginf->upass.l = strlen("JUNK");
    cfginf->upass.v = (caddr_t) malloc(cfginf->upass.l * sizeof(char));//Should be freed during de-init  
    memset(cfginf->upass.v, 0, cfginf->upass.l);
    memcpy (cfginf->upass.v,"JUNK" , cfginf->upass.l);
    
    cfginf->grpname.l = strlen("JUNK");
    cfginf->grpname.v = (caddr_t) malloc(cfginf->grpname.l * sizeof(char));//Should be freed during de-init  
    memset(cfginf->grpname.v, 0, cfginf->grpname.l);
    memcpy (cfginf->grpname.v,"JUNK" , cfginf->grpname.l);
   
    cfginf->grppasswd.l = strlen("JUNK");
    cfginf->grppasswd.v = (caddr_t) malloc(cfginf->grppasswd.l * sizeof(char));//Should be freed during de-init  
    memset(cfginf->grppasswd.v, 0, cfginf->grppasswd.l);
    memcpy (cfginf->grppasswd.v,"JUNK" , cfginf->grppasswd.l);

#else
 
	if (NULL == nh)
		return -1;

    cfginf = malloc (sizeof(struct configInf)); //Should be freed during de-init 
    if(!cfginf)
        return -1;
    
    memset(cfginf, 0, sizeof(struct configInf));
 
    /* Copy Gateway IP */
    cfginf->gatewayIP = *(u_int32_t *)cp;
    cp+=sizeof(cfginf->gatewayIP);
    
    /* Copy grpname */
    cfginf->grpname.l = *(size_t *)cp;
    cp+=sizeof(cfginf->grpname.l);

    cfginf->grpname.v = (caddr_t) malloc(cfginf->grpname.l * sizeof(char));//Should be freed during de-init  
    
    if(!cfginf->grpname.v)
         return -1;
    
    memset(cfginf->grpname.v, 0, cfginf->grpname.l );
    memcpy (cfginf->grpname.v, cp, cfginf->grpname.l);
    cp+=cfginf->grpname.l;
    
    /* Copy grppasswd */
    cfginf->grppasswd.l = *(size_t *)cp;
    cp+=sizeof(cfginf->grppasswd.l);

    cfginf->grppasswd.v = (caddr_t) malloc(cfginf->grppasswd.l * sizeof(char));//Should be freed during de-init  
    
    if(!cfginf->grppasswd.v)
         return -1;
    
    memset(cfginf->grppasswd.v, 0, cfginf->grppasswd.l );
    memcpy (cfginf->grppasswd.v, cp, cfginf->grppasswd.l);
    cp+=cfginf->grppasswd.l;

    /* Copy uname */
    cfginf->uname.l = *(size_t *)cp;
    cp+=sizeof(cfginf->uname.l);

    cfginf->uname.v = (caddr_t) malloc(cfginf->uname.l * sizeof(char));//Should be freed during de-init  
    
    if(!cfginf->uname.v)
         return -1;
    
    memset(cfginf->uname.v, 0, cfginf->uname.l);
    memcpy (cfginf->uname.v, cp, cfginf->uname.l);
    cp+=cfginf->uname.l;

    /* Copy upass */
    cfginf->upass.l = *(size_t *)cp;
    cp+=sizeof(cfginf->upass.l);

    cfginf->upass.v = (caddr_t) malloc(cfginf->upass.l * sizeof(char));//Should be freed during de-init  
    
    if(!cfginf->upass.v)
         return -1;
    
    memset(cfginf->upass.v, 0, cfginf->upass.l);
    memcpy (cfginf->upass.v, cp, cfginf->upass.l);
    cp+=cfginf->upass.l;

	// check the no split tunnel option
	if (0 == memcmp (cp, "nosplittunnel", strlen("nospittunnel"))) {
		plog (LLV_INFO, LOCATION, NULL,
				"Disable the server's split tunnel!\n");
		cp += strlen("nospittunnel");
		nh->noSplitTunnel = 1;
	} else {
		plog (LLV_INFO, LOCATION, NULL,
				"Support the server's split tunnel!\n");
	}

	if (0 == memcmp (cp, "nodns", strlen("nodns"))) {
		plog (LLV_INFO, LOCATION, NULL,
				"Disable the DNS and Domain Name setting with dnsupdate!\n");
		cp += strlen("nodns");
		nh->noDNS = 1;
	} else {
		plog (LLV_INFO, LOCATION, NULL,
				"Support the DNS and Domain Name setting with dnsupdate!\n");
	}

    nh->cfg = cfginf;
#endif

    return 0;
}


char *get_type_str(char* str, int type)
{
	if (NULL == str)
		return NULL;
	switch (type)
	{
		case NORTEL_XAUTH_TYPE:
			strcpy(str, "NORTEL_XAUTH_TYPE");
			break;
		case XAUTH_USER_NAME:
			strcpy(str, "XAUTH_USER_NAME");
			break;
		case XAUTH_USER_PASSWORD:
			strcpy(str, "XAUTH_USER_PASSWORD");
			break;
		case CFG_3RDPARTY_LICENSE_NUMBER:
			strcpy(str, "CFG_3RDPARTY_LICENSE_NUMBER");
			break;
		case CFG_3RDPARTY_VERSION_DATA:
			strcpy(str, "CFG_3RDPARTY_VERSION_DATA");
			break;
		case KEEPALIVE_TIME_INTERVAL:
			strcpy(str, "KEEPALIVE_TIME_INTERVAL");
			break;
		case INTERNAL_IPV4_ADDRESS:
			strcpy(str, "INTERNAL_IPV4_ADDRESS");
			break;
		case INTERNAL_IPV4_NETMASK:
			strcpy(str, "INTERNAL_IPV4_NETMASK");
			break;
		case INTERNAL_IPV4_DNS:
			strcpy(str, "INTERNAL_IPV4_DNS");
			break;
		case CFG_NAT_KEEPALIVE_INTERVAL:
			strcpy(str, "CFG_NAT_KEEPALIVE_INTERVAL");
			break;
		case CFG_BIFURCATION:
			strcpy(str, "CFG_BIFURCATION");
			break;
		case CFG_DOMAIN_NAME:
			strcpy(str, "CFG_DOMAIN_NAME");
			break;
		default:
			// wrong type
			strcpy(str, "UNKNOWN_TYPE");
	}
	return str;
}

void print_ret(int type, int ret)
{
	char type_str[255] = {'\0'};

	if (ret == 0)
		plog(LLV_DEBUG, LOCATION, NULL,
				"Registering %s(0x%04x) ok!\n",
				get_type_str(type_str, type),
				type);
	else
		plog(LLV_ERROR, LOCATION, NULL,
				"Registering %s(0x%04x) failed!\n",
				get_type_str(type_str, type),
				type);
}

int turnpike_nortel_init(short ver, void *cp, void **gp)
{
    /* I declare this cos I dont want to typecast void at every place */

    struct nortelHandle *nh = NULL;
	int ret = 0;

    /* Perform necessary version checks if required */
    if (ver > TURNPIKE_INTERFACE_VER){
        plog(LLV_ERROR,LOCATION,NULL,
            "Version Mismatch: Supported till : %d\tReceived : %d\n",
            TURNPIKE_INTERFACE_VER,ver);
            return -1;
    }
    

    plog(LLV_DEBUG,LOCATION,NULL,"\n Inside turnpike_nortel_init %p \n" , *gp);
    *gp = malloc ( sizeof(struct nortelHandle)); //Should be freed during de-init 

    if (!(*gp)){
        return -1;
    }

    nh = (struct nortelHandle *)(*gp);
    strcpy(nh->assignedDomainName, "");
    memset(nh, 0, sizeof(struct nortelHandle));

    /* 
     * Copy the config priv data from GUI plugin into ike plugin's global priv data 
     * This should be a 'deep copy' as cfg has all dynamic memory.
     */

    if(cp){
        if(cp2gp(nh, cp)<0){
            plog(LLV_ERROR,LOCATION,NULL,"\n CP2GP FAILED \n" );
            //		printf("\n CP2GP FAILED \n" );
            return -1;
        }
    }

    /* Register all the handlers */
    //Quick mode start  - Notify.
    //
    plog(LLV_DEBUG,LOCATION,NULL,"Registering Quick mode start payload  \n");
    ret = registerQMStartCallback();
    
    //info payload - Notify.
    plog(LLV_DEBUG,LOCATION,NULL,"Registering info notify payload  \n");
    registerNotifyPayloadCallback();
    
    //pl e check
    plog(LLV_DEBUG,LOCATION,NULL,"Registering pl e check \n");
    registerIsPayloadExistencyCheckCallback();
    
    //pfkey notify
    plog(LLV_DEBUG,LOCATION,NULL,"Registering pfkey notifications \n");
    registerIsPhase2CompleteCallback();
    
    //Timer
    plog(LLV_DEBUG,LOCATION,NULL,"Registering isRekeyRequired \n");
    registerIsRekeyReqCallback();
    
    //VID
    plog(LLV_DEBUG,LOCATION,NULL,"Registering VID \n");
    registerVIDPayloadCallback();

    //Check VID
    plog(LLV_DEBUG,LOCATION,NULL,"Registering Check VID \n");
    registerCheckVIDPayloadCallback();

    //OpaqueID
    plog(LLV_DEBUG,LOCATION,NULL,"Registering Opaque ID  \n");
    registerOpaqueIDCallback();

    //PSK
    plog(LLV_DEBUG,LOCATION,NULL,"Registering PSK  \n");
    registerGeneratePSKCallback();

    //IKE Attr
    plog(LLV_DEBUG,LOCATION,NULL,"Registering IKE ATTR CES CLIENT VER \n");
    registerCESClientVerCallback();
    registerXtndedContivityVersionCallback();

    //IPsec Attr
    plog(LLV_DEBUG,LOCATION,NULL,"Registering IPsec ATTR UDP ENCAP \n");
    registerUDPEncapCallback();

    //Cfg Attr

    /* REQUESTS */

    //XAUTH TYPE
    ret = registerCfgAttrReqCallback (NORTEL_XAUTH_TYPE,
		   	cfgXauthTypeCallback);
	print_ret (NORTEL_XAUTH_TYPE, ret);

    //XAUTH User Name 
    ret = registerCfgAttrReqCallback (XAUTH_USER_NAME,
		   	cfgXauthUserNameCallback);
	print_ret (XAUTH_USER_NAME, ret);

    //XAUTH Passwd 
    ret = registerCfgAttrReqCallback (XAUTH_USER_PASSWORD,
		   	cfgXauthPasswdCallback);
	print_ret (XAUTH_USER_PASSWORD, ret);

    //3rd party license number 
    ret = registerCfgAttrReqCallback (CFG_3RDPARTY_LICENSE_NUMBER,
			cfg3PartyLicenseCallback);
	print_ret (CFG_3RDPARTY_LICENSE_NUMBER, ret);

    //3rd party license version 
    ret = registerCfgAttrReqCallback (CFG_3RDPARTY_VERSION_DATA,
			cfg3PartyVersionCallback);
	print_ret (CFG_3RDPARTY_VERSION_DATA, ret);

    /* SET */
    //Keep alive interval
    ret = registerCfgAttrSetCallback (KEEPALIVE_TIME_INTERVAL,
		  	cfgAckKACallback);
	print_ret (KEEPALIVE_TIME_INTERVAL, ret);

    //Internal IPV4 Address   
    ret = registerCfgAttrSetCallback (INTERNAL_IPV4_ADDRESS,
		   	cfgAckIPv4Callback);
	print_ret (INTERNAL_IPV4_ADDRESS, ret);

    //Internal IPV4 Address mask   
    ret = registerCfgAttrSetCallback (INTERNAL_IPV4_NETMASK,
		   	cfgAckIPv4MaskCallback);
	print_ret (INTERNAL_IPV4_NETMASK, ret);
	
    //Internal DNS Addr   
    ret = registerCfgAttrSetCallback (INTERNAL_IPV4_DNS,
		   	cfgAckIPv4DnsCallback);
	print_ret (INTERNAL_IPV4_DNS, ret);

    ret = registerCfgAttrSetCallback (CFG_NAT_KEEPALIVE_INTERVAL,
		   	cfgAckNatKeepAliveIntervalCallback);
	print_ret (CFG_NAT_KEEPALIVE_INTERVAL, ret);

    //CFG BIFURCATION   
    ret = registerCfgAttrSetCallback(CFG_BIFURCATION, cfgAckBifurcationCallback);
	print_ret(CFG_BIFURCATION, ret);
    
    //Domain Names
    registerCfgAttrSetCallback(CFG_DOMAIN_NAME, cfgAckIPv4DomainNameCallback); 
	print_ret(CFG_DOMAIN_NAME, ret);
 
    // CFG_SET hook
    plog(LLV_DEBUG,LOCATION,NULL,"Registering CFG_SET_ACK Hook \n"); 
    if (registerCfgSetAckCallback () < 0)
       plog (LLV_WARNING, LOCATION, NULL, "cannot register CFG_SET_ACK callback !");


    /* CFG PRIV TYPES*/

    //XAUTH OK
    plog(LLV_DEBUG,LOCATION,NULL,"Registering XAUTHOK \n");
    registerCfgXauthOKCallback(cfgXauthOKCallback);

    //XAUTH FAILURE
    plog(LLV_DEBUG,LOCATION,NULL,"Registering XAUTHFAIL \n");
    registerCfgXauthFAILCallback(cfgXauthFAILCallback);
    
    //register NATT Options
    plog(LLV_DEBUG,LOCATION,NULL,"Registering NATT options \n");
    registerSetNattOptionsCallback();

    return 0;
}

int turnpike_nortel_getdata(
    short ver,
    void *gprivdata,
    int inlen, 
    char *inbuf, 
    int *outlen, 
    char **outbuf)
{
	u_int32_t cmd = GETDATA_IPV4ADDRMASK;
	char *cur = NULL;

	/* Perform necessary version checks if required */
	if (ver > TURNPIKE_INTERFACE_VER){
		plog(LLV_ERROR,LOCATION,NULL,
				"Version Mismatch: Supported till : %d\tReceived : %d\n",
				TURNPIKE_INTERFACE_VER,ver);
		return -1;
	}
	if (!outlen || !outbuf)
		return -1; /* return error invalid parameters */
	*outlen = 0;
	*outbuf = NULL;

	if (inlen) {
		while (inlen >= sizeof(cmd)) {
			cmd = *(u_int32_t *)(inbuf);
			inbuf += sizeof(u_int32_t);
			inlen -= sizeof(u_int32_t);
			switch(cmd)
			{
				case GETDATA_VERSION:
					if (!(*outbuf = malloc(sizeof(u_int32_t))))
						return -1; /**/
					*outlen = sizeof(u_int32_t);
					*(u_int32_t *)(*outbuf) = NORTEL_IKEPLUGIN_VERSION;
					break;
				case GETDATA_IPV4ADDRMASK:
					/* Input data: none */
					/* Output data: Assigned IP Address, Assinged Net Mask, Primary DNS Addr */
					if (!(*outbuf = malloc(sizeof(u_int32_t) + sizeof(u_int32_t) + sizeof(u_int32_t) + sizeof(char) * 256)))
						return -1; /* Return error code for malloc */
					cur = *outbuf;
					*(u_int32_t *)(cur) =
						((struct nortelHandle *)gprivdata)->assignedIPAddr;
					*outlen += sizeof(u_int32_t); cur += sizeof(u_int32_t);
					*(u_int32_t *)(cur) =
						((struct nortelHandle *)gprivdata)->assignedNetMask;
					*outlen += sizeof(u_int32_t); cur += sizeof(u_int32_t);
					*(u_int32_t *)(cur) =
						((struct nortelHandle *)gprivdata)->assignedDNSAddrPrimary;
					*outlen += sizeof(u_int32_t); cur += sizeof(u_int32_t);

					// support the secondary dns addr
					*(u_int32_t *)(cur) =
						((struct nortelHandle *)gprivdata)->assignedDNSAddrSecondary;
					*outlen += sizeof(u_int32_t); cur += sizeof(u_int32_t);

					strcpy((char *)(cur), ((struct nortelHandle *)gprivdata)->assignedDomainName);
					*outlen += sizeof(char) * (1 + strlen(((struct nortelHandle *)gprivdata)->assignedDomainName));
					cur += sizeof(char) * (1 + strlen(((struct nortelHandle *)gprivdata)->assignedDomainName));

					break;
				case GETDATA_DNSADDR:
					/* Input data: none */
					/* Output data: DNS address list */
					break;
				default:
					plog(LLV_DEBUG,LOCATION,NULL,"Unknown getdata command \n");
					break;
			}
		}
	} else { // If no command is specified return
		if (!(*outbuf = (char *)malloc(sizeof(u_int32_t) + sizeof(u_int32_t))))
			return -1; // Return error code for malloc

		*(u_int32_t *)(*outbuf) =
			((struct nortelHandle *)gprivdata)->assignedIPAddr;
		*outlen += sizeof(u_int32_t); *outbuf += sizeof(u_int32_t);
		*(u_int32_t *)(*outbuf) =
			((struct nortelHandle *)gprivdata)->assignedNetMask;
		*outlen += sizeof(u_int32_t); *outbuf += sizeof(u_int32_t);
	}
	return 0;
}

int turnpike_nortel_deregister(void *gprivdata)
{
 //clean-up gprivdata before .so unloads
 struct nortelHandle *nortelHdl = (struct nortelHandle *)gprivdata;
 struct configInf *cfg = NULL;

 //bring ip alias down
 ipaliasdown();

 dnsdown();

 if(nortelHdl)
  cfg = nortelHdl->cfg;
  
 if(cfg)
 {
	if(cfg->uname.l)
	 	free(cfg->uname.v);
	if(cfg->upass.l)
		free(cfg->upass.v);
	if(cfg->grpname.l)
		free(cfg->grpname.v);
	if(cfg->grppasswd.l)
		free(cfg->grppasswd.v);
	free(cfg);
 } 
 
 if(nortelHdl && nortelHdl->rt_list)
 {
 	if(nortelHdl->rt_list->l)
		free(nortelHdl->rt_list->v);
	free(nortelHdl->rt_list);
 } 
 
 if(nortelHdl)
	 free(nortelHdl);

 tpike_deregister_handlers("nortel");

 return TPIKE_STATUS_SUCCESS;
}
