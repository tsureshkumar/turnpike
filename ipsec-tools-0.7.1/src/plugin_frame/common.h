
/************************************************************************************
*   Copyright (c) 2005, Novell Inc.,                                                *
*   All rights reserved.                                                            *
*                                                                                   *
*   Redistribution and use in source and binary forms, with or without              *
*   modification, are permitted provided that the following conditions              *
*   are met:                                                                        *
*   1.  Redistributions of source code must retain the above copyright              *
*       notice, this list of conditions and the following disclaimer.               *
*   2.  Redistributions in binary form must reproduce the above copyright           *
*       notice, this list of conditions and the following disclaimer in the         *
*       documentation and/or other materials provided with the distribution.        *
*   3.  Neither the name of the Novell nor the names of its contributors            *
*       may be used to endorse or promote products derived from this software       *
*       without specific prior written permission.                                  *
*   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND *
*   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE           *
*   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE      *
*   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE *
*   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL      *
*   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS         *
*   OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)           *
*   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT      *
*   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY       *
*   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF          *
*   SUCH DAMAGE.                                                                    *
*************************************************************************************/

#ifndef __TPIKE_COMMON_H__
#define __TPIKE_COMMON_H__

/****************NOTES ************************
1. Multiple plugins will be stored in the struct pluginlist with priority.
2. A Global priv data for each plugin (in addition to the hook point specific priv data) that will be opaque to framework.
3. Register Handler returns ALREADYREGISTERED if someother plugins has registered.
4. Before registering the plugin should check for dependencies with other plugins using isPluginRegisterted,
*************************************************/

#include <sys/types.h>

/* Defines */

/* DataTypes */
#define TPIKE_DTYPE_STRUCTISAKMPGEN	0x0001
#define TPIKE_DTYPE_STRUCTISAKMPDATA	0x0002
#define TPIKE_DTYPE_STRUCTVCHAR		0x0004
#define TPIKE_DTYPE_STRUCTPAYLOADLIST	0x0008
#define TPIKE_DTYPE_INT32PT             0x0010
#define TPIKE_DTYPE_STRUCTIPH1          0x0020
#define TPIKE_DTYPE_STRUCTNATTOPTIONS   0x0040

//Payload types
#define PRIVATE_NATTVID_PAYLOAD_TYPE	0x0001
#define PRIVATE_VID_PAYLOAD_TYPE	0x0002

//#define STRUCTIPH1		0x0010
//#define STRUCTIPH2		0x0020
//#define STRUCTCADDRT	        0x0040

/* Types */
#define PAYLOAD_TYPE		0x01
#define	ATTRIBUTE_TYPE		0x02
#define NATT_OPTIONS_TYPE	0x03

#define IS_REKEYREQ_TYPE        0x04
#define IS_PLECHECK_TYPE        0x05

#define PFKEY_MSG_TYPE          0x06
#define IKE_NEGO_STATE_TYPE     0x07


/* Attribute types */
#define IKE_ATTRIB_TYPE		0x01
#define CONFIG_ATTRIB_TYPE	0x02
#define IPSEC_ATTRIB_TYPE	0x03
#define ISAKMP_ATTRIB_TYPE	0x04
#define CONFIG_ATTRIB_ACK_TYPE  0x05

#if 0
/* Attribute types */
#define IKEATTR_TYPE		0x01
#define CFGATTR_TYPE	        0x02
#endif

/* Data Structures */

/*TV */
typedef struct tv
{
    int type;
    void *val;
}TV;

struct tvarr {
    int noofvals;
    struct tv tv[1];
};

/* Updated Hookpoint */
struct hookpoint {
	u_int8_t type;
	u_int8_t payloadtype; /*If type==payload => payload type as defined, else 0 */
	u_int8_t subtype; /* Config attr => SET/ACK/REQ/REP/PrivType. Payload => SubType */
	u_int32_t position; /* ijk */
	u_int8_t isoptional;
	/*Identifying the payload/ike attr type */
        u_int32_t keylen;
        void *key; /*Payload =>, attribute etc. */
};

/* Updated Handler Info */
struct handlerinfo {
        char *plugin_name;
	void *hprivdata;             /*Plug-in's priv data */
	u_int32_t datatypein;  /* Flag logical OR of IN DataTypes defiend above */
	u_int32_t datatypeout; /* Flag logical OR of OUT DataTypes defiend above */
	int (*callback)(void *, void *, void *, void **); /* Prototype will be int func(void *gprivdata, void *hprivdata, void *INARRAY, void **OUTARRAY); */
};

typedef int (*plugin_init)(void *gprivdata, void *hprivdata,
			   void *inarray, void **outarray);
typedef int (*plugin_getdata)(int inlen, char *inbuf,
			      int *outlen, char **outbuf);

/* Consumed by plugin */
u_int8_t tpike_is_plugin_registered(char *plugin_name);
int tpike_register_handler(struct hookpoint *,
			   struct handlerinfo *);
int tpike_deregister_handlers(char *plugin_name);

/* Consumed by Racoon */
int tpike_gethook_handlerinfo(struct hookpoint *hp,
			      int absolutepos, struct handlerinfo **hi,
			      int *incount, void **tv);
int tpike_dispatch_generic(struct hookpoint *hp, void *in, void **out);
int tpike_pack_in(void **inarr, u_int32_t noofparams, ...);
int tpike_pack_out(void *outarr, u_int32_t noofparams, ...);

/* Consumed by adminport */
int tpike_register_plugin(short ver, const char *pluginso, char *pluginname, void *cp);
int tpike_plugin_getdata(short ver, char *pluginname, int inlen, char *inbuf,
			 int *outlen, char **outbuf);
int tpike_deregister_plugin_all();


/* Helper macro to make the 'hookpoint'. Consumed by racoon alone. */
#define  mk_hookpoint(typ, pratype, prasubtype, pos, optional, klen, keyval, hp) \
 { \
   hp->type = (typ); hp->payloadtype = (pratype); hp->subtype = (prasubtype); hp->position = (pos); \
   hp->keylen = (klen); \
   if (hp->keylen == 0) \
     hp->key = 0; \
   else  { \
     hp->key = vmalloc(hp->keylen); \
     if (hp->key && (keyval)) memcpy(hp->key, (keyval), (klen)); else hp->keylen = 0; \
   }\
 }

#endif
