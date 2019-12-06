
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

#ifndef __TPIKE_FRAMEWORK__
#define __TPIKE_FRAMEWORK__

/****************NOTES ************************
1. Multiple plugins will be stored in the struct pluginlist with priority.
2. A Global priv data for each plugin (in addition to the hook point specific priv data) that will be opaque to framework.
3. Register Handler returns ALREADYREGISTERED if someother plugins has registered.
4. Before registering the plugin should check for dependencies with other plugins using isPluginRegisterted,
*************************************************/

#include <sys/types.h>
#include <stdlib.h>

/* Defines */

#if 0
/* Types */
#define PAYLOAD_TYPE		0x01
#define	ATTRIBUTE_TYPE		0x02

/* Attribute types */
#define IKE_ATTRIB_TYPE		0x01
#define CONFIG_ATTRIB_TYPE	0x02
#endif

typedef int (tpike_plugin_init_func_t)(short ver, void *cp, void **privdata);
typedef int (tpike_plugin_getdata_func_t)(short version, void *gpdata, int inlen, char *inbuf, int *outlen, char **outbuf);
typedef int (tpike_plugin_deregister_func_t)(void *privdata);
/* Data Structures */

/* Structure handling multiple plugins */
struct plugininfo {
    char *plugin_name; /* Got thru' adminport */
    void *gprivdata;  /* Global (common to whole plugin) priv data */
    void *so_handle;

    tpike_plugin_init_func_t *init_fn;
    tpike_plugin_getdata_func_t *getdata_fn;
    tpike_plugin_deregister_func_t *deregister_fn;

    struct plugininfo *next;
};



/* Functions to be implemented by Framework for framework only!*/
struct plugininfo *get_plugin_info(char *plugin_name);


/*Updated Register Handler */

/*Consumed by plugin */
struct plugininfo *get_registered_plugin(char *);
struct plugininfo *add_plugin_to_list(char *);
void remove_plugin_from_list(char *);
void free_plugin_info_all(struct plugininfo *);

#endif
