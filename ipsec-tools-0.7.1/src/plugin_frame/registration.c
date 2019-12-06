
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

#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <dlfcn.h>

#include "config.h"
/* Framework headers */
#include "common.h"
#include "framework.h"
#include "hashtable.h"
#include "error.h"

/* Racoon headers for logging */
#include "plog.h"
#include "misc.h"

/* Global plugininfo list */
struct plugininfo *plugin_info  = NULL;


struct plugininfo *get_plugin_info(char *plugin_name)
{
	struct plugininfo *temp;

	temp = plugin_info;
	while(temp != NULL) {
		if(strcmp(temp->plugin_name, plugin_name) == 0)
			return temp;
		temp = temp->next;
	}
	return NULL;
}

/************************************************************************************************************
Function    - is_plugin_registered
Input       - plugin name
Output      - pointer to the plugin
Description - This will search for the plugin in the pluginInfo list based on the plugin name.
************************************************************************************************************/

u_int8_t is_plugin_registered(char *plugin_name)
{
	if(get_plugin_info(plugin_name))
		return 1;

	return 0;
}

/************************************************************************************************************
Function    - addPluginToList
Input       - plugin name
Output      - pointer to the plugin
Description - This will add the plugin in the pluginInfo list based on the plugin name.
************************************************************************************************************/
struct plugininfo *add_plugin_to_list(char *plugin_name)
{
	struct plugininfo *newinfo, *temp;
	int plugin_len = 0;

	if(plugin_name == NULL)
		return NULL;

	newinfo = (struct plugininfo *)malloc(sizeof(struct plugininfo));
	if(newinfo == NULL)
		return NULL;

	memset(newinfo,0,sizeof(newinfo));

	plugin_len = strlen(plugin_name);

	newinfo->plugin_name = (char *)malloc(plugin_len + 1);
	if(newinfo->plugin_name == NULL)	//malloc failed
		return NULL;

	memset(newinfo->plugin_name, 0, plugin_len + 1);
	strncpy(newinfo->plugin_name, plugin_name, plugin_len);

	newinfo->gprivdata = NULL;
	newinfo->so_handle = NULL;
	newinfo->next = NULL;

	//add to end of list
	temp = plugin_info;
	if(!temp)
	{
		plugin_info = newinfo;
	}
	else
	{
		while(temp->next)
		{
			temp = temp->next;
		}
		temp->next = newinfo;
	}
	return newinfo;
}


/* *****************************************************************************/
/* Function    - removePluginFromList */
/* Input       - plugin name */
/* Output      -  */
/* Description - This will remove the plugin in the pluginInfo list */
/*               based on the plugin name */
/* ******************************************************************************/
void remove_plugin_from_list(char *plugin_name)
{
	struct plugininfo *toremove, *temp;

	if(!strcmp(plugin_info->plugin_name, plugin_name))
	{
		toremove = plugin_info;
		plugin_info = plugin_info->next;
		//deep free plugin info
		free_plugin_info_all(toremove);
		free(toremove);
	}
	else
	{
		temp = plugin_info;
		while(temp->next)
		{
			if(!strcmp(temp->next->plugin_name, plugin_name))
			{
				toremove = temp->next;
				temp->next = temp->next->next;
				//deep free plugin info
				free_plugin_info_all(toremove);
				free(toremove);
			}
			temp = temp->next;
		}
	}

}

void free_plugin_info_all(struct plugininfo *plugin)
{
	if(plugin->plugin_name)
		free(plugin->plugin_name);
	/* Plugin would have freed the private data by now */
	/*
	// No need to free so_handle as it never got allocated (9.3 racoon crash on disconnect problem fix )
	if(plugin->so_handle)
	free(plugin->so_handle);
	*/
}

/***************************************************************************
 * Function    - registerHandler
 * Input       - plugin name, hookpoint, handlerinfo
 * Output      - success or failure or already registered
 * Description - This function will be called by the IKE plugin for each
 *               hookpoint to register the handlerinfo.
 **************************************************************************/
int tpike_register_handler(struct hookpoint *hp, struct handlerinfo *hi)
{
	int status;
	struct plugininfo *plugin;

	if((plugin = get_plugin_info(hi->plugin_name)) == NULL)
		return TPIKE_ERR_PLUGIN_NOT_REGISTERED;

	// update the handlerInfo for each hookpoint to have a backpointer to the plugin.
	//handlerInfo->plugin = plugin;

	//insert in hash table
	status = insert_in_hash_bucket(hp, hi, plugin);

	return status;
}

int tpike_deregister_handlers(char *plugin_name)
{
	/*   just clean up the hash_table.
TODO: Maintain a chain of handlers for each plugin,
clean up only the handlers registered by this plugin
*/
	clear_hash_table ();
	return 0;
}

int tpike_deregister_plugin_all()
{
	struct plugininfo *plugin = NULL;
	char sym_name[256];
	char *plugin_name = NULL;
	int retval = TPIKE_ERR_PLUGIN_GENERIC;
	int (*deregister_fn)(void *) = NULL;

	//de-register all plugins
	plugin = plugin_info;

	while(plugin)
	{
		if (!plugin->so_handle)
			return TPIKE_ERR_SO_LOAD_FAILURE;

		plugin_name = plugin->plugin_name;

		sprintf(sym_name, "turnpike_%s_deregister", plugin_name);
		if (!(deregister_fn = dlsym(plugin->so_handle, sym_name)))
			return TPIKE_ERR_SYM_LOAD_FAILURE;

		plugin->deregister_fn = deregister_fn;

		/* plugin's deregister function will clean-up private data
		   and deregister handlers */
		retval = (*deregister_fn)(plugin->gprivdata);

		/* plugin's IKE .so related clean-up is over, unload the .so */
		if(retval == TPIKE_STATUS_SUCCESS)
			retval = dlclose(plugin->so_handle);

		plugin = plugin->next;

		/* remove the plugin from the framework's plugin list */
		if(!retval)
		{
			remove_plugin_from_list(plugin_name);
		}
	}
	return retval;
}

int tpike_register_plugin(short ver, const char *pluginso, char *pluginname, void *cp)
{
	char sym_name[256] = "\0";
	void *so_handle = NULL;
	tpike_plugin_init_func_t *plugin_init_fn = NULL;
	struct plugininfo *plugin = NULL;

#if 0
	plog(LLV_DEBUG2, LOCATION, NULL, "about to call so: %s plugin name is :%s \n",pluginso, pluginname);
#else
	printf("about to call so: %s plugin name is :%s \n",pluginso, pluginname);
#endif
	if (is_plugin_registered(pluginname) == 0 )
	{
		//Add this plugin to my plugin list
		plugin = add_plugin_to_list(pluginname); //(plugin name)
		if(plugin == NULL)
			return TPIKE_ERR_PLUGIN_REGISTRATION_FAILURE;
	}
	else
	{
		plugin = get_plugin_info(pluginname);
	}

	//load plugin.
	if (!plugin)
		return TPIKE_ERR_PLUGIN_REGISTRATION_FAILURE;

	sprintf(sym_name, "turnpike_%s_init", pluginname);

	//so_handle = dlopen(pluginso, RTLD_LAZY);
	if (!plugin->so_handle)
		plugin->so_handle = dlopen(pluginso, RTLD_GLOBAL | RTLD_LAZY);

	if (plugin->so_handle){
#if 0
		plog(LLV_DEBUG, LOCATION, NULL, "Opened so: %s -- Searching for symbol %s\n",pluginso, sym_name);
#else
		printf("Opened so: %s -- Searching for symbol %s\n",pluginso, sym_name);

#endif

		plugin_init_fn = dlsym(plugin->so_handle, sym_name);
	}
	else
	{
#if 0
		plog(LLV_ERROR, LOCATION, NULL, "Failed opening so:%s, dlopen returned error:%s\n", pluginso, dlerror());
#else
		printf( "Failed opening so:%s, dlopen returned error:%s\n", pluginso, dlerror());

#endif
		//remove plugin from plugin list
		remove_plugin_from_list(pluginname);
		return TPIKE_ERR_SO_LOAD_FAILURE;
	}

#if 0
	plog(LLV_DEBUG2, LOCATION, NULL, "About to call init at memory location %x  with cp %x and plugin %x\n", plugin_init_fn, cp, plugin);
#else
	printf("About to call init at memory location %p  with cp %p and plugin %p\n", plugin_init_fn,
			cp, plugin);

#endif

	if(plugin_init_fn){
		(*plugin_init_fn)(ver, cp, &(plugin->gprivdata)); //(short, void *cp, void **gp)
		plugin->init_fn = plugin_init_fn;
	}
	else
	{
		//remove plugin from plugin list
		//    Commenting for debugging
		remove_plugin_from_list(pluginname);
		return TPIKE_ERR_SYM_LOAD_FAILURE;
	}
#ifndef NODEBUG
	dump_hash();
#endif

	return 0;
}

int tpike_plugin_getdata(short ver, char *pluginname, int inlen, char *inbuf,
			 int *outlen, char **outbuf)
{
	struct plugininfo *plugin = NULL;
	char sym_name[256];
	tpike_plugin_getdata_func_t *getdata_fn = NULL;

	if ((plugin = get_plugin_info(pluginname)) == NULL)
		return TPIKE_ERR_PLUGIN_NOT_REGISTERED;

	if (!plugin->so_handle)
		return TPIKE_ERR_SO_LOAD_FAILURE;
	sprintf(sym_name, "turnpike_%s_getdata", pluginname);
	if (!(getdata_fn = dlsym(plugin->so_handle, sym_name)))
		return TPIKE_ERR_SYM_LOAD_FAILURE;
	plugin->getdata_fn = getdata_fn;
	return (int) ((*getdata_fn)(ver, plugin->gprivdata, inlen, inbuf, outlen, outbuf));
}

