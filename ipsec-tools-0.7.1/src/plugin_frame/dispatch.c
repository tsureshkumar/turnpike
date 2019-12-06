
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
#include <stdlib.h>
#include <stdarg.h>
#include "common.h"
#include "framework.h"
#include "error.h"
#include "hashtable.h"

int get_hook_handler_info(struct hookpoint *hp, int absolutepos, struct handlerinfo **hi, int *incount, void **tv)
{
	int status = TPIKE_ERR_HASH_MATCH_NOT_FOUND;

	status = get_handler_match_in_hash_bucket(hp, hi);

	// *incount = getType((*hi)->DataTypeToBeSent, tv);	//return value?

	return status;
}

#if 0
int getType (u_int32_t dataTypeMask, TV *tvl)
{
	int i = 0;
	u_int32_t j = 1;
	while (j != 0x80000000 ){
		if ( dataTypeMask & j )
		{
			tvl[i].t = j;
			tvl[i].v = NULL;
			i++;
		}
		j<<=1;
	}
	return i;
}
#endif

int tpike_dispatch_generic(struct hookpoint *hp, void *in, void **out)
{
	struct handlerinfo *hi;
	int status;
	struct plugininfo *plugin;

	if ((status = get_handler_match_in_hash_bucket(hp, &hi)) == TPIKE_STATUS_SUCCESS) {
		// TODO: Validate that the minimum input arguments are present
		// TODO: Validate that the output arguments are sufficient
		if (hi->callback) {
			// Obtain gpriv data
			plugin = get_plugin_info(hi->plugin_name);

			if(!plugin)
				return TPIKE_ERR_PLUGIN_NOT_REGISTERED;

			status = (*(hi->callback))(plugin->gprivdata, hi->hprivdata, in, out);
			return status;
		}
		else
			return TPIKE_ERR_HASH_MATCH_NOT_FOUND;
	}
	return status;
}

int tpike_pack_in(void **inarr, u_int32_t noofparams, ...)
{
	int i;
	struct tvarr *in;
	va_list(ap);

	if (noofparams == 0) /* no parameters to pass, send NULL */
		return TPIKE_STATUS_SUCCESS;

	va_start(ap, noofparams);
	if (((*inarr) = malloc(sizeof(struct tvarr) + (noofparams - 1) * (sizeof(struct tv)))) == NULL)
		return TPIKE_ERR_MEM_ALLOC_FAILED;
	in = (*inarr);

	in->noofvals = noofparams;
	for (i = 0; i < noofparams; i++)
	{
		in->tv[i].type = va_arg(ap, int);
		in->tv[i].val = va_arg(ap, void *);
	}
	return TPIKE_STATUS_SUCCESS;
}

int tpike_pack_out(void *outarr, u_int32_t noofparams, ...)
{
	int i, j;
	int type, found = 0;
	struct tvarr *out = (struct tvarr *)(outarr);
	va_list(ap);

	va_start(ap, noofparams);
	for (i = 0; i < noofparams; i++)
	{
		type = va_arg(ap, int);
		found = 0;
		for (j = 0; j < out->noofvals; j++)
		{
			if (type == out->tv[i].type)
			{
				*(va_arg(ap, void **)) = out->tv[i].val;
				found = 1;
				break;
			}
			if (!found)
				return TPIKE_ERR_PLUGIN_ARG_MISMATCH;
		}
	}
	return TPIKE_STATUS_SUCCESS;
}
