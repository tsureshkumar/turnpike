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
#include <assert.h>
#include <string.h>
#include "vpncErrorHandling.h"

static const char * get_error_message (int ecode);
static const char * get_error_prefix (int ecode);
int errgen_format_error (int ecode, char *out_str, int len);

/* remove this public function when no one uses */
char *
errString(int ecode, char *out_str)
{
	errgen_format_error (ecode, out_str, MAX_ERR_STRING_LEN);
	return out_str;
}

/**
 * gets the error string for the error code and 
 * formats it suitably.
 */
int 
errgen_format_error (int ecode, char *out_str, int len)
{
	const char *err_msg = get_error_message (ecode);
	int ret = 0;

	assert (out_str != NULL);
	
	if (IS_GUI_ERROR (ecode)) {
		ret = strlen (strncat (out_str, err_msg, len-1));
		return ret;
	}
	
	ret = snprintf (out_str, len, "%s-%04d:%s", 
			get_error_prefix (ecode), ecode, err_msg);
	return ret >= len ? len : ret;
}


static const char *
get_error_message (int ecode)
{
	return (const char *) _errString (ecode);
}

static const char *
get_error_prefix (int ecode)
{
	if (IS_GUI_ERROR (ecode))
		return NULL;
		
	if (IS_CLI_ERROR (ecode))
		return ERR_CODE_STRING "CLI";
	
	if(IS_UI_ERROR (ecode))
		return ERR_CODE_STRING "UI";

	return ERR_CODE_STRING "UNKNOWN";
}

