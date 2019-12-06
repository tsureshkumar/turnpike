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

#ifndef __H_ERROR_HANDING__
#define __H_ERROR_HANDING__ 1

#define ERR_CODE_STRING              "VPNCLIENT-" 
#define MAX_ERR_STRING_LEN           256 /* no error messages should exceed 256 chars */

#define CLI_ERR_BASE                 0x1100
#define GUI_ERR_BASE                 0x1200
#define GUICLI_ERR_BASE              0x1300

#define IS_CLI_ERROR(x)            ((x) > 0 && (x) < CLI_ERR_BASE)
#define IS_GUI_ERROR(x)            ((x) >= CLI_ERR_BASE && (x) < GUI_ERR_BASE)
#define IS_UI_ERROR(x)             ((x) >= GUI_ERR_BASE && (x) < GUICLI_ERR_BASE)

#ifdef NOTUSED_RIGHT_NOW
#define VPNCMGR_ERR_BASE             0x1300
#define RACOON_ERR_BASE              0x1500
#define IPSEC_ERR_BASE               0x1600
#define PLUTO_ERR_BASE               0x1700
#define AUTHNMAS_ERR_BASE            0x1800
#define AUTHXXX_ERR_BASE             0x1900
#endif


char * _errString (int err_code);

#endif // __H_ERROR_HANDING__
