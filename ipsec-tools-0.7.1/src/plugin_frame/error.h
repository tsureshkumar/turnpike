
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

#ifndef _PLUGIN_ERROR_H
#define _PLUGIN_ERROR_H

#define TPIKE_STATUS_SUCCESS           0x00000000
#define PLUGIN_FRAME_STATUS_SUCCESS           0x00000000

/* Framework errors start at 0xFFFFFFFF (-1) */
#define TPIKE_ERR_HASH_TABLE_OVERFLOW         0xFFFFFFFF
#define TPIKE_ERR_MEM_ALLOC_FAILED            0xFFFFFFFE
#define TPIKE_ERR_PLUGIN_NOT_REGISTERED       0xFFFFFFFD
#define TPIKE_ERR_HOOK_ALREADY_REGISTERED     0xFFFFFFFC
#define TPIKE_ERR_PLUGIN_REGISTRATION_FAILURE 0xFFFFFFFB
#define TPIKE_ERR_SYM_LOAD_FAILURE	      0xFFFFFFFA
#define TPIKE_ERR_HASH_MATCH_NOT_FOUND	      0xFFFFFFF9
#define TPIKE_ERR_SO_LOAD_FAILURE             0xFFFFFFF8
#define TPIKE_ERR_PLUGIN_ARG_MISMATCH         0xFFFFFFF9

/* Generic plugin errors start at 0xFFFFFF00 (-255) */
#define TPIKE_ERR_PLUGIN_GENERIC	      0xFFFFFF00
#define TPIKE_ERR_PLUGIN_MEM_ALLOC_FAILED     0xFFFFFE00

#define TPIKE_OK(x) ((x) == TPIKE_STATUS_SUCCESS)

#endif /* _PLUGIN_ERROR_H */
