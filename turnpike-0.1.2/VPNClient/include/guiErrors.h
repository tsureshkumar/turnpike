
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

#define IKE_PH1_ESTABLISHED		0x0100
#define IKE_PH1_DELETED			0x0101
#define IKE_XAUTH_SUCCESS		0x0102 
#define ISAKMP_MODE_CONFIG_SUCCESS	0x0103 
#define IKE_PH2_ESTABLISHED		0x0104 
#define IKE_PH2_DELETED			0x0105 
#define IKE_PEER_NOT_REACHABLE		0x0106 
#define IKE_PEER_NOT_RESPONDING		0x0107 
#define IKE_PEER_TERMINATED_SA		0x0108 
#define IKE_TERMINATED			0x0109 
#define IKE_EVENT_Q_OVERFLOW		0x010A 
#define IKE_XAUTH_FAILED		0x0110 
#define IKE_PH1_AUTH_FAILED		0x0111 


#define INVALID_PROFILE_CERT		0x1100 
#define ENTER_IP			0x1102 
#define CERT_TOO_LENGTHY		0x1103 
#define ENTER_PASSWORD			0x1104 
#define CERT_ERROR			0x1105 
#define NO_PFX_FILES			0x1106 
#define CERT_DIR_DOES_NOT_EXIST		0x1107 
#define CERT_EXTRACTION_FAILED		0x1108 
#define INVALID_IP			0x1109 
#define GATEWAY_IP_INVALID		0x110A 
#define DNS_RESOLVE_FAILED		0x110B 
#define XML_PARSE_FAILED		0x110C 
#define INVALID_PROFILE			0x110D 
#define RACOON_CONNECT_FAILURE		0x110E 
#define COULD_NOT_SEND_TO_RACOON	0x110F 
#define COULD_NOT_SEND_TO_GATEWAY	0x1110 
#define FAILED_TO_RECEIVE_FROM_GATEWAY	0x1111 
#define RACOON_FAILED_TO_RESPOND	0x1112 
#define INVALID_GW_IP			0x1113 
#define GMODULE_SUPPORT_ERROR		0x1114 
#define HELP_FILE_NOT_LOCATED		0x1115 
#define PROFILE_DIR_DOES_NOT_EXIST	0x1116 
#define INVALID_PH2_NETWORK		0x1117 
#define INVALID_PH2_MASK		0x1118 
#define GATEWAY_CONNECTION_TIMEOUT	0x1119
#define INVALID_PROFILE_NAME		0x1120
#define INVALID_PROFILE_AUTH_DETAILS	0x1121
#define AUTHENTICATION_FAILED		0x1122
#define GATEWAY_NOT_RESPONDING		0x1123

