
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

#define IKE_PH1_ESTABLISHED             0x0100
#define IKE_PH1_DELETED                 0x0101
#define IKE_XAUTH_SUCCESS               0x0102
#define ISAKMP_MODE_CONFIG_SUCCESS      0x0103
#define IKE_PH2_ESTABLISHED             0x0104
#define IKE_PH2_DELETED                 0x0105
#define IKE_PEER_NOT_REACHABLE          0x0106
#define IKE_PEER_NOT_RESPONDING         0x0107
#define IKE_PEER_TERMINATED_SA          0x0108
#define IKE_TERMINATED                  0x0109
#define IKE_EVENT_Q_OVERFLOW            0x010A
#define IKE_XAUTH_FAILED                0x0110
#define IKE_PH1_AUTH_FAILED             0x0111

#define CAN_NOT_OPEN_FILE               0x1200
#define INVALID_SERVER_IPADDR           0x1201
#define IKE_DAEMON_FAILURE              0x1202
#define FAILED_TO_CONNECT_TO_GATEWAY    0x1203
#define CAN_NOT_XML_PARSE_FILE          0x1204
#define BAD_PROFILE                     0x1205
#define DIRECTORY_DOES_NOT_EXIST        0x1206
#define CAN_NOT_SET_USR_ENV             0x1207
#define PROFILE_FILE_NOT_FOUND          0x1208
#define TOO_MANY_ARGUMENTS              0x1209
#define VERBOSE_MODE_SPECIFIED_ALONE    0x120A
#define PROFILE_FILE_DOES_NOT_EXIST     0x120B
#define CERT_PATH_DOES_NOT_EXIST        0x120C
#define FAILED_TO_EXTRACT_CERT          0x120D
//#define FAILED_TO_CONNECT_TO_GATEWAY  0x120E
#define PLUGIN_REPARSE_FUNC_MISSING     0x120F
#define INVALID_GW_IP_ADDR              0x1210
#define DNS_RESOLUTION_FAILED           0x1211
#define GATEWAY_TIME_OUT                0x1212
#define PROFILE_DIRECTORY_EMPTY         0x1213
#define AUTH_FAILED                     0x1214
#define PEER_DISCONNECTED               0x1215
