
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

/*
The paylaod state will be defined as follows:

u_int32_t payload_state = i|j|k1|k2

i- 0ne byte
j - One byte
k1 -One byte
k2 - One byte

i- exchange type
j- Message index
k1- after payload
k2- before payload
*/

/*'i' - exchange type is defined as in RFC as follows: u_int8_t*/

#define ISAKMP_ETYPE_BASE	1 /* Base */
#define ISAKMP_ETYPE_IDENT	2 /* Identity Proteciton */
/*#define ISAKMP_ETYPE_AUTH	3*/ /* Authentication Only */
#define ISAKMP_ETYPE_AGG	4 /* Aggressive */
#define ISAKMP_ETYPE_INFO	5 /* Informational */
#define ISAKMP_ETYPE_CFG	6 /* Mode config */
#define ISAKMP_ETYPE_QUICK	32/* Quick Mode */
#define ISAKMP_ETYPE_ALLPHASE1  0xfd
#define ISAKMP_ETYPE_ALLPHASE2  0xfe
#define ISAKMP_ETYPE_ALL	0xff

/*'j' - Message Index - u_int8_t*/
/*
MSb:
Initiator - 0
Responsder - 1

Next bit:
Recv: 0
Send: 1

Next 6 bits:
Message Index
*/

#define TPIKE_MIDX_INITIATOR 0x10
#define TPIKE_MIDX_RESPONDER 0x20
#define TPIKE_MIDX_RECEIVE   0x40
#define TPIKE_MIDX_SEND	  0x80
#define TPIKE_MIDX_ANY       0x00

#define TPIKE_MAX_MESSAGE    16

#define ONE 1

/*Initiator */

#define INITIATOR_RECIEVE 	TPIKE_MIDX_INITIATOR|TPIKE_MIDX_RECEIVE
#define INITIATOR_SEND 	        TPIKE_MIDX_INITIATOR|TPIKE_MIDX_SEND

/*Responder*/
#define RESPONDER_RECEIVE    	TPIKE_MIDX_RESPONDER|TPIKE_MIDX_RECEIVE
#define RESPONDER_SEND          TPIKE_MIDX_RESPONDER|TPIKE_MIDX_SEND|(ONE)

/*Initiator */

#define INITIATOR_RECIEVE_ONE 	INITIATOR_RECIEVE|ONE
#define INITIATOR_SEND_ONE 	INITIATOR_SEND|ONE

#define INITIATOR_RECIEVE_TWO 	INITIATOR_RECIEVE|(ONE<<1)
#define INITIATOR_SEND_TWO 	INITIATOR_SEND|(ONE<<1)

#define INITIATOR_RCVD_THREE 	INITIATOR_RECIEVE|(ONE<<2)
#define INITIATOR_SEND_THREE 	INITIATOR_SEND|(ONE<<2)

/*Responder*/
#define RESPONDER_RCVD_ONE 	RESPONDER_RECEIVE|(ONE)
#define RESPONDER_SEND_ONE 	RESPONDER_SEND|(ONE)

#define RESPONDER_RCVD_TWO 	RESPONDER_RECEIVE|(ONE<<1)
#define RESPONDER_SEND_TWO 	RESPONDER_SEND|(ONE<<1)

#define RESPONDER_RCVD_THREE 	RESPONDER_RECEIVE|(ONE<<2)
#define RESPONDER_SEND_THREE 	RESPONDER_SEND|(ONE<<2)

/*

'k1' (is payload after) - u_int8_t
'k2' (is payload before) - u_int8_t

Wild card positions
k1=k2=0  => First Payload in message
k1=k2=0xff => Any, Last Payload in Message

Relative position
k1=0,k2=x => before payload x , where x- payload type defined below
k1=x,k2=0 => after payload x , where x- payload type defined below
k1=x,k2=y => after payload x and before payload y, where x,y - payload types defined below.

Absolute position
k1=k2=i => at absolute 'ith' payload. 1<=i<=0xfe

*/

#define ISAKMP_NPTYPE_SA	1	/* Security Association */
#define ISAKMP_NPTYPE_P		2	/* Proposal */
#define ISAKMP_NPTYPE_T		3	/* Transform */
#define ISAKMP_NPTYPE_KE	4	/* Key Exchange */
#define ISAKMP_NPTYPE_ID	5	/* Identification */
#define ISAKMP_NPTYPE_CERT	6	/* Certificate */
#define ISAKMP_NPTYPE_CR	7	/* Certificate Request */
#define ISAKMP_NPTYPE_HASH	8	/* Hash */
#define ISAKMP_NPTYPE_SIG	9	/* Signature */
#define ISAKMP_NPTYPE_NONCE	10	/* Nonce */
#define ISAKMP_NPTYPE_N		11	/* Notification */
#define ISAKMP_NPTYPE_D		12	/* Delete */
#define ISAKMP_NPTYPE_VID	13	/* Vendor ID */
#define ISAKMP_NPTYPE_ATTR	14	/* Attribute */

#define ISAKMP_NPTYPE_NATD_BADDRAFT	15	/* NAT Discovery */
#define ISAKMP_NPTYPE_NATOA_BADDRAFT	16	/* NAT Original Address */

#define ISAKMP_NPTYPE_NATD_RFC		20	/* NAT Discovery */
#define ISAKMP_NPTYPE_NATOA_RFC		21	/* NAT Original Address */

/* 128 - 255 -Private Payloads */


#define ISAKMP_NPTYPE_NATD_DRAFT	130	/* NAT Discovery */
#define ISAKMP_NPTYPE_NATOA_DRAFT	131	/* NAT Original Address */
#define ISAKMP_NPTYPE_FRAG		132	/* IKE fragmentation payload */

#define GET_EXCH(x)                   ((((u_int32_t) (x) & 0xff000000) >> 24))
#define SET_EXCH(x)                   (((u_int32_t)(x) << 24))
#define GET_MIDX(x)                   ((((u_int32_t)(x) & 0x00ff0000) >> 16))
#define SET_MIDX(x)                   (((u_int32_t) (x) << 16))
#define GET_PAYLOAD_1(x)              (((u_int32_t) (x) & 0x0000ff00) >> 8)
#define GET_PAYLOAD_2(y)              ((u_int32_t) (y) & 0xff)
#define SET_PAYLOADS(x, y)            ((((u_int32_t) (x) << 8) | (y)))

#define MAKE_POS2(exch, j, payload1, payload2) \
                 (u_int32_t) (((exch) << 24) | \
		 (j << 16) | \
		 ((payload1) << 8) | \
		 ((payload2)))

#define MAKE_POS(exch, initorresp, sendorrecv, messageno, payload1, payload2) \
        ( (u_int32_t) MAKE_POS2(exch, ((initorresp)|(sendorrecv)|(messageno)) , payload1, payload2) )
