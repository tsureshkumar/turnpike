/*	$NetBSD: admin.h,v 1.4 2006/09/09 16:22:09 manu Exp $	*/

/* Id: admin.h,v 1.11 2005/06/19 22:37:47 manubsd Exp */

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _ADMIN_H
#define _ADMIN_H

#define ADMINSOCK_PATH ADMINPORTDIR "/racoon.sock"

extern char *adminsock_path;
extern uid_t adminsock_owner;
extern gid_t adminsock_group;
extern mode_t adminsock_mode;

/* command for administration. */
/* NOTE: host byte order. */
struct admin_com {
	u_int16_t ac_len;	/* total packet length including data */
	u_int16_t ac_cmd;
	int16_t ac_errno;
	u_int16_t ac_proto;
};

/*
 * No data follows as the data.
 * These don't use proto field.
 */
#define ADMIN_RELOAD_CONF	0x0001
#define ADMIN_SHOW_SCHED	0x0002
#define ADMIN_SHOW_EVT		0x0003

/*
 * No data follows as the data.
 * These use proto field.
 */
#define ADMIN_SHOW_SA		0x0101
#define ADMIN_FLUSH_SA		0x0102

/*
 * The admin_com_indexes follows, see below.
 */
#define ADMIN_DELETE_SA		0x0201
#define ADMIN_ESTABLISH_SA	0x0202
#define ADMIN_DELETE_ALL_SA_DST	0x0204	/* All SA for a given peer */

/*
 * The admin_com_indexes and admin_com_psk follow, see below.
 */
#define ADMIN_ESTABLISH_SA_PSK	0x0203

/* 0x03xx is used for supporting plugin_frame features*/
#define ADMIN_PUSH_PHASE1CONFIG         0x0301
#define ADMIN_PUSH_PHASE1PROPOSAL       0x0302
#define ADMIN_PUSH_PHASE2CONFIG         0x0303
#define ADMIN_DISCONNECT_DST            0x0304
#define ADMIN_REPARSE_RACOON_CONF       0x0305
#define ADMIN_REPLACE_SAINFO            0x0306
#define ADMIN_SET_VENDOR_CONFIG_DATA    0x0307
#define ADMIN_GET_VENDOR_PRIV_DATA      0X0308

/*
 * user login follows
 */
#define ADMIN_LOGOUT_USER	0x0205  /* Delete SA for a given Xauth user */


/*
 * Range 0x08xx is reserved for privilege separation, see privsep.h 
 */

/* the value of proto */
#define ADMIN_PROTO_ISAKMP	0x01ff
#define ADMIN_PROTO_IPSEC	0x02ff
#define ADMIN_PROTO_AH		0x0201
#define ADMIN_PROTO_ESP		0x0202
#define ADMIN_PROTO_INTERNAL	0x0301

/* the value of policy action for supporting plugin_frame features*/
#define ACTION_ENCRYPT          0x0000
#define ACTION_DENY             0x0001
#define ACTION_BYPASS           0x0002

struct admin_com_indexes {
	u_int8_t prefs;
	u_int8_t prefd;
	u_int8_t ul_proto;
	u_int8_t reserved;
	struct sockaddr_storage src;
	struct sockaddr_storage dst;
};

struct admin_com_psk { 
	int id_type;
	size_t id_len;
	size_t key_len;
	/* Followed by id and key */
}; 

struct peer_identifier {
	u_int8_t        id_type;
	u_int16_t       id_len;
	char            idv[1];
};

struct admin_com_ph1config {
	struct sockaddr_storage dst;
	u_int8_t                mode; /* exchange type*/
	u_int8_t                verify_cert;
	u_int8_t                verify_identifier;
	u_int8_t                my_identifier_type;
	u_int16_t               my_identifier_len;
	u_int16_t               num_peer_identifier;
	char                    id[1];
	/* id[1] format:my_identifier followed by peer_identifier struct(s)*/
};

struct admin_com_ph1proposal {
	u_int8_t        encryption_algo;
	u_int8_t        hash_algo;
	u_int8_t        auth_method;
	u_int8_t        dh_group;
};

struct admin_com_ph1proposal_list{
	struct sockaddr_storage dst;
	u_int8_t num_proposal; /* number of proposals being sent */
	struct admin_com_ph1proposal ph1proposal[1];/* if num_proposal > 1, */
	/*this will be a list of proposals */
};

struct admin_com_ph2_ikeattrib {
	u_int8_t        pfs_group;
	u_int8_t        encryption_algorithm;
	u_int8_t        authentication_algorithm;
	u_int8_t        compression_algorithm;
	u_int32_t       lifetime;
};

struct admin_com_ph2policy {
	struct sockaddr_storage dst_addr;
	u_int8_t        dst_prefixlen;
	u_int8_t        upperspec;
	u_int8_t        direction;
	u_int8_t        action;
	u_int8_t        protocol;
	u_int8_t        mode;
};

struct admin_com_ph2config {
	struct sockaddr_storage src_end_point;
	struct sockaddr_storage dst_end_point;
	short   num_ph2_policies;
	char    pad;
	char    policy[1];
};

typedef struct {
	int addrtype; /* Use IPSECDOI_ID_xxxx_xxxx types. eg. IPSECDOI_ID_IPV4_ADDR */
	union {
		struct sockaddr_storage addr;
		struct {
			struct sockaddr_storage laddr;
			struct sockaddr_storage haddr;
		} range;
	} addrt;
} admin_com_addrinfo;

struct admin_com_replace_sainfo{
	admin_com_addrinfo old_src_addr;
	admin_com_addrinfo old_dst_addr;
	admin_com_addrinfo new_src_addr;
	admin_com_addrinfo new_dst_addr;
	struct sockaddr_storage peeraddr;
};


extern int admin2pfkey_proto __P((u_int));

#define POLICY_STR_LEN 512

/* TEMPORARY STUFF for supporting plugin_frame */
extern int add_default_policy_to_SPD(int);

#endif /* _ADMIN_H */
